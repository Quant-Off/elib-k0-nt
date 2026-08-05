#![allow(clippy::upper_case_acronyms)]

use aes::{AES256CBC, AES256CTR};
use std::fs;
use std::path::{Path, PathBuf};

const MCT_COUNTS: usize = 100;
const MCT_INNER: usize = 1000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    CNC,
    CTR,
}

impl Mode {
    fn iv_name(self) -> &'static str {
        match self {
            Mode::CNC => "IV",
            Mode::CTR => "CTR",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    KAT,
    MMT,
    MCT,
}

#[derive(Default)]
struct RawBlock {
    count: String,
    fields: Vec<(String, String)>,
}

impl RawBlock {
    fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }
}

type FieldRow = Vec<(&'static str, String)>;

fn hex_decode(s: &str, ctx: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "{ctx}: 홀수 길이 16진 문자열");
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = char::from(pair[0]).to_digit(16);
            let lo = char::from(pair[1]).to_digit(16);
            match (hi, lo) {
                (Some(hi), Some(lo)) => ((hi << 4) | lo) as u8,
                _ => panic!("{ctx}: 16진수가 아닌 문자"),
            }
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(
            char::from_digit(u32::from(b >> 4), 16)
                .unwrap()
                .to_ascii_uppercase(),
        );
        out.push(
            char::from_digit(u32::from(b & 0x0F), 16)
                .unwrap()
                .to_ascii_uppercase(),
        );
    }
    out
}

fn parse_field(line: &str, block: &mut RawBlock, ctx: &str) {
    let (name, value) = line
        .split_once('=')
        .unwrap_or_else(|| panic!("{ctx}: 잘못된 필드 형식 {line:?}"));
    let name = name.trim();
    let value = value.trim();
    if name == "COUNT" {
        block.count = value.to_string();
    } else {
        block.fields.push((name.to_string(), value.to_string()));
    }
}

fn parse_file(content: &str, ctx: &str) -> Vec<RawBlock> {
    let mut block: Option<RawBlock> = None;
    let mut blocks = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            if let Some(pending) = block.take() {
                blocks.push(pending);
            }
        } else {
            parse_field(line, block.get_or_insert_default(), ctx);
        }
    }
    if let Some(pending) = block.take() {
        blocks.push(pending);
    }
    blocks
}

fn hex_field<const N: usize>(block: &RawBlock, name: &str, ctx: &str) -> [u8; N] {
    let value = block
        .get(name)
        .unwrap_or_else(|| panic!("{ctx}: {name} 필드 누락"));
    hex_decode(value, &format!("{ctx} {name}"))
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| {
            panic!("{ctx}: {name} 길이 {}바이트가 {N}바이트와 다름", v.len())
        })
}

fn one_shot(mode: Mode, key: &[u8; 32], iv: &[u8; 16], pt: &[u8], ctx: &str) -> Vec<u8> {
    let mut ct = vec![0u8; pt.len()];
    match mode {
        Mode::CNC => {
            let mut cipher = AES256CBC::default();
            cipher.init(key);
            cipher
                .encrypt(iv, pt, &mut ct)
                .unwrap_or_else(|e| panic!("{ctx}: CBC 암호화 실패 {e:?}"));
        }
        Mode::CTR => {
            let mut cipher = AES256CTR::default();
            cipher.init(key);
            let mut counter = u128::from_be_bytes(*iv);
            for (pt_chunk, ct_chunk) in pt.chunks(16).zip(ct.chunks_mut(16)) {
                cipher
                    .apply_iv(&counter.to_be_bytes(), pt_chunk, ct_chunk)
                    .unwrap_or_else(|e| panic!("{ctx}: CTR 암호화 실패 {e:?}"));
                counter = counter.wrapping_add(1);
            }
        }
    }
    ct
}

fn mct_chain(mode: Mode, mut key: [u8; 32], mut iv: [u8; 16], mut pt: [u8; 16]) -> Vec<FieldRow> {
    let mut counts = Vec::with_capacity(MCT_COUNTS);
    for _ in 0..MCT_COUNTS {
        let mut row = vec![
            ("KEY", hex_encode(&key)),
            (mode.iv_name(), hex_encode(&iv)),
            ("PT", hex_encode(&pt)),
        ];
        let mut ct_prev = [0u8; 16];
        let mut ct = [0u8; 16];
        match mode {
            Mode::CNC => {
                let mut cipher = AES256CBC::default();
                cipher.init(&key);
                let mut chain = iv;
                let mut block = pt;
                for _ in 0..MCT_INNER {
                    let mut enc = [0u8; 16];
                    cipher.encrypt(&chain, &block, &mut enc).unwrap();
                    block = chain;
                    chain = enc;
                    ct_prev = ct;
                    ct = enc;
                }
                iv = ct;
                pt = ct_prev;
            }
            Mode::CTR => {
                let mut cipher = AES256CTR::default();
                cipher.init(&key);
                let mut counter = u128::from_be_bytes(iv);
                let mut block = pt;
                for _ in 0..MCT_INNER {
                    let mut enc = [0u8; 16];
                    cipher
                        .apply_iv(&counter.to_be_bytes(), &block, &mut enc)
                        .unwrap();
                    counter = counter.wrapping_add(1);
                    ct_prev = ct;
                    ct = enc;
                    block = enc;
                }
                iv = counter.to_be_bytes();
                pt = ct;
            }
        }
        row.push(("CT", hex_encode(&ct)));
        counts.push(row);
        for (dst, src) in key.iter_mut().zip(ct_prev.iter().chain(ct.iter())) {
            *dst ^= src;
        }
    }
    counts
}

fn expected_blocks(mode: Mode, kind: Kind, req_blocks: &[RawBlock], ctx: &str) -> Vec<FieldRow> {
    match kind {
        Kind::KAT | Kind::MMT => req_blocks
            .iter()
            .enumerate()
            .map(|(idx, block)| {
                let bctx = format!("{ctx} 블록 {idx}");
                let key: [u8; 32] = hex_field(block, "KEY", &bctx);
                let iv: [u8; 16] = hex_field(block, mode.iv_name(), &bctx);
                let pt = hex_decode(
                    block
                        .get("PT")
                        .unwrap_or_else(|| panic!("{bctx}: PT 필드 누락")),
                    &format!("{bctx} PT"),
                );
                let ct = one_shot(mode, &key, &iv, &pt, &bctx);
                vec![
                    ("KEY", hex_encode(&key)),
                    (mode.iv_name(), hex_encode(&iv)),
                    ("PT", hex_encode(&pt)),
                    ("CT", hex_encode(&ct)),
                ]
            })
            .collect(),
        Kind::MCT => {
            assert!(
                req_blocks.len() == 1,
                "{ctx}: MCT req 블록 수 {} (1이어야 함)",
                req_blocks.len()
            );
            let block = &req_blocks[0];
            mct_chain(
                mode,
                hex_field(block, "KEY", ctx),
                hex_field(block, mode.iv_name(), ctx),
                hex_field(block, "PT", ctx),
            )
        }
    }
}

fn verify_sam(expected: &[FieldRow], sam_content: &str, kind: Kind, ctx: &str) -> Vec<String> {
    let sam_blocks = parse_file(sam_content, ctx);
    assert!(
        sam_blocks.len() == expected.len(),
        "{ctx}: 기대 {}블록 vs sam {}블록",
        expected.len(),
        sam_blocks.len()
    );
    let mut mismatches = Vec::new();
    for (idx, (fields, sam_block)) in expected.iter().zip(sam_blocks.iter()).enumerate() {
        if kind == Kind::MCT {
            assert!(
                sam_block.count == idx.to_string(),
                "{ctx}: COUNT 순서 불일치 (sam {} vs 기대 {idx})",
                sam_block.count
            );
        }
        for (name, value) in fields {
            let sam_value = sam_block
                .get(name)
                .unwrap_or_else(|| panic!("{ctx} 블록 {idx}: sam에 {name} 필드 없음"));
            if !sam_value.eq_ignore_ascii_case(value) {
                mismatches.push(format!(
                    "블록 {idx} {name}: 계산 {value} vs sam {sam_value}"
                ));
            }
        }
    }
    mismatches
}

fn fill_template(template: &str, expected: &[FieldRow], ctx: &str) -> String {
    let newline = if template.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut out: Vec<String> = Vec::new();
    let mut idx = 0usize;
    let mut saw_field = false;
    for line in template.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if saw_field {
                idx += 1;
                saw_field = false;
            }
            out.push(line.to_string());
            continue;
        }
        saw_field = true;
        let (name, value) = trimmed
            .split_once('=')
            .unwrap_or_else(|| panic!("{ctx}: 잘못된 템플릿 라인 {line:?}"));
        let name = name.trim();
        let value = value.trim();
        assert!(
            idx < expected.len(),
            "{ctx}: 템플릿 블록 수가 기대 {}블록 초과",
            expected.len()
        );
        if name == "COUNT" {
            assert!(
                value == idx.to_string(),
                "{ctx}: 템플릿 COUNT {value}가 순번 {idx}와 다름"
            );
            out.push(line.to_string());
            continue;
        }
        let (_, exp_value) = expected[idx]
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("{ctx} 블록 {idx}: 알 수 없는 템플릿 필드 {name}"));
        if value == "?" {
            out.push(format!("{name} = {exp_value}"));
        } else {
            assert!(
                value.eq_ignore_ascii_case(exp_value),
                "{ctx} 블록 {idx}: 템플릿 {name} 값이 req 계산과 불일치"
            );
            out.push(line.to_string());
        }
    }
    let mut sam = out.join(newline);
    if template.ends_with('\n') {
        sam.push_str(newline);
    }
    sam
}

fn synthesize(kind: Kind, expected: &[FieldRow], newline: &str) -> String {
    let mut out = String::new();
    for (idx, fields) in expected.iter().enumerate() {
        if idx > 0 {
            out.push_str(newline);
        }
        if kind == Kind::MCT {
            out.push_str(&format!("COUNT = {idx}{newline}"));
        }
        for (name, value) in fields {
            out.push_str(&format!("{name} = {value}{newline}"));
        }
    }
    out
}

fn classify(path: &Path) -> Option<(Mode, Kind)> {
    let stem = path.file_stem()?.to_str()?.to_ascii_uppercase();
    if !stem.starts_with("AES-256") {
        return None;
    }
    let mode = if stem.contains("(CBC)") {
        Mode::CNC
    } else if stem.contains("(CTR)") {
        Mode::CTR
    } else {
        return None;
    };
    let kind = if stem.ends_with("_KAT") {
        Kind::KAT
    } else if stem.ends_with("_MMT") {
        Kind::MMT
    } else if stem.ends_with("_MCT") {
        Kind::MCT
    } else {
        return None;
    };
    Some((mode, kind))
}

fn cavp_root() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("KCMVP_CAVP_DIR") {
        return Some(PathBuf::from(dir));
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.join("cavp");
    root.is_dir().then_some(root)
}

fn collect_req_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_req_files(&path, found);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("req"))
            && classify(&path).is_some()
        {
            found.push(path);
        }
    }
}

fn report_mismatches(path: &Path, mismatches: &[String], total: usize, failures: &mut Vec<String>) {
    eprintln!(
        "{} 대조 실패 {}건 (전체 {total} counts)",
        path.display(),
        mismatches.len()
    );
    for m in mismatches.iter().take(10) {
        eprintln!("  {m}");
    }
    failures.push(format!("{}: {}건 불일치", path.display(), mismatches.len()));
}

// cavp/ 트리의 AES-256 CBC·CTR KAT/MMT/MCT req 를 계산해 rsp 파일로 출력합니다 (sam 은 배포 템플릿 그대로 두고 레이아웃·대조 기준으로만 사용, 기존 rsp 는 회귀 대조)
#[test]
fn kcmvp_cbc_ctr_req_vs_rsp() {
    let Some(root) = cavp_root() else {
        eprintln!("cavp 디렉터리 없음 - KCMVP CBC/CTR 대조 생략");
        return;
    };
    let mut req_files = Vec::new();
    collect_req_files(&root, &mut req_files);
    req_files.sort();
    if req_files.is_empty() {
        eprintln!(
            "{}: CBC·CTR req 파일 없음 - KCMVP CBC/CTR 대조 생략",
            root.display()
        );
        return;
    }

    let mut failures = Vec::new();
    for req in &req_files {
        let ctx = req.display().to_string();
        let (mode, kind) = classify(req).unwrap();
        let content = fs::read_to_string(req).unwrap_or_else(|e| panic!("{ctx}: 읽기 실패 {e}"));
        let req_blocks = parse_file(&content, &ctx);
        let expected = expected_blocks(mode, kind, &req_blocks, &ctx);
        let sam_path = req.with_extension("sam");
        let rsp_path = req.with_extension("rsp");

        let mut layout = None;
        let mut sam_ok = true;
        match fs::read_to_string(&sam_path) {
            Ok(sam) if sam.contains("= ?") => layout = Some(sam),
            Ok(sam) => {
                let mismatches = verify_sam(&expected, &sam, kind, &ctx);
                if mismatches.is_empty() {
                    println!(
                        "{} 대조 통과 ({} counts)",
                        sam_path.display(),
                        expected.len()
                    );
                    layout = Some(sam);
                } else {
                    report_mismatches(&sam_path, &mismatches, expected.len(), &mut failures);
                    sam_ok = false;
                }
            }
            Err(_) => {}
        }
        if !sam_ok {
            continue;
        }

        match fs::read_to_string(&rsp_path) {
            Ok(rsp) if !rsp.contains("= ?") => {
                let mismatches = verify_sam(&expected, &rsp, kind, &ctx);
                if mismatches.is_empty() {
                    println!(
                        "{} 대조 통과 ({} counts)",
                        rsp_path.display(),
                        expected.len()
                    );
                } else {
                    report_mismatches(&rsp_path, &mismatches, expected.len(), &mut failures);
                }
            }
            _ => {
                let rsp = match &layout {
                    Some(template) => fill_template(template, &expected, &ctx),
                    None => {
                        let newline = if content.contains("\r\n") {
                            "\r\n"
                        } else {
                            "\n"
                        };
                        synthesize(kind, &expected, newline)
                    }
                };
                fs::write(&rsp_path, rsp).unwrap_or_else(|e| panic!("{ctx}: rsp 쓰기 실패 {e}"));
                println!("{} 생성 ({} counts)", rsp_path.display(), expected.len());
            }
        }
    }
    assert!(
        failures.is_empty(),
        "rsp·sam 대조 실패\n{}",
        failures.join("\n")
    );
}

// SP 800-38A F.2.5·F.5.5 벡터와 내장 템플릿으로 일회 암호화·템플릿 채움·대조·오염 검출 로직을 자가 검증합니다
#[test]
fn kcmvp_cbc_ctr_self_check() {
    let key_hex = "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4";
    let pt_hex = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    let key: [u8; 32] = hex_decode(key_hex, "self").try_into().unwrap();
    let pt = hex_decode(pt_hex, "self");

    let cbc_iv_hex = "000102030405060708090A0B0C0D0E0F";
    let cbc_iv: [u8; 16] = hex_decode(cbc_iv_hex, "self").try_into().unwrap();
    let cbc_ct = one_shot(Mode::CNC, &key, &cbc_iv, &pt, "self-cbc");
    assert!(
        hex_encode(&cbc_ct)
            == "F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D39F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B",
        "SP 800-38A F.2.5 불일치"
    );

    let ctr_iv: [u8; 16] = hex_decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", "self")
        .try_into()
        .unwrap();
    let ctr_ct = one_shot(Mode::CTR, &key, &ctr_iv, &pt, "self-ctr");
    assert!(
        hex_encode(&ctr_ct)
            == "601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C52B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6",
        "SP 800-38A F.5.5 불일치"
    );

    let block0 = &pt_hex[..32];
    let block1 = &pt_hex[32..64];
    let req = format!(
        "KEY = {key_hex}\r\nIV = {cbc_iv_hex}\r\nPT = {block0}\r\n\r\nKEY = {key_hex}\r\nIV = {cbc_iv_hex}\r\nPT = {block1}\r\n\r\n"
    );
    let req_blocks = parse_file(&req, "self-kat");
    assert!(req_blocks.len() == 2, "req 파싱 블록 수 불일치");
    let expected = expected_blocks(Mode::CNC, Kind::KAT, &req_blocks, "self-kat");

    let template = format!(
        "KEY = {key_hex}\r\nIV = {cbc_iv_hex}\r\nPT = {block0}\r\nCT = ?\r\n\r\nKEY = {key_hex}\r\nIV = {cbc_iv_hex}\r\nPT = {block1}\r\nCT = ?"
    );
    let filled = fill_template(&template, &expected, "self-kat-fill");
    assert!(!filled.contains('?'), "템플릿 미기입 잔존");
    assert!(!filled.ends_with('\n'), "후행 개행 규약 불일치");
    let mismatches = verify_sam(&expected, &filled, Kind::KAT, "self-kat-verify");
    assert!(mismatches.is_empty(), "생성 sam 대조 실패 {mismatches:?}");

    let first_ct = &expected[0][3].1;
    let corrupted_char = if first_ct.ends_with('0') { "1" } else { "0" };
    let corrupted_ct = format!("{}{corrupted_char}", &first_ct[..first_ct.len() - 1]);
    let corrupted = filled.replacen(first_ct.as_str(), &corrupted_ct, 1);
    let mismatches = verify_sam(&expected, &corrupted, Kind::KAT, "self-kat-corrupt");
    assert!(mismatches.len() == 1, "오염 sam 미검출 {mismatches:?}");

    let mct_expected: Vec<FieldRow> = vec![
        vec![
            ("KEY", "AA".to_string()),
            ("IV", "BB".to_string()),
            ("PT", "CC".to_string()),
            ("CT", "DD".to_string()),
        ],
        vec![
            ("KEY", "EE".to_string()),
            ("IV", "FF".to_string()),
            ("PT", "11".to_string()),
            ("CT", "22".to_string()),
        ],
    ];
    let mct_template = "COUNT = 0\r\nKEY = aa\r\nIV = BB\r\nPT = CC\r\nCT = ?\r\n\r\nCOUNT = 1\r\nKEY = ?\r\nIV = ?\r\nPT = ?\r\nCT = ?\r\n";
    let mct_filled = fill_template(mct_template, &mct_expected, "self-mct-fill");
    assert!(
        mct_filled
            == "COUNT = 0\r\nKEY = aa\r\nIV = BB\r\nPT = CC\r\nCT = DD\r\n\r\nCOUNT = 1\r\nKEY = EE\r\nIV = FF\r\nPT = 11\r\nCT = 22\r\n",
        "MCT 템플릿 채움 불일치"
    );
    let mismatches = verify_sam(&mct_expected, &mct_filled, Kind::MCT, "self-mct-verify");
    assert!(mismatches.is_empty(), "MCT 대조 실패 {mismatches:?}");

    let synthesized = synthesize(Kind::MCT, &mct_expected, "\r\n");
    let mismatches = verify_sam(&mct_expected, &synthesized, Kind::MCT, "self-mct-synth");
    assert!(mismatches.is_empty(), "MCT 합성 대조 실패 {mismatches:?}");
}
