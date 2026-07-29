#![allow(clippy::upper_case_acronyms)]

use sha2::{SHA2, SHA224, SHA256, SHA384, SHA512};
use std::fs;
use std::path::{Path, PathBuf};

const MCT_COUNTS: usize = 100;
const MCT_INNER: usize = 1000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Alg {
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

impl Alg {
    fn digest_len(self) -> usize {
        match self {
            Alg::SHA224 => 28,
            Alg::SHA256 => 32,
            Alg::SHA384 => 48,
            Alg::SHA512 => 64,
        }
    }

    fn hash(self, msg: &[u8]) -> Vec<u8> {
        match self {
            Alg::SHA224 => one_shot::<SHA224>(msg),
            Alg::SHA256 => one_shot::<SHA256>(msg),
            Alg::SHA384 => one_shot::<SHA384>(msg),
            Alg::SHA512 => one_shot::<SHA512>(msg),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    LMT,
    SMT,
    MCT,
}

#[derive(Default)]
struct RawBlock {
    l: String,
    len: String,
    fields: Vec<(String, String)>,
}

impl RawBlock {
    fn get(&self, name: &str) -> Option<&str> {
        let special = match name {
            "L" => Some(self.l.as_str()),
            "Len" => Some(self.len.as_str()),
            _ => None,
        };
        if let Some(value) = special {
            return (!value.is_empty()).then_some(value);
        }
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
    if name == "L" {
        block.l = value.to_string();
    } else if name == "Len" {
        block.len = value.to_string();
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

fn one_shot<H: SHA2>(msg: &[u8]) -> Vec<u8> {
    let mut hasher = H::new();
    hasher.update(msg);
    hasher.finalize().as_bytes().to_vec()
}

fn mct_chain<H: SHA2, const N: usize>(seed: [u8; N]) -> Vec<FieldRow> {
    let mut seed = seed;
    let mut rows = Vec::with_capacity(MCT_COUNTS);
    for count in 0..MCT_COUNTS {
        let mut md0 = seed;
        let mut md1 = seed;
        let mut md2 = seed;
        for _ in 0..MCT_INNER {
            let mut hasher = H::new();
            hasher.update(&md0);
            hasher.update(&md1);
            hasher.update(&md2);
            let digest = hasher.finalize();
            md0 = md1;
            md1 = md2;
            md2 = digest
                .as_bytes()
                .try_into()
                .unwrap_or_else(|_| panic!("MCT 다이제스트 길이가 {N}바이트와 다름"));
        }
        rows.push(vec![("COUNT", count.to_string()), ("MD", hex_encode(&md2))]);
        seed = md2;
    }
    rows
}

fn expected_blocks(alg: Alg, kind: Kind, req_blocks: &[RawBlock], ctx: &str) -> Vec<FieldRow> {
    assert!(!req_blocks.is_empty(), "{ctx}: req 블록 없음");
    let header = &req_blocks[0];
    assert!(
        header.len.is_empty() && header.fields.is_empty(),
        "{ctx}: L 헤더 블록에 잉여 필드"
    );
    assert!(
        header.l == alg.digest_len().to_string(),
        "{ctx}: L 값 {}이 기대 {}와 다름",
        header.l,
        alg.digest_len()
    );
    let mut rows = vec![vec![("L", header.l.clone())]];
    match kind {
        Kind::LMT | Kind::SMT => {
            for (idx, block) in req_blocks[1..].iter().enumerate() {
                let bctx = format!("{ctx} 블록 {idx}");
                assert!(!block.len.is_empty(), "{bctx}: Len 필드 누락");
                let bits: usize = block
                    .len
                    .parse()
                    .unwrap_or_else(|_| panic!("{bctx}: Len 파싱 실패"));
                assert!(
                    bits.is_multiple_of(8),
                    "{bctx}: Len {bits}이 8의 배수가 아님"
                );
                let msg_hex = block
                    .get("Msg")
                    .unwrap_or_else(|| panic!("{bctx}: Msg 필드 누락"));
                let msg = hex_decode(msg_hex, &format!("{bctx} Msg"));
                let body = if bits == 0 {
                    assert!(msg == [0u8], "{bctx}: Len 0 인데 Msg 가 00 이 아님");
                    &[][..]
                } else {
                    assert!(
                        msg.len() * 8 == bits,
                        "{bctx}: Msg 길이 {}비트가 Len {bits}과 다름",
                        msg.len() * 8
                    );
                    &msg[..]
                };
                let md = alg.hash(body);
                rows.push(vec![
                    ("Len", block.len.clone()),
                    ("Msg", msg_hex.to_string()),
                    ("MD", hex_encode(&md)),
                ]);
            }
        }
        Kind::MCT => {
            assert!(
                req_blocks.len() == 2,
                "{ctx}: MCT req 블록 수 {} (2여야 함)",
                req_blocks.len()
            );
            let block = &req_blocks[1];
            let seed_hex = block
                .get("Seed")
                .unwrap_or_else(|| panic!("{ctx}: Seed 필드 누락"));
            rows.push(vec![("Seed", seed_hex.to_string())]);
            let chain = match alg {
                Alg::SHA224 => mct_chain::<SHA224, 28>(hex_field(block, "Seed", ctx)),
                Alg::SHA256 => mct_chain::<SHA256, 32>(hex_field(block, "Seed", ctx)),
                Alg::SHA384 => mct_chain::<SHA384, 48>(hex_field(block, "Seed", ctx)),
                Alg::SHA512 => mct_chain::<SHA512, 64>(hex_field(block, "Seed", ctx)),
            };
            rows.extend(chain);
        }
    }
    rows
}

fn verify_sam(expected: &[FieldRow], sam_content: &str, ctx: &str) -> Vec<String> {
    let sam_blocks = parse_file(sam_content, ctx);
    assert!(
        sam_blocks.len() == expected.len(),
        "{ctx}: 기대 {}블록 vs 파일 {}블록",
        expected.len(),
        sam_blocks.len()
    );
    let mut mismatches = Vec::new();
    for (idx, (fields, sam_block)) in expected.iter().zip(sam_blocks.iter()).enumerate() {
        for (name, value) in fields {
            let sam_value = sam_block
                .get(name)
                .unwrap_or_else(|| panic!("{ctx} 블록 {idx}: 파일에 {name} 필드 없음"));
            if !sam_value.eq_ignore_ascii_case(value) {
                mismatches.push(format!(
                    "블록 {idx} {name}: 계산 {value} vs 파일 {sam_value}"
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
    let mut rsp = out.join(newline);
    if template.ends_with('\n') {
        rsp.push_str(newline);
    }
    rsp
}

fn synthesize(expected: &[FieldRow], newline: &str) -> String {
    let mut out = String::new();
    for (idx, fields) in expected.iter().enumerate() {
        if idx > 0 {
            out.push_str(newline);
        }
        for (name, value) in fields {
            out.push_str(&format!("{name} = {value}{newline}"));
        }
    }
    out
}

fn classify(path: &Path) -> Option<(Alg, Kind)> {
    let stem = path.file_stem()?.to_str()?.to_ascii_uppercase();
    let alg = if stem.starts_with("SHA2-224") {
        Alg::SHA224
    } else if stem.starts_with("SHA2-256") {
        Alg::SHA256
    } else if stem.starts_with("SHA2-384") {
        Alg::SHA384
    } else if stem.starts_with("SHA2-512") {
        Alg::SHA512
    } else {
        return None;
    };
    let kind = if stem.ends_with("_LMT") {
        Kind::LMT
    } else if stem.ends_with("_SMT") {
        Kind::SMT
    } else if stem.ends_with("_MCT") {
        Kind::MCT
    } else {
        return None;
    };
    Some((alg, kind))
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
        "{} 대조 실패 {}건 (전체 {total} 블록)",
        path.display(),
        mismatches.len()
    );
    for m in mismatches.iter().take(10) {
        eprintln!("  {m}");
    }
    failures.push(format!("{}: {}건 불일치", path.display(), mismatches.len()));
}

// cavp/ 트리의 SHA2 LMT/SMT/MCT req 를 계산해 rsp 파일로 출력합니다 (sam 은 배포 템플릿 그대로 두고 레이아웃·대조 기준으로만 사용, 기존 rsp 는 회귀 대조)
#[test]
fn kcmvp_sha2_req_vs_rsp() {
    let Some(root) = cavp_root() else {
        eprintln!("cavp 디렉터리 없음 - KCMVP SHA2 대조 생략");
        return;
    };
    let mut req_files = Vec::new();
    collect_req_files(&root, &mut req_files);
    req_files.sort();
    if req_files.is_empty() {
        eprintln!(
            "{}: SHA2 req 파일 없음 - KCMVP SHA2 대조 생략",
            root.display()
        );
        return;
    }

    let mut failures = Vec::new();
    for req in &req_files {
        let ctx = req.display().to_string();
        let (alg, kind) = classify(req).unwrap();
        let content = fs::read_to_string(req).unwrap_or_else(|e| panic!("{ctx}: 읽기 실패 {e}"));
        let req_blocks = parse_file(&content, &ctx);
        let expected = expected_blocks(alg, kind, &req_blocks, &ctx);
        let sam_path = req.with_extension("sam");
        let rsp_path = req.with_extension("rsp");

        let mut layout = None;
        let mut sam_ok = true;
        match fs::read_to_string(&sam_path) {
            Ok(sam) if sam.contains("= ?") => layout = Some(sam),
            Ok(sam) => {
                let mismatches = verify_sam(&expected, &sam, &ctx);
                if mismatches.is_empty() {
                    println!("{} 대조 통과 ({} 블록)", sam_path.display(), expected.len());
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
                let mismatches = verify_sam(&expected, &rsp, &ctx);
                if mismatches.is_empty() {
                    println!("{} 대조 통과 ({} 블록)", rsp_path.display(), expected.len());
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
                        synthesize(&expected, newline)
                    }
                };
                fs::write(&rsp_path, rsp).unwrap_or_else(|e| panic!("{ctx}: rsp 쓰기 실패 {e}"));
                println!("{} 생성 ({} 블록)", rsp_path.display(), expected.len());
            }
        }
    }
    assert!(
        failures.is_empty(),
        "rsp·sam 대조 실패\n{}",
        failures.join("\n")
    );
}

// FIPS 180-4 확정 벡터와 내장 템플릿으로 해시 계산·MCT 체인·템플릿 채움·대조·오염 검출 로직을 자가 검증합니다
#[test]
fn kcmvp_sha2_self_check() {
    let abc = b"abc";
    assert!(
        hex_encode(&Alg::SHA224.hash(abc))
            == "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7",
        "FIPS 180-4 SHA-224 불일치"
    );
    assert!(
        hex_encode(&Alg::SHA256.hash(abc))
            == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        "FIPS 180-4 SHA-256 불일치"
    );
    assert!(
        hex_encode(&Alg::SHA384.hash(abc))
            == "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7",
        "FIPS 180-4 SHA-384 불일치"
    );
    assert!(
        hex_encode(&Alg::SHA512.hash(abc))
            == "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
        "FIPS 180-4 SHA-512 불일치"
    );
    assert!(
        hex_encode(&Alg::SHA256.hash(&[]))
            == "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "SHA-256 빈 메시지 불일치"
    );

    let req = "L = 32\r\n\r\nLen = 24\r\nMsg = 616263\r\n\r\nLen = 0\r\nMsg = 00\r\n\r\n";
    let req_blocks = parse_file(req, "self-smt");
    assert!(req_blocks.len() == 3, "req 파싱 블록 수 불일치");
    let expected = expected_blocks(Alg::SHA256, Kind::SMT, &req_blocks, "self-smt");
    assert!(expected.len() == 3, "기대 블록 수 불일치");
    assert!(
        expected[1][2].1 == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        "SMT abc MD 불일치"
    );
    assert!(
        expected[2][2].1 == "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "SMT Len 0 MD 불일치"
    );

    let template =
        "L = 32\r\n\r\nLen = 24\r\nMsg = 616263\r\nMD = ?\r\n\r\nLen = 0\r\nMsg = 00\r\nMD = ?";
    let filled = fill_template(template, &expected, "self-fill");
    assert!(!filled.contains('?'), "템플릿 미기입 잔존");
    assert!(!filled.ends_with('\n'), "후행 개행 규약 불일치");
    let mismatches = verify_sam(&expected, &filled, "self-verify");
    assert!(mismatches.is_empty(), "생성 rsp 대조 실패 {mismatches:?}");

    let first_md = &expected[1][2].1;
    let corrupted_char = if first_md.ends_with('0') { "1" } else { "0" };
    let corrupted_md = format!("{}{corrupted_char}", &first_md[..first_md.len() - 1]);
    let corrupted = filled.replacen(first_md.as_str(), &corrupted_md, 1);
    let mismatches = verify_sam(&expected, &corrupted, "self-corrupt");
    assert!(mismatches.len() == 1, "오염 rsp 미검출 {mismatches:?}");

    let synthesized = synthesize(&expected, "\r\n");
    let mismatches = verify_sam(&expected, &synthesized, "self-synth");
    assert!(mismatches.is_empty(), "합성 rsp 대조 실패 {mismatches:?}");

    let seed: [u8; 32] = Alg::SHA256.hash(abc).try_into().unwrap();
    let rows = mct_chain::<SHA256, 32>(seed);
    assert!(rows.len() == MCT_COUNTS, "MCT 행 수 불일치");
    let mut chain_seed = seed.to_vec();
    for (count, row) in rows.iter().take(2).enumerate() {
        let mut window = [chain_seed.clone(), chain_seed.clone(), chain_seed.clone()];
        let mut md = Vec::new();
        for _ in 0..MCT_INNER {
            let mut msg = Vec::with_capacity(window[0].len() * 3);
            msg.extend_from_slice(&window[0]);
            msg.extend_from_slice(&window[1]);
            msg.extend_from_slice(&window[2]);
            md = Alg::SHA256.hash(&msg);
            window.swap(0, 1);
            window.swap(1, 2);
            window[2] = md.clone();
        }
        assert!(
            row[0].1 == count.to_string() && row[1].1 == hex_encode(&md),
            "MCT COUNT {count} 독립 재계산 불일치"
        );
        chain_seed = md;
    }
}
