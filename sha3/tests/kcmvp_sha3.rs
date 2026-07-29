#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]

use sha3::{SHA3, SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use std::fs;
use std::path::{Path, PathBuf};

const MCT_COUNTS: usize = 100;
const MCT_INNER: usize = 1000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Alg {
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl Alg {
    fn digest_len(self) -> usize {
        match self {
            Alg::SHA3_224 => 28,
            Alg::SHA3_256 => 32,
            Alg::SHA3_384 => 48,
            Alg::SHA3_512 => 64,
        }
    }

    fn hash(self, msg: &[u8]) -> Vec<u8> {
        match self {
            Alg::SHA3_224 => one_shot::<SHA3_224>(msg),
            Alg::SHA3_256 => one_shot::<SHA3_256>(msg),
            Alg::SHA3_384 => one_shot::<SHA3_384>(msg),
            Alg::SHA3_512 => one_shot::<SHA3_512>(msg),
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

fn one_shot<H: SHA3>(msg: &[u8]) -> Vec<u8> {
    let mut hasher = H::new();
    hasher.update(msg);
    hasher.finalize().as_bytes().to_vec()
}

// KCMVP 해시 MCT 는 KISA 암호알고리즘 검증기준 V3.0 "07. SHA3 검증시스템" 5.4 임의
// 메시지 검사 규약을 따릅니다. 윈도 크기 N = floor(r/n) + 1 (r = 스펀지 rate 비트,
// n = 다이제스트 비트) 이고 Msg = MD[i-N] || ... || MD[i-1] 이라 SHA3 는 사이즈별로
// N 이 6/5/3/2 로 달라집니다. SHA2 는 전 사이즈 N=3 이라 sha2 하네스의 고정 3-윈도가
// 그대로 규약과 일치합니다. NIST SHA3VS 의 단일 연쇄 MD[i] = SHA3(MD[i-1]) 을 쓰면
// MCT 만 전부 어긋납니다
fn mct_chain<H: SHA3, const N: usize>(seed: [u8; N]) -> Vec<FieldRow> {
    let window = (1600 - 16 * N) / (8 * N) + 1;
    let mut seed = seed;
    let mut rows = Vec::with_capacity(MCT_COUNTS);
    for count in 0..MCT_COUNTS {
        let mut md: Vec<[u8; N]> = vec![seed; window];
        for _ in 0..MCT_INNER {
            let mut hasher = H::new();
            for part in &md {
                hasher.update(part);
            }
            let digest = hasher.finalize();
            md.rotate_left(1);
            md[window - 1] = digest
                .as_bytes()
                .try_into()
                .unwrap_or_else(|_| panic!("MCT 다이제스트 길이가 {N}바이트와 다름"));
        }
        let last = md[window - 1];
        rows.push(vec![
            ("COUNT", count.to_string()),
            ("MD", hex_encode(&last)),
        ]);
        seed = last;
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
                Alg::SHA3_224 => mct_chain::<SHA3_224, 28>(hex_field(block, "Seed", ctx)),
                Alg::SHA3_256 => mct_chain::<SHA3_256, 32>(hex_field(block, "Seed", ctx)),
                Alg::SHA3_384 => mct_chain::<SHA3_384, 48>(hex_field(block, "Seed", ctx)),
                Alg::SHA3_512 => mct_chain::<SHA3_512, 64>(hex_field(block, "Seed", ctx)),
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
    let alg = if stem.starts_with("SHA3-224") {
        Alg::SHA3_224
    } else if stem.starts_with("SHA3-256") {
        Alg::SHA3_256
    } else if stem.starts_with("SHA3-384") {
        Alg::SHA3_384
    } else if stem.starts_with("SHA3-512") {
        Alg::SHA3_512
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

// cavp/ 트리의 SHA3 LMT/SMT/MCT req 를 계산해 rsp 파일로 출력합니다 (sam 은 배포 템플릿 그대로 두고 레이아웃·대조 기준으로만 사용, 기존 rsp 는 회귀 대조)
#[test]
fn kcmvp_sha3_req_vs_rsp() {
    let Some(root) = cavp_root() else {
        eprintln!("cavp 디렉터리 없음 - KCMVP SHA3 대조 생략");
        return;
    };
    let mut req_files = Vec::new();
    collect_req_files(&root, &mut req_files);
    req_files.sort();
    if req_files.is_empty() {
        eprintln!(
            "{}: SHA3 req 파일 없음 - KCMVP SHA3 대조 생략",
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

// FIPS 202 확정 벡터와 내장 템플릿으로 해시 계산·MCT 체인·템플릿 채움·대조·오염 검출 로직을 자가 검증합니다
#[test]
fn kcmvp_sha3_self_check() {
    let abc = b"abc";
    assert!(
        hex_encode(&Alg::SHA3_224.hash(abc))
            == "E642824C3F8CF24AD09234EE7D3C766FC9A3A5168D0C94AD73B46FDF",
        "FIPS 202 SHA3-224 불일치"
    );
    assert!(
        hex_encode(&Alg::SHA3_256.hash(abc))
            == "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532",
        "FIPS 202 SHA3-256 불일치"
    );
    assert!(
        hex_encode(&Alg::SHA3_384.hash(abc))
            == "EC01498288516FC926459F58E2C6AD8DF9B473CB0FC08C2596DA7CF0E49BE4B298D88CEA927AC7F539F1EDF228376D25",
        "FIPS 202 SHA3-384 불일치"
    );
    assert!(
        hex_encode(&Alg::SHA3_512.hash(abc))
            == "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0",
        "FIPS 202 SHA3-512 불일치"
    );
    assert!(
        hex_encode(&Alg::SHA3_256.hash(&[]))
            == "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A",
        "SHA3-256 빈 메시지 불일치"
    );

    let req = "L = 32\r\n\r\nLen = 24\r\nMsg = 616263\r\n\r\nLen = 0\r\nMsg = 00\r\n\r\n";
    let req_blocks = parse_file(req, "self-smt");
    assert!(req_blocks.len() == 3, "req 파싱 블록 수 불일치");
    let expected = expected_blocks(Alg::SHA3_256, Kind::SMT, &req_blocks, "self-smt");
    assert!(expected.len() == 3, "기대 블록 수 불일치");
    assert!(
        expected[1][2].1 == "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532",
        "SMT abc MD 불일치"
    );
    assert!(
        expected[2][2].1 == "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A",
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

    let seed: [u8; 32] = Alg::SHA3_256.hash(abc).try_into().unwrap();
    let rows = mct_chain::<SHA3_256, 32>(seed);
    assert!(rows.len() == MCT_COUNTS, "MCT 행 수 불일치");
    let window_len = (1600 - 16 * 32) / (8 * 32) + 1;
    let mut chain_seed = seed.to_vec();
    for (count, row) in rows.iter().take(2).enumerate() {
        let mut window = vec![chain_seed.clone(); window_len];
        let mut md = Vec::new();
        for _ in 0..MCT_INNER {
            let mut msg = Vec::with_capacity(window_len * chain_seed.len());
            for part in &window {
                msg.extend_from_slice(part);
            }
            md = Alg::SHA3_256.hash(&msg);
            window.rotate_left(1);
            window[window_len - 1] = md.clone();
        }
        assert!(
            row[0].1 == count.to_string() && row[1].1 == hex_encode(&md),
            "MCT COUNT {count} 독립 재계산 불일치"
        );
        chain_seed = md;
    }

    // KISA 공식 벡터의 Seed 로 COUNT=0 정답 MD 를 KAT 대조합니다
    fn kisa_kat<H: SHA3, const N: usize>(name: &str, seed_hex: &str, md0_hex: &str) {
        let seed: [u8; N] = hex_decode(seed_hex, name).try_into().unwrap();
        let rows = mct_chain::<H, N>(seed);
        assert!(
            rows[0][0].1 == "0" && rows[0][1].1 == md0_hex,
            "KISA {name} MCT KAT 불일치"
        );
    }
    kisa_kat::<SHA3_224, 28>(
        "SHA3-224",
        "8C08A9BD0B308661ACE3E41E2B83ED8A996DDA04A12B5C9010EA3AE2",
        "DA4273B331B22AAB84068D4773C568BB7EABE0E163A598D3BD186DA2",
    );
    kisa_kat::<SHA3_256, 32>(
        "SHA3-256",
        "99F9C9BB358B28A4ABD395CE170DAE72A1527597FF0FF72A3CB52C50B8B21FFB",
        "9F5B796BFC84008F899FA0921226811FD9DA1A94E55C2ED17FD6BE1859C06ACC",
    );
    kisa_kat::<SHA3_384, 48>(
        "SHA3-384",
        "AAE8B2B7AA3DF27829BFB1AB7D381F146B30370EF56B392B73B35B1BE5D8BBCF88F499DDA7F3C327B45350B8972991EE",
        "AE61D961D32BAD53B7D141EA60920F83CB4DFE3C81B92D5D8C1CE95EC44C3CF03F5EE50981904ECA7038E8F28DDA52A1",
    );
    kisa_kat::<SHA3_512, 64>(
        "SHA3-512",
        "B7D9D3B4D49894BB27AF615B69C2DFFD7315D2A1534FD4C59F7E4D89095C9F1234D1A12CC6B84F33BFE6C0330968584E4F0D3E5E132510DCFB87D6016CD9352A",
        "A54435FE431B16E8BFF29CC67C194D4D05BE1AAC5630D732FDF7D514524726B28C0EAC339FF3FEB34804A45257E3090934D6B94CD81200E58322E5547B2D890A",
    );
}
