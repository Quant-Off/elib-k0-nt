use aes::{AES256GCM, Error, GCM_MIN_TAG_SIZE, GCM_TAG_SIZE};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
enum Mode {
    AE,
    AD,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct GroupParams {
    key_len: usize,
    iv_len: usize,
    pt_len: usize,
    aad_len: usize,
    tag_len: usize,
}

#[derive(Default)]
struct RawBlock {
    count: String,
    fields: Vec<(String, String)>,
    invalid: bool,
}

impl RawBlock {
    fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Default)]
struct Stats {
    counts: usize,
    valid: usize,
    invalid: usize,
}

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

fn parse_header(line: &str, params: &mut GroupParams, ctx: &str) {
    let inner = line
        .trim()
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or_else(|| panic!("{ctx}: 잘못된 헤더 형식 {line:?}"));
    let (name, value) = inner
        .split_once('=')
        .unwrap_or_else(|| panic!("{ctx}: 잘못된 헤더 형식 {line:?}"));
    let value: usize = value
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("{ctx}: 헤더 값이 정수가 아님 {line:?}"));
    match name.trim().to_ascii_lowercase().as_str() {
        "keylen" => params.key_len = value,
        "ivlen" => params.iv_len = value,
        "ptlen" => params.pt_len = value,
        "aadlen" => params.aad_len = value,
        "taglen" => params.tag_len = value,
        _ => panic!("{ctx}: 알 수 없는 헤더 {line:?}"),
    }
}

fn parse_field(line: &str, block: &mut RawBlock, ctx: &str) {
    if line.trim().eq_ignore_ascii_case("invalid") {
        block.invalid = true;
        return;
    }
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

fn parse_file(content: &str, ctx: &str) -> Vec<(GroupParams, RawBlock)> {
    let mut params = GroupParams::default();
    let mut block: Option<RawBlock> = None;
    let mut blocks = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if let Some(pending) = block.take() {
                blocks.push((params, pending));
            }
        } else if trimmed.starts_with('[') {
            assert!(block.is_none(), "{ctx}: COUNT 블록 도중 헤더 등장 {line:?}");
            parse_header(line, &mut params, ctx);
        } else {
            parse_field(line, block.get_or_insert_default(), ctx);
        }
    }
    if let Some(pending) = block.take() {
        blocks.push((params, pending));
    }
    blocks
}

fn hex_field(block: &RawBlock, name: &str, bits: usize, ctx: &str) -> Vec<u8> {
    let value = block
        .get(name)
        .unwrap_or_else(|| panic!("{ctx}: {name} 필드 누락"));
    let bytes = hex_decode(value, &format!("{ctx} {name}"));
    assert!(
        bytes.len() * 8 == bits,
        "{ctx}: {name} 길이 {}비트가 선언된 {bits}비트와 다름",
        bytes.len() * 8
    );
    bytes
}

fn compute_answers(
    mode: Mode,
    params: GroupParams,
    block: &RawBlock,
    ctx: &str,
    stats: &mut Stats,
) -> Vec<(&'static str, String)> {
    let ctx = format!("{ctx} COUNT = {}", block.count);
    assert!(
        params.key_len == 256,
        "{ctx}: 지원하지 않는 KeyLen {}",
        params.key_len
    );
    assert!(
        (GCM_MIN_TAG_SIZE * 8..=GCM_TAG_SIZE * 8).contains(&params.tag_len)
            && params.tag_len.is_multiple_of(8),
        "{ctx}: 지원하지 않는 TagLen {}",
        params.tag_len
    );

    let key: [u8; 32] = hex_field(block, "Key", params.key_len, &ctx)
        .try_into()
        .unwrap();
    let iv = hex_field(block, "IV", params.iv_len, &ctx);
    let aad = hex_field(block, "Adata", params.aad_len, &ctx);
    let gcm = AES256GCM::new(&key);
    stats.counts += 1;

    match mode {
        Mode::AE => {
            let pt = hex_field(block, "PT", params.pt_len, &ctx);
            let mut ct = vec![0u8; pt.len()];
            let mut tag = vec![0u8; params.tag_len / 8];
            gcm.encrypt_with_iv(&iv, &aad, &pt, &mut ct, &mut tag)
                .unwrap_or_else(|e| panic!("{ctx}: 암호화 실패 {e:?}"));
            vec![("C", hex_encode(&ct)), ("T", hex_encode(&tag))]
        }
        Mode::AD => {
            let ct = hex_field(block, "C", params.pt_len, &ctx);
            let tag = hex_field(block, "T", params.tag_len, &ctx);
            let mut pt = vec![0u8; ct.len()];
            match gcm.decrypt_with_iv(&iv, &aad, &ct, &tag, &mut pt) {
                Ok(()) => {
                    stats.valid += 1;
                    vec![("PT", hex_encode(&pt))]
                }
                Err(Error::AuthenticationFailed) => {
                    stats.invalid += 1;
                    vec![("Invalid", String::new())]
                }
                Err(e) => panic!("{ctx}: 복호화 실패 {e:?}"),
            }
        }
    }
}

fn verify_sam(req_content: &str, sam_content: &str, mode: Mode, ctx: &str) -> (Stats, Vec<String>) {
    let req_blocks = parse_file(req_content, ctx);
    let sam_blocks = parse_file(sam_content, ctx);
    assert!(
        req_blocks.len() == sam_blocks.len(),
        "{ctx}: req {}블록 vs sam {}블록",
        req_blocks.len(),
        sam_blocks.len()
    );

    let mut stats = Stats::default();
    let mut mismatches = Vec::new();

    for ((req_params, req_block), (sam_params, sam_block)) in
        req_blocks.iter().zip(sam_blocks.iter())
    {
        assert!(
            req_block.count == sam_block.count,
            "{ctx}: COUNT 순서 불일치 (req {} vs sam {})",
            req_block.count,
            sam_block.count
        );
        assert!(
            req_params == sam_params,
            "{ctx} COUNT = {}: req/sam 헤더 파라미터 불일치",
            req_block.count
        );
        assert!(
            req_block.get("Key") == sam_block.get("Key"),
            "{ctx} COUNT = {}: req/sam Key 불일치",
            req_block.count
        );

        for (name, computed) in compute_answers(mode, *req_params, req_block, ctx, &mut stats) {
            if name == "Invalid" {
                if !sam_block.invalid {
                    mismatches.push(format!(
                        "COUNT = {} PT: 계산 Invalid vs sam {}",
                        req_block.count,
                        sam_block.get("PT").unwrap_or("(없음)")
                    ));
                }
                continue;
            }
            if name == "PT" && sam_block.invalid {
                mismatches.push(format!(
                    "COUNT = {} PT: 계산 {computed} vs sam Invalid",
                    req_block.count
                ));
                continue;
            }
            let expected = sam_block.get(name).unwrap_or_else(|| {
                panic!("{ctx} COUNT = {}: sam에 {name} 필드 없음", req_block.count)
            });
            if !expected.eq_ignore_ascii_case(&computed) {
                mismatches.push(format!(
                    "COUNT = {} {name}: 계산 {computed} vs sam {expected}",
                    req_block.count
                ));
            }
        }
    }
    (stats, mismatches)
}

fn fill_req(content: &str, mode: Mode, ctx: &str) -> (String, Stats) {
    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut out: Vec<String> = Vec::new();
    let mut params = GroupParams::default();
    let mut block: Option<RawBlock> = None;
    let mut stats = Stats::default();

    let flush = |block: &mut Option<RawBlock>,
                 out: &mut Vec<String>,
                 stats: &mut Stats,
                 params: GroupParams| {
        if let Some(pending) = block.take() {
            for (name, value) in compute_answers(mode, params, &pending, ctx, stats) {
                if name == "Invalid" {
                    out.push("Invalid".to_string());
                } else {
                    out.push(format!("{name} = {value}"));
                }
            }
        }
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            flush(&mut block, &mut out, &mut stats, params);
            out.push(line.to_string());
        } else if trimmed.starts_with('[') {
            assert!(block.is_none(), "{ctx}: COUNT 블록 도중 헤더 등장 {line:?}");
            parse_header(line, &mut params, ctx);
            out.push(line.to_string());
        } else {
            out.push(line.to_string());
            parse_field(line, block.get_or_insert_default(), ctx);
        }
    }
    flush(&mut block, &mut out, &mut stats, params);

    let mut sam = out.join(newline);
    if content.ends_with('\n') {
        sam.push_str(newline);
    }
    (sam, stats)
}

fn detect_mode(path: &Path, content: &str) -> Mode {
    let stem = path
        .file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_uppercase();
    if stem.ends_with("_AE") {
        return Mode::AE;
    }
    if stem.ends_with("_AD") {
        return Mode::AD;
    }
    if content
        .lines()
        .any(|line| line.trim_start().starts_with("T ="))
    {
        Mode::AD
    } else {
        Mode::AE
    }
}

fn cavp_root() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("KCMVP_CAVP_DIR") {
        return Some(PathBuf::from(dir));
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.join("cavp");
    root.is_dir().then_some(root)
}

fn collect_gcm_req_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_gcm_req_files(&path, found);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && name.to_ascii_uppercase().starts_with("GCM")
            && name.to_ascii_lowercase().ends_with(".req")
        {
            found.push(path);
        }
    }
}

fn describe(mode: Mode, stats: &Stats) -> String {
    match mode {
        Mode::AE => format!("{} counts", stats.counts),
        Mode::AD => format!(
            "{} counts, valid {}, invalid {}",
            stats.counts, stats.valid, stats.invalid
        ),
    }
}

fn flip_last_hex(hex: &str) -> String {
    let mut flipped = hex.to_string();
    let last = if flipped.ends_with('0') { "1" } else { "0" };
    flipped.replace_range(flipped.len() - 1.., last);
    flipped
}

fn report_mismatches(
    path: &Path,
    mismatches: &[String],
    summary: &str,
    failures: &mut Vec<String>,
) {
    eprintln!(
        "{} 대조 실패 {}건 (전체 {summary})",
        path.display(),
        mismatches.len()
    );
    for m in mismatches.iter().take(10) {
        eprintln!("  {m}");
    }
    failures.push(format!("{}: {}건 불일치", path.display(), mismatches.len()));
}

// cavp/ 트리의 GCM req 를 계산해 rsp 파일로 출력합니다 (sam 은 답이 기입된 경우 대조 기준, 기존 rsp 는 회귀 대조)
#[test]
fn kcmvp_gcm_req_vs_rsp() {
    let Some(root) = cavp_root() else {
        eprintln!("cavp 디렉터리 없음 - KCMVP GCM 대조 생략");
        return;
    };
    let mut req_files = Vec::new();
    collect_gcm_req_files(&root, &mut req_files);
    req_files.sort();
    if req_files.is_empty() {
        eprintln!(
            "{}: GCM req 파일 없음 - KCMVP GCM 대조 생략",
            root.display()
        );
        return;
    }

    let mut failures = Vec::new();
    for req in &req_files {
        let ctx = req.display().to_string();
        let content = fs::read_to_string(req).unwrap_or_else(|e| panic!("{ctx}: 읽기 실패 {e}"));
        let mode = detect_mode(req, &content);
        let sam_path = req.with_extension("sam");
        let rsp_path = req.with_extension("rsp");

        let mut sam_ok = true;
        if let Ok(sam) = fs::read_to_string(&sam_path)
            && !sam.contains("= ?")
        {
            let (stats, mismatches) = verify_sam(&content, &sam, mode, &ctx);
            if mismatches.is_empty() {
                println!(
                    "{} 대조 통과 ({})",
                    sam_path.display(),
                    describe(mode, &stats)
                );
            } else {
                report_mismatches(
                    &sam_path,
                    &mismatches,
                    &describe(mode, &stats),
                    &mut failures,
                );
                sam_ok = false;
            }
        }
        if !sam_ok {
            continue;
        }

        match fs::read_to_string(&rsp_path) {
            Ok(rsp) if !rsp.contains("= ?") => {
                let (stats, mismatches) = verify_sam(&content, &rsp, mode, &ctx);
                if mismatches.is_empty() {
                    println!(
                        "{} 대조 통과 ({})",
                        rsp_path.display(),
                        describe(mode, &stats)
                    );
                } else {
                    report_mismatches(
                        &rsp_path,
                        &mismatches,
                        &describe(mode, &stats),
                        &mut failures,
                    );
                }
            }
            _ => {
                let (rsp, stats) = fill_req(&content, mode, &ctx);
                fs::write(&rsp_path, rsp).unwrap_or_else(|e| panic!("{ctx}: rsp 쓰기 실패 {e}"));
                println!("{} 생성 ({})", rsp_path.display(), describe(mode, &stats));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "rsp·sam 대조 실패\n{}",
        failures.join("\n")
    );
}

// 내장 벡터로 req 파싱과 rsp 생성·대조 로직을 자가 검증합니다
#[test]
fn kcmvp_gcm_self_check() {
    let key_hex = "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308";
    let iv_hex = "CAFEBABEFACEDBADDECAF888";
    let aad_hex = "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2";
    let pt_hex = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39";

    let key: [u8; 32] = hex_decode(key_hex, "self").try_into().unwrap();
    let iv = hex_decode(iv_hex, "self");
    let aad = hex_decode(aad_hex, "self");
    let pt = hex_decode(pt_hex, "self");
    let gcm = AES256GCM::new(&key);
    let mut ct = vec![0u8; pt.len()];
    let mut tag = vec![0u8; 14];
    gcm.encrypt_with_iv(&iv, &aad, &pt, &mut ct, &mut tag)
        .unwrap();
    let ct_hex = hex_encode(&ct);
    let tag_hex = hex_encode(&tag);

    let ae_req = format!(
        "[KeyLen = 256]\r\n[IVLen = 96]\r\n[PTLen = 480]\r\n[AADLen = 160]\r\n[TagLen = 112]\r\n\r\nCOUNT = 0\r\nKey = {key_hex}\r\nIV = {iv_hex}\r\nPT = {pt_hex}\r\nAdata = {aad_hex}\r\n"
    );
    let (ae_sam, ae_stats) = fill_req(&ae_req, Mode::AE, "self-ae");
    let ae_expected = format!("{ae_req}C = {ct_hex}\r\nT = {tag_hex}\r\n");
    assert_eq!(ae_sam, ae_expected, "AE sam 형식 불일치");
    assert!(ae_stats.counts == 1);

    let (_, mismatches) = verify_sam(&ae_req, &ae_sam, Mode::AE, "self-ae-verify");
    assert!(mismatches.is_empty(), "생성 sam 대조 실패 {mismatches:?}");

    let corrupted_sam = ae_sam.replace(
        &format!("T = {tag_hex}"),
        &format!("T = {}", flip_last_hex(&tag_hex)),
    );
    let (_, mismatches) = verify_sam(&ae_req, &corrupted_sam, Mode::AE, "self-ae-corrupt");
    assert!(mismatches.len() == 1, "오염 sam 미검출 {mismatches:?}");

    let bad_tag_hex = flip_last_hex(&tag_hex);
    let ad_req = format!(
        "[KeyLen = 256]\r\n[IVlen = 96]\r\n[PTLen = 480]\r\n[AADLen = 160]\r\n[TagLen = 112]\r\n\r\nCOUNT = 0\r\nKey = {key_hex}\r\nIV = {iv_hex}\r\nAdata = {aad_hex}\r\nC = {ct_hex}\r\nT = {tag_hex}\r\n\r\nCOUNT = 1\r\nKey = {key_hex}\r\nIV = {iv_hex}\r\nAdata = {aad_hex}\r\nC = {ct_hex}\r\nT = {bad_tag_hex}\r\n"
    );
    let (ad_sam, ad_stats) = fill_req(&ad_req, Mode::AD, "self-ad");
    assert!(
        ad_sam.contains(&format!("T = {tag_hex}\r\nPT = {pt_hex}\r\n")),
        "AD 유효 응답 불일치"
    );
    assert!(
        ad_sam.contains(&format!("T = {bad_tag_hex}\r\nInvalid\r\n")),
        "AD Invalid 응답 불일치"
    );
    assert!(
        !ad_sam.contains("PT = Invalid"),
        "AD Invalid 응답에 PT 접두어 잔존"
    );
    assert!(ad_stats.counts == 2 && ad_stats.valid == 1 && ad_stats.invalid == 1);

    let (_, mismatches) = verify_sam(&ad_req, &ad_sam, Mode::AD, "self-ad-verify");
    assert!(mismatches.is_empty(), "AD sam 대조 실패 {mismatches:?}");

    let swapped_sam = ad_sam.replacen("Invalid", &format!("PT = {pt_hex}"), 1);
    let (_, mismatches) = verify_sam(&ad_req, &swapped_sam, Mode::AD, "self-ad-swap");
    assert!(mismatches.len() == 1, "Invalid 오염 미검출 {mismatches:?}");

    let swapped_valid = ad_sam.replacen(&format!("PT = {pt_hex}"), "Invalid", 1);
    let (_, mismatches) = verify_sam(&ad_req, &swapped_valid, Mode::AD, "self-ad-swap-valid");
    assert!(
        mismatches.len() == 1,
        "유효 카운트 Invalid 오염 미검출 {mismatches:?}"
    );

    let empty_req = "[KeyLen = 256]\r\n[IVLen = 96]\r\n[PTLen = 0]\r\n[AADLen = 0]\r\n[TagLen = 128]\r\n\r\nCOUNT = 0\r\nKey = D6D04FFE1C2CF03660E19639B7FB28235E17E307AC7FF534459647B791779A21\r\nIV = 6CD9D58A1F369DD58F2C2736\r\nPT = \r\nAdata = \r\n";
    let (empty_sam, _) = fill_req(empty_req, Mode::AE, "self-empty");
    assert!(
        empty_sam.contains("Adata = \r\nC = \r\nT = "),
        "빈 PT 응답 형식 불일치"
    );
}
