use aes::{AES256GCM, Error, GCM_MIN_TAG_SIZE, KEY_SIZE};
use std::fs;
use std::path::{Path, PathBuf};

fn cavp_root() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("KCMVP_CAVP_DIR") {
        return Some(PathBuf::from(dir));
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.join("cavp");
    root.is_dir().then_some(root)
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

fn arr<const N: usize>(v: &[u8], ctx: &str) -> [u8; N] {
    v.try_into()
        .unwrap_or_else(|_| panic!("{ctx}: 길이 {} (기대 {N})", v.len()))
}

#[derive(Default)]
struct Case {
    count: String,
    key: Vec<u8>,
    iv: Vec<u8>,
    pt: Vec<u8>,
    aad: Vec<u8>,
    ct: Vec<u8>,
    tag: Vec<u8>,
    fail: bool,
    started: bool,
}

fn parse_rsp(text: &str, ctx: &str) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut cur = Case::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if line == "FAIL" {
            cur.fail = true;
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            panic!("{ctx}: 해석 불가 행 {line:?}");
        };
        let (name, value) = (name.trim(), value.trim());
        if name == "Count" {
            if cur.started {
                cases.push(std::mem::take(&mut cur));
            }
            cur.started = true;
            cur.count = value.to_string();
            continue;
        }
        let field_ctx = format!("{ctx} Count {} {name}", cur.count);
        let bytes = hex_decode(value, &field_ctx);
        match name {
            "Key" => cur.key = bytes,
            "IV" => cur.iv = bytes,
            "PT" => cur.pt = bytes,
            "AAD" => cur.aad = bytes,
            "CT" => cur.ct = bytes,
            "Tag" => cur.tag = bytes,
            other => panic!("{ctx}: 알 수 없는 필드 {other}"),
        }
    }
    if cur.started {
        cases.push(cur);
    }
    cases
}

fn load_cases(name: &str) -> Option<Vec<Case>> {
    let Some(root) = cavp_root() else {
        eprintln!("cavp 디렉터리 없음 - NIST GCM {name} 생략");
        return None;
    };
    let path = root.join("NIST-GCM").join(name);
    let Ok(text) = fs::read_to_string(&path) else {
        eprintln!("{}: 벡터 없음 - NIST GCM {name} 생략", path.display());
        return None;
    };
    let cases = parse_rsp(&text, name);
    (!cases.is_empty()).then_some(cases)
}

fn run_cases(name: &str, cases: &[Case], decrypt: bool) {
    let (mut ran, mut skipped, mut failed_expected) = (0usize, 0usize, 0usize);
    let mut mismatches = Vec::new();
    for case in cases {
        if case.tag.len() < GCM_MIN_TAG_SIZE {
            skipped += 1;
            continue;
        }
        ran += 1;
        let ctx = format!(
            "{name} Count {} (iv {}B tag {}B pt {}B aad {}B)",
            case.count,
            case.iv.len(),
            case.tag.len(),
            if decrypt {
                case.ct.len()
            } else {
                case.pt.len()
            },
            case.aad.len()
        );
        let key: [u8; KEY_SIZE] = arr(&case.key, &ctx);
        let mut gcm = AES256GCM::default();
        gcm.init(&key);
        if decrypt {
            let mut pt_buf = vec![0u8; case.ct.len()];
            let res = gcm.decrypt_with_iv(&case.iv, &case.aad, &case.ct, &case.tag, &mut pt_buf);
            let ok = match (&res, case.fail) {
                (Err(Error::AuthenticationFailed), true) => {
                    failed_expected += 1;
                    true
                }
                (Ok(()), false) => pt_buf == case.pt,
                _ => false,
            };
            if !ok {
                mismatches.push(format!("{ctx}: {res:?} (fail 기대 {})", case.fail));
            }
        } else {
            let mut ct_buf = vec![0u8; case.pt.len()];
            let mut tag_buf = vec![0u8; case.tag.len()];
            let res = gcm.encrypt_with_iv(&case.iv, &case.aad, &case.pt, &mut ct_buf, &mut tag_buf);
            if !(res.is_ok() && ct_buf == case.ct && tag_buf == case.tag) {
                mismatches.push(format!("{ctx}: 암호화 출력 불일치 ({res:?})"));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{name} 불일치 {}건 / 실행 {ran}건: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
    if decrypt {
        println!(
            "{name} {ran}건 통과 (인증 실패 판정 {failed_expected}건 포함, 태그 96비트 미만 {skipped}건 스킵)"
        );
    } else {
        println!("{name} {ran}건 통과 (태그 96비트 미만 {skipped}건 스킵)");
    }
}

#[test]
fn nist_cavs_gcm_encrypt_256() {
    let Some(cases) = load_cases("gcmEncryptExtIV256.rsp") else {
        return;
    };
    run_cases("gcmEncryptExtIV256", &cases, false);
}

#[test]
fn nist_cavs_gcm_decrypt_256() {
    let Some(cases) = load_cases("gcmDecrypt256.rsp") else {
        return;
    };
    run_cases("gcmDecrypt256", &cases, true);
}
