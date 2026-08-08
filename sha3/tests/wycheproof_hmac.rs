#![allow(clippy::upper_case_acronyms)]

use sha3::{SHA3, SHA3_224, SHA3_256, SHA3_384, SHA3_512};
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
    if s == "-" {
        return Vec::new();
    }
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

fn vectors(name: &str) -> Option<Vec<Vec<String>>> {
    let Some(root) = cavp_root() else {
        eprintln!("cavp 디렉터리 없음 - Wycheproof {name} 생략");
        return None;
    };
    let path = root.join("Wycheproof-HMAC").join(name);
    let Ok(text) = fs::read_to_string(&path) else {
        eprintln!("{}: 벡터 없음 - Wycheproof {name} 생략", path.display());
        return None;
    };
    let records = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split_whitespace().map(str::to_string).collect())
        .collect::<Vec<Vec<String>>>();
    (!records.is_empty()).then_some(records)
}

fn one_shot<H: SHA3>(msg: &[u8]) -> Vec<u8> {
    let mut h = H::new();
    h.update(msg);
    h.finalize().as_bytes().to_vec()
}

fn hmac<H: SHA3>(block: usize, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut k0 = if key.len() > block {
        one_shot::<H>(key)
    } else {
        key.to_vec()
    };
    k0.resize(block, 0);
    let mut inner = H::new();
    inner.update(&k0.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(msg);
    let inner_md = inner.finalize();
    let mut outer = H::new();
    outer.update(&k0.iter().map(|b| b ^ 0x5C).collect::<Vec<u8>>());
    outer.update(inner_md.as_bytes());
    outer.finalize().as_bytes().to_vec()
}

fn run_hmac<H: SHA3>(name: &str, block: usize) {
    let Some(records) = vectors(&format!("{name}.txt")) else {
        return;
    };
    let (mut valid, mut invalid) = (0usize, 0usize);
    let mut mismatches = Vec::new();
    for r in &records {
        let ctx = format!("Wycheproof {name} tcId {} [{}]", r[0], r[6]);
        let tag_bits = r[2]
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("{ctx}: tagSize 해석 불가"));
        let key = hex_decode(&r[3], &ctx);
        let msg = hex_decode(&r[4], &ctx);
        let tag = hex_decode(&r[5], &ctx);
        let computed = hmac::<H>(block, &key, &msg);
        let matches = computed[..tag_bits / 8] == tag[..];
        match r[1].as_str() {
            "valid" => {
                valid += 1;
                if !matches {
                    mismatches.push(format!("{ctx}: 정상 태그 불일치"));
                }
            }
            "invalid" => {
                invalid += 1;
                if matches {
                    mismatches.push(format!("{ctx}: 위조 태그 수락"));
                }
            }
            other => panic!("{ctx}: 알 수 없는 판정 {other}"),
        }
    }
    assert!(
        mismatches.is_empty(),
        "{name} 불일치 {}건: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
    println!(
        "Wycheproof {name} {}건 통과 (valid {valid} / invalid {invalid})",
        records.len()
    );
}

#[test]
fn wycheproof_hmac_sha3() {
    run_hmac::<SHA3_224>("HMAC_SHA3-224", 144);
    run_hmac::<SHA3_256>("HMAC_SHA3-256", 136);
    run_hmac::<SHA3_384>("HMAC_SHA3-384", 104);
    run_hmac::<SHA3_512>("HMAC_SHA3-512", 72);
}
