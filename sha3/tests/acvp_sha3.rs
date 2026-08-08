#![allow(clippy::upper_case_acronyms)]

use sha3::{SHA3, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, XOF};
use std::fs;
use std::path::{Path, PathBuf};

const MCT_COUNTS: usize = 100;
const MCT_INNER: usize = 1000;

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

fn load_lines(name: &str) -> Option<Vec<String>> {
    let Some(root) = cavp_root() else {
        eprintln!("cavp 디렉터리 없음 - ACVP {name} 생략");
        return None;
    };
    let path = root.join("ACVP-SHA3").join(name);
    let Ok(text) = fs::read_to_string(&path) else {
        eprintln!("{}: 벡터 없음 - ACVP {name} 생략", path.display());
        return None;
    };
    let lines = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect::<Vec<String>>();
    (!lines.is_empty()).then_some(lines)
}

fn one_shot<H: SHA3>(msg: &[u8]) -> Vec<u8> {
    let mut h = H::new();
    h.update(msg);
    h.finalize().as_bytes().to_vec()
}

fn xof_bits<H: XOF>(msg: &[u8], out_bits: usize, msb_align: bool) -> Vec<u8> {
    let mut h = H::new();
    h.update(msg);
    let mut out = vec![0u8; out_bits.div_ceil(8)];
    h.finalize_into(&mut out);
    let rem = out_bits % 8;
    if rem != 0
        && let Some(last) = out.last_mut()
    {
        let kept = *last & ((1u8 << rem) - 1);
        *last = if msb_align { kept << (8 - rem) } else { kept };
    }
    out
}

fn run_aft<H: SHA3>(alg: &str) {
    let Some(lines) = load_lines(&format!("{alg}_AFT.txt")) else {
        return;
    };
    let mut mismatches = Vec::new();
    for line in &lines {
        let f = line.split_whitespace().collect::<Vec<&str>>();
        let ctx = format!("ACVP {alg} AFT tcId {}", f[0]);
        let msg = hex_decode(f[1], &ctx);
        let md = hex_decode(f[2], &ctx);
        if one_shot::<H>(&msg) != md {
            mismatches.push(ctx);
        }
    }
    assert!(
        mismatches.is_empty(),
        "{alg} AFT 불일치 {}건: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
    println!("ACVP {alg} AFT {}건 통과", lines.len());
}

fn run_mct<H: SHA3>(alg: &str) {
    let Some(lines) = load_lines(&format!("{alg}_MCT.txt")) else {
        return;
    };
    assert_eq!(lines.len(), 2 + MCT_COUNTS, "{alg} MCT 형식 오류");
    assert_eq!(lines[0], "standard", "{alg} MCT 버전 미지원");
    let mut md = hex_decode(&lines[1], &format!("{alg} MCT seed"));
    for (i, expected_hex) in lines[2..].iter().enumerate() {
        let ctx = format!("ACVP {alg} MCT 체크포인트 {i}");
        let expected = hex_decode(expected_hex, &ctx);
        for _ in 0..MCT_INNER {
            md = one_shot::<H>(&md);
        }
        assert_eq!(md, expected, "{ctx} 불일치");
    }
    println!("ACVP {alg} MCT 체크포인트 {MCT_COUNTS}개 통과");
}

fn run_shake<H: XOF>(alg: &str, kind: &str) {
    let Some(lines) = load_lines(&format!("{alg}_{kind}.txt")) else {
        return;
    };
    let mut mismatches = Vec::new();
    for line in &lines {
        let f = line.split_whitespace().collect::<Vec<&str>>();
        let ctx = format!("ACVP {alg} {kind} tcId {}", f[0]);
        let msg = hex_decode(f[1], &ctx);
        let out_bits = f[2]
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("{ctx}: outLen 해석 불가"));
        let md = hex_decode(f[3], &ctx);
        if xof_bits::<H>(&msg, out_bits, kind == "FIPS202") != md {
            mismatches.push(format!("{ctx} (outLen {out_bits})"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{alg} {kind} 불일치 {}건: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
    println!("ACVP {alg} {kind} {}건 통과", lines.len());
}

fn run_shake_mct<H: XOF>(alg: &str) {
    let Some(lines) = load_lines(&format!("{alg}_MCT.txt")) else {
        return;
    };
    assert_eq!(lines.len(), 2 + MCT_COUNTS, "{alg} MCT 형식 오류");
    let bounds = lines[0].split_whitespace().collect::<Vec<&str>>();
    let min_bytes = bounds[0].parse::<usize>().unwrap() / 8;
    let max_bytes = bounds[1].parse::<usize>().unwrap() / 8;
    let range = max_bytes - min_bytes + 1;
    let mut out = hex_decode(&lines[1], &format!("{alg} MCT seed"));
    let mut out_len = max_bytes;
    for (i, line) in lines[2..].iter().enumerate() {
        let f = line.split_whitespace().collect::<Vec<&str>>();
        let ctx = format!("ACVP {alg} MCT 체크포인트 {i}");
        let expected_bits = f[0]
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("{ctx}: outLen 해석 불가"));
        let expected = hex_decode(f[1], &ctx);
        for _ in 0..MCT_INNER {
            let mut msg = [0u8; 16];
            let n = out.len().min(16);
            msg[..n].copy_from_slice(&out[..n]);
            out = xof_bits::<H>(&msg, out_len * 8, false);
            let rm = u16::from_be_bytes([out[out.len() - 2], out[out.len() - 1]]) as usize;
            out_len = min_bytes + rm % range;
        }
        assert_eq!(out.len() * 8, expected_bits, "{ctx} 출력 길이 불일치");
        assert_eq!(out, expected, "{ctx} 불일치");
    }
    println!("ACVP {alg} MCT 체크포인트 {MCT_COUNTS}개 통과");
}

fn run_ldt<H: SHA3>(alg: &str) {
    let Some(lines) = load_lines(&format!("{alg}_LDT.txt")) else {
        return;
    };
    for line in &lines {
        let f = line.split_whitespace().collect::<Vec<&str>>();
        let ctx = format!("ACVP {alg} LDT tcId {}", f[0]);
        let content = hex_decode(f[1], &ctx);
        let full_bits = f[2]
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{ctx}: 길이 해석 불가"));
        let md = hex_decode(f[3], &ctx);
        assert!(full_bits.is_multiple_of(8), "{ctx}: 비트 단위 길이");
        let total = full_bits / 8;
        let chunk = content.repeat(65536 / content.len());
        let mut h = H::new();
        let mut remaining = total;
        while remaining > 0 {
            let n = remaining.min(chunk.len() as u64) as usize;
            h.update(&chunk[..n]);
            remaining -= n as u64;
        }
        assert_eq!(h.finalize().as_bytes(), md, "{ctx} 불일치");
        println!("ACVP {alg} LDT tcId {} ({} MiB) 통과", f[0], total >> 20);
    }
}

#[test]
fn acvp_sha3_aft() {
    run_aft::<SHA3_224>("SHA3-224");
    run_aft::<SHA3_256>("SHA3-256");
    run_aft::<SHA3_384>("SHA3-384");
    run_aft::<SHA3_512>("SHA3-512");
}

#[test]
fn acvp_sha3_mct() {
    run_mct::<SHA3_224>("SHA3-224");
    run_mct::<SHA3_256>("SHA3-256");
    run_mct::<SHA3_384>("SHA3-384");
    run_mct::<SHA3_512>("SHA3-512");
}

#[test]
fn acvp_shake_aft() {
    run_shake::<SHAKE128>("SHAKE-128", "AFT");
    run_shake::<SHAKE128>("SHAKE-128", "VOT");
    run_shake::<SHAKE128>("SHAKE-128", "FIPS202");
    run_shake::<SHAKE256>("SHAKE-256", "AFT");
    run_shake::<SHAKE256>("SHAKE-256", "VOT");
    run_shake::<SHAKE256>("SHAKE-256", "FIPS202");
}

#[test]
fn acvp_shake_mct() {
    run_shake_mct::<SHAKE128>("SHAKE-128");
    run_shake_mct::<SHAKE256>("SHAKE-256");
}

#[test]
#[ignore = "대용량 (알고리즘당 15GiB) - cargo test --release -- --ignored 로 실행"]
fn acvp_sha3_ldt() {
    run_ldt::<SHA3_224>("SHA3-224");
    run_ldt::<SHA3_256>("SHA3-256");
    run_ldt::<SHA3_384>("SHA3-384");
    run_ldt::<SHA3_512>("SHA3-512");
}
