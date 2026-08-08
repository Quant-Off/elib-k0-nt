use sha2::{SHA2, SHA224, SHA256, SHA384, SHA512};
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
    let path = root.join("ACVP-SHA2").join(name);
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

fn one_shot<H: SHA2>(msg: &[u8]) -> Vec<u8> {
    let mut h = H::new();
    h.update(msg);
    h.finalize().as_bytes().to_vec()
}

fn run_aft<H: SHA2>(alg: &str) {
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

fn run_mct<H: SHA2>(alg: &str) {
    let Some(lines) = load_lines(&format!("{alg}_MCT.txt")) else {
        return;
    };
    assert_eq!(lines.len(), 2 + MCT_COUNTS, "{alg} MCT 형식 오류");
    let version = lines[0].as_str();
    let mut seed = hex_decode(&lines[1], &format!("{alg} MCT seed"));
    let init_len = seed.len();
    for (i, expected_hex) in lines[2..].iter().enumerate() {
        let ctx = format!("ACVP {alg} MCT({version}) 체크포인트 {i}");
        let expected = hex_decode(expected_hex, &ctx);
        let (mut a, mut b, mut c) = (seed.clone(), seed.clone(), seed);
        let mut md = Vec::new();
        for _ in 0..MCT_INNER {
            let mut msg = a.clone();
            msg.extend_from_slice(&b);
            msg.extend_from_slice(&c);
            match version {
                "standard" => {}
                "alternate" => msg.resize(init_len, 0),
                other => panic!("{ctx}: 알 수 없는 MCT 버전 {other}"),
            }
            md = one_shot::<H>(&msg);
            a = b;
            b = c;
            c = md.clone();
        }
        assert_eq!(md, expected, "{ctx} 불일치");
        seed = md;
    }
    println!("ACVP {alg} MCT({version}) 체크포인트 {MCT_COUNTS}개 통과");
}

fn run_ldt<H: SHA2>(alg: &str) {
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
fn acvp_sha2_aft() {
    run_aft::<SHA224>("SHA2-224");
    run_aft::<SHA256>("SHA2-256");
    run_aft::<SHA384>("SHA2-384");
    run_aft::<SHA512>("SHA2-512");
}

#[test]
fn acvp_sha2_mct() {
    run_mct::<SHA224>("SHA2-224");
    run_mct::<SHA256>("SHA2-256");
    run_mct::<SHA384>("SHA2-384");
    run_mct::<SHA512>("SHA2-512");
}

#[test]
#[ignore = "대용량 (알고리즘당 15GiB) - cargo test --release -- --ignored 로 실행"]
fn acvp_sha2_ldt() {
    run_ldt::<SHA224>("SHA2-224");
    run_ldt::<SHA256>("SHA2-256");
    run_ldt::<SHA384>("SHA2-384");
    run_ldt::<SHA512>("SHA2-512");
}
