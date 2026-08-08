use aes::{AES256, AES256CBC, AES256CTR, BLOCK_SIZE, KEY_SIZE};
use std::fs;
use std::path::{Path, PathBuf};

const MCT_OUTER: usize = 100;
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

fn arr<const N: usize>(v: &[u8], ctx: &str) -> [u8; N] {
    v.try_into()
        .unwrap_or_else(|_| panic!("{ctx}: 길이 {} (기대 {N})", v.len()))
}

fn load_records(path: &Path) -> Option<Vec<Vec<String>>> {
    let text = fs::read_to_string(path).ok()?;
    let records = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split_whitespace().map(str::to_string).collect())
        .collect::<Vec<Vec<String>>>();
    (!records.is_empty()).then_some(records)
}

fn vectors(name: &str) -> Option<Vec<Vec<String>>> {
    let Some(root) = cavp_root() else {
        eprintln!("cavp 디렉터리 없음 - ACVP {name} 생략");
        return None;
    };
    let path = root.join("ACVP-AES").join(name);
    match load_records(&path) {
        Some(records) => Some(records),
        None => {
            eprintln!("{}: 벡터 없음 - ACVP {name} 생략", path.display());
            None
        }
    }
}

fn report(label: &str, total: usize, mismatches: &[String]) {
    assert!(
        mismatches.is_empty(),
        "{label} 불일치 {}건 / 전체 {total}건: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
    println!("{label} {total}건 통과");
}

#[test]
fn acvp_ecb_aft() {
    let Some(records) = vectors("ECB_AFT.txt") else {
        return;
    };
    let mut mismatches = Vec::new();
    for r in &records {
        let ctx = format!("ECB AFT tcId {}", r[0]);
        let key: [u8; KEY_SIZE] = arr(&hex_decode(&r[2], &ctx), &ctx);
        let pt = hex_decode(&r[3], &ctx);
        let ct = hex_decode(&r[4], &ctx);
        let mut cipher = AES256::default();
        cipher.init(&key);
        let encrypt = r[1] == "encrypt";
        let (input, expected) = if encrypt { (&pt, &ct) } else { (&ct, &pt) };
        assert!(input.len().is_multiple_of(BLOCK_SIZE), "{ctx}: 블록 정렬");
        let mut out = Vec::with_capacity(input.len());
        for chunk in input.chunks_exact(BLOCK_SIZE) {
            let block: [u8; BLOCK_SIZE] = arr(chunk, &ctx);
            let processed = if encrypt {
                cipher.encrypt(&block)
            } else {
                cipher.decrypt(&block)
            };
            out.extend_from_slice(&processed);
        }
        if out != *expected {
            mismatches.push(ctx);
        }
    }
    report("ACVP ECB AFT", records.len(), &mismatches);
}

#[test]
fn acvp_cbc_aft() {
    let Some(records) = vectors("CBC_AFT.txt") else {
        return;
    };
    let mut mismatches = Vec::new();
    for r in &records {
        let ctx = format!("CBC AFT tcId {}", r[0]);
        let key: [u8; KEY_SIZE] = arr(&hex_decode(&r[2], &ctx), &ctx);
        let iv: [u8; BLOCK_SIZE] = arr(&hex_decode(&r[3], &ctx), &ctx);
        let pt = hex_decode(&r[4], &ctx);
        let ct = hex_decode(&r[5], &ctx);
        let mut cbc = AES256CBC::default();
        cbc.init(&key);
        let encrypt = r[1] == "encrypt";
        let (input, expected) = if encrypt { (&pt, &ct) } else { (&ct, &pt) };
        let mut out = vec![0u8; input.len()];
        let res = if encrypt {
            cbc.encrypt(&iv, input, &mut out)
        } else {
            cbc.decrypt(&iv, input, &mut out)
        };
        if res.is_err() || out != *expected {
            mismatches.push(format!("{ctx} ({res:?})"));
        }
    }
    report("ACVP CBC AFT", records.len(), &mismatches);
}

#[test]
fn acvp_ctr_aft() {
    let Some(records) = vectors("CTR_AFT.txt") else {
        return;
    };
    let mut mismatches = Vec::new();
    for r in &records {
        let ctx = format!("CTR AFT tcId {}", r[0]);
        let bits: usize = r[2]
            .parse()
            .unwrap_or_else(|_| panic!("{ctx}: payloadLen 파싱 실패"));
        let key: [u8; KEY_SIZE] = arr(&hex_decode(&r[3], &ctx), &ctx);
        let iv: [u8; BLOCK_SIZE] = arr(&hex_decode(&r[4], &ctx), &ctx);
        let pt = hex_decode(&r[5], &ctx);
        let ct = hex_decode(&r[6], &ctx);
        let encrypt = r[1] == "encrypt";
        let (input, expected) = if encrypt { (&pt, &ct) } else { (&ct, &pt) };
        assert_eq!(input.len(), bits.div_ceil(8), "{ctx}: payload 길이");
        let mut ctr = AES256CTR::default();
        ctr.init(&key);
        let mut out = vec![0u8; input.len()];
        ctr.apply_iv(&iv, input, &mut out)
            .unwrap_or_else(|e| panic!("{ctx}: {e:?}"));
        let rem = bits % 8;
        if rem != 0
            && let Some(last) = out.last_mut()
        {
            *last &= 0xFFu8 << (8 - rem);
        }
        if out != *expected {
            mismatches.push(ctx);
        }
    }
    report("ACVP CTR AFT", records.len(), &mismatches);
}

struct MctEntry {
    key: Vec<u8>,
    iv: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
}

fn load_mct(records: &[Vec<String>], dir: &str, has_iv: bool) -> Vec<MctEntry> {
    let mut entries: Vec<(usize, MctEntry)> = records
        .iter()
        .filter(|r| r[0] == dir)
        .map(|r| {
            let ctx = format!("MCT {dir} idx {}", r[1]);
            let idx: usize = r[1]
                .parse()
                .unwrap_or_else(|_| panic!("{ctx}: 인덱스 파싱 실패"));
            let key = hex_decode(&r[2], &ctx);
            let iv = if has_iv {
                hex_decode(&r[3], &ctx)
            } else {
                Vec::new()
            };
            let off = usize::from(has_iv);
            let pt = hex_decode(&r[3 + off], &ctx);
            let ct = hex_decode(&r[4 + off], &ctx);
            (idx, MctEntry { key, iv, pt, ct })
        })
        .collect();
    entries.sort_by_key(|(idx, _)| *idx);
    entries.into_iter().map(|(_, entry)| entry).collect()
}

fn run_ecb_mct_chain(entries: &[MctEntry], encrypt: bool, failures: &mut Vec<String>) {
    let dir = if encrypt { "encrypt" } else { "decrypt" };
    assert_eq!(entries.len(), MCT_OUTER, "ECB MCT {dir} 체크포인트 수");
    let mut key: [u8; KEY_SIZE] = arr(&entries[0].key, "ECB MCT 시드 키");
    let seed_src = if encrypt {
        &entries[0].pt
    } else {
        &entries[0].ct
    };
    let mut seed: [u8; BLOCK_SIZE] = arr(seed_src, "ECB MCT 시드 블록");
    for (i, entry) in entries.iter().enumerate() {
        let input = if encrypt { &entry.pt } else { &entry.ct };
        if entry.key != key || *input != seed {
            failures.push(format!("ECB MCT {dir} {i}: 체인 입력 불일치"));
            return;
        }
        let mut cipher = AES256::default();
        cipher.init(&key);
        let mut block = seed;
        let (mut prev, mut last) = ([0u8; BLOCK_SIZE], [0u8; BLOCK_SIZE]);
        for _ in 0..MCT_INNER {
            prev = last;
            last = if encrypt {
                cipher.encrypt(&block)
            } else {
                cipher.decrypt(&block)
            };
            block = last;
        }
        let expected = if encrypt { &entry.ct } else { &entry.pt };
        if *expected != last {
            failures.push(format!("ECB MCT {dir} {i}: 출력 불일치"));
            return;
        }
        for (dst, src) in key[..BLOCK_SIZE].iter_mut().zip(prev.iter()) {
            *dst ^= src;
        }
        for (dst, src) in key[BLOCK_SIZE..].iter_mut().zip(last.iter()) {
            *dst ^= src;
        }
        seed = last;
    }
}

fn run_cbc_mct_chain(entries: &[MctEntry], encrypt: bool, failures: &mut Vec<String>) {
    let dir = if encrypt { "encrypt" } else { "decrypt" };
    assert_eq!(entries.len(), MCT_OUTER, "CBC MCT {dir} 체크포인트 수");
    let mut key: [u8; KEY_SIZE] = arr(&entries[0].key, "CBC MCT 시드 키");
    let mut iv: [u8; BLOCK_SIZE] = arr(&entries[0].iv, "CBC MCT 시드 IV");
    let seed_src = if encrypt {
        &entries[0].pt
    } else {
        &entries[0].ct
    };
    let mut seed: [u8; BLOCK_SIZE] = arr(seed_src, "CBC MCT 시드 블록");
    for (i, entry) in entries.iter().enumerate() {
        let input = if encrypt { &entry.pt } else { &entry.ct };
        if entry.key != key || entry.iv != iv || *input != seed {
            failures.push(format!("CBC MCT {dir} {i}: 체인 입력 불일치"));
            return;
        }
        let mut cbc = AES256CBC::default();
        cbc.init(&key);
        let (mut prev, mut last) = ([0u8; BLOCK_SIZE], [0u8; BLOCK_SIZE]);
        if encrypt {
            let mut cv = iv;
            let mut cur = seed;
            for _ in 0..MCT_INNER {
                let mut out = [0u8; BLOCK_SIZE];
                cbc.encrypt(&cv, &cur, &mut out)
                    .unwrap_or_else(|e| panic!("CBC MCT {dir} {i}: {e:?}"));
                prev = last;
                last = out;
                cur = cv;
                cv = out;
            }
        } else {
            let mut cv = iv;
            let mut cur = seed;
            for j in 0..MCT_INNER {
                let mut out = [0u8; BLOCK_SIZE];
                cbc.decrypt(&cv, &cur, &mut out)
                    .unwrap_or_else(|e| panic!("CBC MCT {dir} {i}: {e:?}"));
                prev = last;
                last = out;
                let next_ct = if j == 0 { iv } else { prev };
                cv = cur;
                cur = next_ct;
            }
        }
        let expected = if encrypt { &entry.ct } else { &entry.pt };
        if *expected != last {
            failures.push(format!("CBC MCT {dir} {i}: 출력 불일치"));
            return;
        }
        for (dst, src) in key[..BLOCK_SIZE].iter_mut().zip(prev.iter()) {
            *dst ^= src;
        }
        for (dst, src) in key[BLOCK_SIZE..].iter_mut().zip(last.iter()) {
            *dst ^= src;
        }
        iv = last;
        seed = prev;
    }
}

#[test]
fn acvp_ecb_mct() {
    let Some(records) = vectors("ECB_MCT.txt") else {
        return;
    };
    let mut failures = Vec::new();
    run_ecb_mct_chain(&load_mct(&records, "encrypt", false), true, &mut failures);
    run_ecb_mct_chain(&load_mct(&records, "decrypt", false), false, &mut failures);
    assert!(failures.is_empty(), "ACVP ECB MCT 실패: {failures:?}");
    println!("ACVP ECB MCT 2체인 x {MCT_OUTER}회 통과");
}

#[test]
fn acvp_cbc_mct() {
    let Some(records) = vectors("CBC_MCT.txt") else {
        return;
    };
    let mut failures = Vec::new();
    run_cbc_mct_chain(&load_mct(&records, "encrypt", true), true, &mut failures);
    run_cbc_mct_chain(&load_mct(&records, "decrypt", true), false, &mut failures);
    assert!(failures.is_empty(), "ACVP CBC MCT 실패: {failures:?}");
    println!("ACVP CBC MCT 2체인 x {MCT_OUTER}회 통과");
}
