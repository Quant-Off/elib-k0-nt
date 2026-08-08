use aes::{AES256CBC, AES256GCM, BLOCK_SIZE, KEY_SIZE};
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

fn arr<const N: usize>(v: &[u8], ctx: &str) -> [u8; N] {
    v.try_into()
        .unwrap_or_else(|_| panic!("{ctx}: 길이 {} (기대 {N})", v.len()))
}

fn vectors(name: &str) -> Option<Vec<Vec<String>>> {
    let Some(root) = cavp_root() else {
        eprintln!("cavp 디렉터리 없음 - Wycheproof {name} 생략");
        return None;
    };
    let path = root.join("Wycheproof-AES").join(name);
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

fn pkcs7_pad(msg: &[u8]) -> Vec<u8> {
    let pad = BLOCK_SIZE - msg.len() % BLOCK_SIZE;
    let mut out = msg.to_vec();
    out.resize(msg.len() + pad, pad as u8);
    out
}

fn pkcs7_unpad(buf: &[u8]) -> Option<&[u8]> {
    let pad = *buf.last()? as usize;
    if pad == 0 || pad > BLOCK_SIZE || pad > buf.len() {
        return None;
    }
    buf[buf.len() - pad..]
        .iter()
        .all(|&b| b as usize == pad)
        .then_some(&buf[..buf.len() - pad])
}

#[test]
fn wycheproof_gcm() {
    let Some(records) = vectors("GCM.txt") else {
        return;
    };
    let (mut valid, mut invalid, mut acceptable) = (0usize, 0usize, 0usize);
    let mut mismatches = Vec::new();
    for r in &records {
        let ctx = format!("Wycheproof GCM tcId {} [{}]", r[0], r[8]);
        let key: [u8; KEY_SIZE] = arr(&hex_decode(&r[2], &ctx), &ctx);
        let iv = hex_decode(&r[3], &ctx);
        let aad = hex_decode(&r[4], &ctx);
        let msg = hex_decode(&r[5], &ctx);
        let ct = hex_decode(&r[6], &ctx);
        let tag = hex_decode(&r[7], &ctx);
        let mut gcm = AES256GCM::default();
        gcm.init(&key);
        let mut pt_buf = vec![0u8; ct.len()];
        let dec = gcm.decrypt_with_iv(&iv, &aad, &ct, &tag, &mut pt_buf);
        match r[1].as_str() {
            "valid" => {
                valid += 1;
                if !(dec.is_ok() && pt_buf == msg) {
                    mismatches.push(format!("{ctx}: 정상 입력 복호 실패 ({dec:?})"));
                    continue;
                }
                let mut ct_buf = vec![0u8; msg.len()];
                let mut tag_buf = vec![0u8; tag.len()];
                let enc = gcm.encrypt_with_iv(&iv, &aad, &msg, &mut ct_buf, &mut tag_buf);
                if !(enc.is_ok() && ct_buf == ct && tag_buf == tag) {
                    mismatches.push(format!("{ctx}: 암호화 출력 불일치 ({enc:?})"));
                }
            }
            "invalid" => {
                invalid += 1;
                if dec.is_ok() {
                    mismatches.push(format!("{ctx}: 위조 입력 수락"));
                }
            }
            "acceptable" => {
                acceptable += 1;
                if dec.is_ok() && pt_buf != msg {
                    mismatches.push(format!("{ctx}: 수락 후 평문 불일치"));
                }
            }
            other => panic!("{ctx}: 알 수 없는 판정 {other}"),
        }
    }
    assert!(
        mismatches.is_empty(),
        "Wycheproof GCM 불일치 {}건: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
    println!(
        "Wycheproof GCM 256비트 {}건 통과 (valid {valid} / invalid {invalid} / acceptable {acceptable})",
        records.len()
    );
}

#[test]
fn wycheproof_cbc_pkcs5() {
    let Some(records) = vectors("CBC_PKCS5.txt") else {
        return;
    };
    let (mut valid, mut invalid) = (0usize, 0usize);
    let mut mismatches = Vec::new();
    for r in &records {
        let ctx = format!("Wycheproof CBC tcId {} [{}]", r[0], r[6]);
        let key: [u8; KEY_SIZE] = arr(&hex_decode(&r[2], &ctx), &ctx);
        let iv: [u8; BLOCK_SIZE] = arr(&hex_decode(&r[3], &ctx), &ctx);
        let msg = hex_decode(&r[4], &ctx);
        let ct = hex_decode(&r[5], &ctx);
        let mut cbc = AES256CBC::default();
        cbc.init(&key);
        match r[1].as_str() {
            "valid" => {
                valid += 1;
                let padded = pkcs7_pad(&msg);
                let mut ct_buf = vec![0u8; padded.len()];
                let enc = cbc.encrypt(&iv, &padded, &mut ct_buf);
                if !(enc.is_ok() && ct_buf == ct) {
                    mismatches.push(format!("{ctx}: 암호화 출력 불일치 ({enc:?})"));
                    continue;
                }
                let mut pt_buf = vec![0u8; ct.len()];
                let dec = cbc.decrypt(&iv, &ct, &mut pt_buf);
                let stripped = dec.is_ok().then(|| pkcs7_unpad(&pt_buf)).flatten();
                if stripped != Some(&msg[..]) {
                    mismatches.push(format!("{ctx}: 복호 또는 패딩 제거 실패 ({dec:?})"));
                }
            }
            "invalid" => {
                invalid += 1;
                let mut pt_buf = vec![0u8; ct.len()];
                match cbc.decrypt(&iv, &ct, &mut pt_buf) {
                    Err(_) => {}
                    Ok(()) => {
                        if pkcs7_unpad(&pt_buf).is_some() {
                            mismatches.push(format!("{ctx}: 잘못된 패딩 수락"));
                        }
                    }
                }
            }
            other => panic!("{ctx}: 알 수 없는 판정 {other}"),
        }
    }
    assert!(
        mismatches.is_empty(),
        "Wycheproof CBC-PKCS5 불일치 {}건: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
    println!(
        "Wycheproof CBC-PKCS5 256비트 {}건 통과 (valid {valid} / invalid {invalid})",
        records.len()
    );
}
