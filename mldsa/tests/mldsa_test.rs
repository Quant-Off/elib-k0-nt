use mldsa::{MLDSA44, MLDSA65, MLDSA87};

#[test]
fn test_mldsa44_keygen_sign_verify() {
    let xi = [0x42u8; 32];
    let (pk, sk) = MLDSA44::keygen(&xi).unwrap();

    let message = b"Hello, ML-DSA!";
    let ctx = b"";
    let rnd = [0x00u8; 32];

    let sig = MLDSA44::sign(&sk, message, ctx, &rnd).unwrap();
    let valid = MLDSA44::verify(&pk, message, &sig, ctx).unwrap();

    assert!(valid, "ML-DSA-44 서명 검증 실패");
}

#[test]
fn test_mldsa44_wrong_message() {
    let xi = [0x42u8; 32];
    let (pk, sk) = MLDSA44::keygen(&xi).unwrap();

    let message = b"Hello, ML-DSA!";
    let wrong_message = b"Wrong message";
    let ctx = b"";
    let rnd = [0x00u8; 32];

    let sig = MLDSA44::sign(&sk, message, ctx, &rnd).unwrap();
    let valid = MLDSA44::verify(&pk, wrong_message, &sig, ctx).unwrap();

    assert!(!valid, "잘못된 메시지에서 검증 통과해서는 안됨");
}

#[test]
fn test_mldsa65_keygen_sign_verify() {
    let xi = [0x55u8; 32];
    let (pk, sk) = MLDSA65::keygen(&xi).unwrap();

    let message = b"ML-DSA-65 Test";
    let ctx = b"test context";
    let rnd = [0x11u8; 32];

    let sig = MLDSA65::sign(&sk, message, ctx, &rnd).unwrap();
    let valid = MLDSA65::verify(&pk, message, &sig, ctx).unwrap();

    assert!(valid, "ML-DSA-65 서명 검증 실패");
}

#[test]
fn test_mldsa87_keygen_sign_verify() {
    let xi = [0xAAu8; 32];
    let (pk, sk) = MLDSA87::keygen(&xi).unwrap();

    let message = b"ML-DSA-87 Test";
    let ctx = b"";
    let rnd = [0x22u8; 32];

    let sig = MLDSA87::sign(&sk, message, ctx, &rnd).unwrap();
    let valid = MLDSA87::verify(&pk, message, &sig, ctx).unwrap();

    assert!(valid, "ML-DSA-87 서명 검증 실패");
}

#[test]
fn test_key_sizes() {
    assert_eq!(MLDSA44::PK_LEN, 1312);
    assert_eq!(MLDSA44::SK_LEN, 2560);
    assert_eq!(MLDSA44::SIG_LEN, 2420);

    assert_eq!(MLDSA65::PK_LEN, 1952);
    assert_eq!(MLDSA65::SK_LEN, 4032);
    assert_eq!(MLDSA65::SIG_LEN, 3309);

    assert_eq!(MLDSA87::PK_LEN, 2592);
    assert_eq!(MLDSA87::SK_LEN, 4896);
    assert_eq!(MLDSA87::SIG_LEN, 4627);
}

#[test]
fn test_deterministic_keygen() {
    let xi = [0x99u8; 32];

    let (pk1, sk1) = MLDSA44::keygen(&xi).unwrap();
    let (pk2, sk2) = MLDSA44::keygen(&xi).unwrap();

    assert_eq!(pk1, pk2, "동일 시드에서 공개키가 동일해야 함");
    assert_eq!(sk1, sk2, "동일 시드에서 비밀키가 동일해야 함");
}

#[test]
fn test_context_too_long() {
    let xi = [0x42u8; 32];
    let (pk, sk) = MLDSA44::keygen(&xi).unwrap();

    let message = b"test";
    let long_ctx = [0u8; 256];
    let rnd = [0x00u8; 32];

    let result = MLDSA44::sign(&sk, message, &long_ctx, &rnd);
    assert!(result.is_err(), "256바이트 컨텍스트는 오류여야 함");

    let fake_sig = [0u8; 2420];
    let result = MLDSA44::verify(&pk, message, &fake_sig, &long_ctx);
    assert!(result.is_err(), "검증에서도 오류여야 함");
}
