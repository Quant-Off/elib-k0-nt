//! Phase 2 architectural acceptance — DMN-05.
//! caller -> MockTransport -> dispatch -> ed25519 keygen/sign/verify -> MockTransport -> caller 의
//! 단일 종단간 라운드트립이 통과해야 milestone 의 architectural acceptance 가 인정.

use elib_k0_ipc::{HEADER_LEN, MAGIC, MAX_FRAME, Op, VER, decode_header};
use elib_k0_mock_transport::{MockTransport, encode_op_to_wire};
use elib_k0d_core::serve_one;

/// Phase 2 의 architectural acceptance 통합 테스트.
/// SignKeygen -> Sign -> Verify 3-step 라운드트립이 모두 통과해야 wire codec +
/// dispatcher + Transport seam + ed25519 backend 가 모두 정상 동작.
#[test]
fn ed25519_e2e_roundtrip() {
    let seed: [u8; 32] = [0x42u8; 32];
    let message: &[u8] = b"phase 2 architectural acceptance";
    let msg_len = message.len();
    assert!(msg_len <= 1024, "test 전제: msg <= SIG-08 cap");

    let mut transport = MockTransport::new();
    let mut req_buf = [0u8; MAX_FRAME];
    let mut resp_buf = [0u8; MAX_FRAME];

    // ── (1) SignKeygenEd25519 ────────────────────────────────────
    let req_len = encode_op_to_wire(Op::SignKeygenEd25519, &seed, &mut req_buf)
        .expect("encode SignKeygenEd25519");
    transport
        .client_send(&req_buf[..req_len])
        .expect("client_send 1");

    serve_one(&mut transport);

    let resp_len = transport.client_recv(&mut resp_buf).expect("client_recv 1");
    assert_eq!(resp_len, HEADER_LEN + 64, "keygen response 는 11 + 64 byte");
    let h = decode_header(&resp_buf[..resp_len]).expect("decode_header keygen");
    assert_eq!(h.op, Op::SignKeygenEd25519);
    assert_eq!(h.len, 64);
    let pk_bytes: [u8; 32] = resp_buf[HEADER_LEN..HEADER_LEN + 32]
        .try_into()
        .expect("pk slice");
    let sk_bytes: [u8; 32] = resp_buf[HEADER_LEN + 32..HEADER_LEN + 64]
        .try_into()
        .expect("sk slice");
    assert_eq!(sk_bytes, seed, "Ed25519 sk 는 seed 자체");
    // MAGIC + VER 도 검증.
    assert_eq!(
        u32::from_le_bytes(resp_buf[..4].try_into().expect("magic")),
        MAGIC
    );
    assert_eq!(resp_buf[4], VER);

    // ── (2) SignEd25519 ──────────────────────────────────────────
    // payload = sk(32) || msg_len(u16 LE) || msg(msg_len)
    let mut sign_payload = [0u8; 32 + 2 + 1024];
    sign_payload[..32].copy_from_slice(&seed);
    sign_payload[32..34].copy_from_slice(&(msg_len as u16).to_le_bytes());
    sign_payload[34..34 + msg_len].copy_from_slice(message);
    let sign_payload_len = 34 + msg_len;

    let req_len = encode_op_to_wire(
        Op::SignEd25519,
        &sign_payload[..sign_payload_len],
        &mut req_buf,
    )
    .expect("encode SignEd25519");
    transport
        .client_send(&req_buf[..req_len])
        .expect("client_send 2");

    serve_one(&mut transport);

    let resp_len = transport.client_recv(&mut resp_buf).expect("client_recv 2");
    assert_eq!(resp_len, HEADER_LEN + 64, "sign response 는 11 + 64 byte");
    let h = decode_header(&resp_buf[..resp_len]).expect("decode_header sign");
    assert_eq!(h.op, Op::SignEd25519);
    assert_eq!(h.len, 64);
    let signature: [u8; 64] = resp_buf[HEADER_LEN..HEADER_LEN + 64]
        .try_into()
        .expect("sig slice");

    // ── (3) VerifyEd25519 ───────────────────────────────────────
    // payload = pk(32) || sig(64) || msg_len(u16 LE) || msg(msg_len)
    let mut verify_payload = [0u8; 32 + 64 + 2 + 1024];
    verify_payload[..32].copy_from_slice(&pk_bytes);
    verify_payload[32..96].copy_from_slice(&signature);
    verify_payload[96..98].copy_from_slice(&(msg_len as u16).to_le_bytes());
    verify_payload[98..98 + msg_len].copy_from_slice(message);
    let verify_payload_len = 98 + msg_len;

    let req_len = encode_op_to_wire(
        Op::VerifyEd25519,
        &verify_payload[..verify_payload_len],
        &mut req_buf,
    )
    .expect("encode VerifyEd25519");
    transport
        .client_send(&req_buf[..req_len])
        .expect("client_send 3");

    serve_one(&mut transport);

    let resp_len = transport.client_recv(&mut resp_buf).expect("client_recv 3");
    assert_eq!(resp_len, HEADER_LEN + 1, "verify response 는 11 + 1 byte");
    let h = decode_header(&resp_buf[..resp_len]).expect("decode_header verify");
    assert_eq!(h.op, Op::VerifyEd25519);
    assert_eq!(h.len, 1);
    assert_eq!(
        resp_buf[HEADER_LEN], 1u8,
        "유효한 서명에 대해 verify_ok = 1"
    );

    // ── (4) Tampered verify — 보너스 회귀 차단 ─────────────────
    let mut tampered_payload = verify_payload;
    // message 의 첫 바이트를 변조 (서명 일관성 깨짐).
    tampered_payload[98] ^= 0x01;

    let req_len = encode_op_to_wire(
        Op::VerifyEd25519,
        &tampered_payload[..verify_payload_len],
        &mut req_buf,
    )
    .expect("encode VerifyEd25519 tampered");
    transport
        .client_send(&req_buf[..req_len])
        .expect("client_send 4");

    serve_one(&mut transport);

    let resp_len = transport.client_recv(&mut resp_buf).expect("client_recv 4");
    assert_eq!(resp_len, HEADER_LEN + 1);
    assert_eq!(
        resp_buf[HEADER_LEN], 0u8,
        "변조된 메시지에 대해 verify_ok = 0"
    );
}
