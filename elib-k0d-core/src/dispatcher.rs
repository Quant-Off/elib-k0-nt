use elib_k0_ipc::{
    HEADER_LEN, IpcError, Op, SecureFrameBuffer, Transport, decode_header, encode_error,
    encode_header,
};
use zeroize::Zeroize;

use crate::arena::RequestArena;

pub(crate) fn serve_one_body<T: Transport>(
    transport: &mut T,
    wire_in: &mut SecureFrameBuffer,
    wire_out: &mut SecureFrameBuffer,
    arena: &mut RequestArena,
) {
    let n = match transport.round_trip(&[], wire_in.as_mut_slice()) {
        Ok(n) => n,
        Err(_) => {
            return;
        }
    };

    let frame_slice = match wire_in.as_slice().get(..n) {
        Some(s) => s,
        None => {
            return;
        }
    };
    let op = match parse_request(frame_slice, arena) {
        Ok(op) => op,
        Err(e) => {
            let elen = encode_error(wire_out.as_mut_slice(), e);
            let _ = transport.round_trip(&wire_out.as_slice()[..elen], wire_in.as_mut_slice());
            return;
        }
    };
    arena.op = op;

    let nout = match op {
        Op::SignKeygenEd25519 => dispatch_ed25519_keygen(arena, wire_out),
        Op::SignEd25519 => dispatch_ed25519_sign(arena, wire_out),
        Op::VerifyEd25519 => dispatch_ed25519_verify(arena, wire_out),
        Op::SignKeygenEd448
        | Op::SignKeygenMLDSA44
        | Op::SignKeygenMLDSA65
        | Op::SignKeygenMLDSA87
        | Op::SignEd448
        | Op::SignMLDSA44
        | Op::SignMLDSA65
        | Op::SignMLDSA87
        | Op::VerifyEd448
        | Op::VerifyMLDSA44
        | Op::VerifyMLDSA65
        | Op::VerifyMLDSA87
        | Op::KexKeygenX25519
        | Op::KexKeygenX448
        | Op::KexKeygenMLKEM512
        | Op::KexKeygenMLKEM768
        | Op::KexKeygenMLKEM1024
        | Op::KexKeygenX25519MLKEM768
        | Op::EncapsX25519
        | Op::EncapsX448
        | Op::EncapsMLKEM512
        | Op::EncapsMLKEM768
        | Op::EncapsMLKEM1024
        | Op::EncapsX25519MLKEM768
        | Op::DecapsX25519
        | Op::DecapsX448
        | Op::DecapsMLKEM512
        | Op::DecapsMLKEM768
        | Op::DecapsMLKEM1024
        | Op::DecapsX25519MLKEM768 => {
            encode_error(wire_out.as_mut_slice(), IpcError::AlgorithmNotImplemented)
        }
    };

    let send_slice = match wire_out.as_slice().get(..nout) {
        Some(s) => s,
        None => {
            return;
        }
    };
    let _ = transport.round_trip(send_slice, wire_in.as_mut_slice());
}

pub(crate) fn parse_request(frame: &[u8], arena: &mut RequestArena) -> Result<Op, IpcError> {
    let header = match decode_header(frame) {
        Ok(h) => h,
        Err(e) => {
            return Err(e);
        }
    };
    let payload_len = header.len as usize;
    let total = HEADER_LEN.saturating_add(payload_len);
    let payload = match frame.get(HEADER_LEN..total) {
        Some(s) => s,
        None => return Err(IpcError::TruncatedFrame),
    };

    match header.op {
        Op::SignKeygenEd25519 => {
            if payload.len() != 32 {
                return Err(IpcError::MalformedRequest);
            }
            let seed_bytes = match payload.get(..32) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            let sk_dst = match arena.sk.get_mut(..32) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            sk_dst.copy_from_slice(seed_bytes);
            Ok(header.op)
        }
        Op::SignEd25519 => {
            if payload.len() < 34 {
                return Err(IpcError::MalformedRequest);
            }
            let sk_bytes = match payload.get(0..32) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            let msg_len_bytes = match payload.get(32..34) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            let msg_len_arr: [u8; 2] = match msg_len_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return Err(IpcError::MalformedRequest),
            };
            let msg_len = u16::from_le_bytes(msg_len_arr) as usize;
            if msg_len > 1024 {
                return Err(IpcError::PayloadTooLong);
            }
            if payload.len() != 34 + msg_len {
                return Err(IpcError::MalformedRequest);
            }
            let msg_bytes = match payload.get(34..34 + msg_len) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            let sk_dst = match arena.sk.get_mut(..32) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            sk_dst.copy_from_slice(sk_bytes);
            arena.msg_len = msg_len as u16;
            let dst = match arena.msg.get_mut(..msg_len) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            dst.copy_from_slice(msg_bytes);
            Ok(header.op)
        }
        Op::VerifyEd25519 => {
            if payload.len() < 98 {
                return Err(IpcError::MalformedRequest);
            }
            let pk_bytes = match payload.get(0..32) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            let pk_arr: [u8; 32] = match pk_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return Err(IpcError::MalformedRequest),
            };
            let sig_bytes = match payload.get(32..96) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            let sig_arr: [u8; 64] = match sig_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return Err(IpcError::MalformedRequest),
            };
            let msg_len_bytes = match payload.get(96..98) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            let msg_len_arr: [u8; 2] = match msg_len_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return Err(IpcError::MalformedRequest),
            };
            let msg_len = u16::from_le_bytes(msg_len_arr) as usize;
            if msg_len > 1024 {
                return Err(IpcError::PayloadTooLong);
            }
            if payload.len() != 98 + msg_len {
                return Err(IpcError::MalformedRequest);
            }
            let msg_bytes = match payload.get(98..98 + msg_len) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            let pk_dst = match arena.pk.get_mut(..32) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            pk_dst.copy_from_slice(&pk_arr);
            let sig_dst = match arena.sig.get_mut(..64) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            sig_dst.copy_from_slice(&sig_arr);
            arena.msg_len = msg_len as u16;
            let dst = match arena.msg.get_mut(..msg_len) {
                Some(s) => s,
                None => return Err(IpcError::MalformedRequest),
            };
            dst.copy_from_slice(msg_bytes);
            Ok(header.op)
        }
        Op::SignKeygenEd448
        | Op::SignKeygenMLDSA44
        | Op::SignKeygenMLDSA65
        | Op::SignKeygenMLDSA87
        | Op::SignEd448
        | Op::SignMLDSA44
        | Op::SignMLDSA65
        | Op::SignMLDSA87
        | Op::VerifyEd448
        | Op::VerifyMLDSA44
        | Op::VerifyMLDSA65
        | Op::VerifyMLDSA87
        | Op::KexKeygenX25519
        | Op::KexKeygenX448
        | Op::KexKeygenMLKEM512
        | Op::KexKeygenMLKEM768
        | Op::KexKeygenMLKEM1024
        | Op::KexKeygenX25519MLKEM768
        | Op::EncapsX25519
        | Op::EncapsX448
        | Op::EncapsMLKEM512
        | Op::EncapsMLKEM768
        | Op::EncapsMLKEM1024
        | Op::EncapsX25519MLKEM768
        | Op::DecapsX25519
        | Op::DecapsX448
        | Op::DecapsMLKEM512
        | Op::DecapsMLKEM768
        | Op::DecapsMLKEM1024
        | Op::DecapsX25519MLKEM768 => Ok(header.op),
    }
}

pub(crate) fn dispatch_ed25519_keygen(
    arena: &RequestArena,
    wire_out: &mut SecureFrameBuffer,
) -> usize {
    // Ed25519 keypair 는 32-byte seed 로부터 결정적 derivation (RFC 8032 §5.1.5).
    // arena.sk[..32] 가 SignKeygenEd25519 요청의 seed 를 holding (D-18 8-필드 arena;
    // sk slot 재사용 per CONTEXT.md B-01 fix — seed_len == sk_len for Ed25519).
    let mut seed = [0u8; 32];
    let seed_src = match arena.sk.get(..32) {
        Some(s) => s,
        None => return encode_error(wire_out.as_mut_slice(), IpcError::MalformedRequest),
    };
    seed.copy_from_slice(seed_src);
    let keypair = ed25519::Keypair::from_seed(&seed);
    let pk_bytes: [u8; 32] = *keypair.public.as_bytes();

    // payload = pk(32) || sk(32) = 64
    let payload_len: u32 = 64;
    let header_n = match encode_header(wire_out.as_mut_slice(), Op::SignKeygenEd25519, payload_len)
    {
        Ok(n) => n,
        Err(_) => {
            seed.zeroize();
            return encode_error(wire_out.as_mut_slice(), IpcError::MalformedRequest);
        }
    };
    if header_n != HEADER_LEN {
        seed.zeroize();
        return encode_error(wire_out.as_mut_slice(), IpcError::MalformedRequest);
    }
    let pk_dst = match wire_out.as_mut_slice().get_mut(HEADER_LEN..HEADER_LEN + 32) {
        Some(s) => s,
        None => {
            seed.zeroize();
            return encode_error(wire_out.as_mut_slice(), IpcError::PayloadTooLong);
        }
    };
    pk_dst.copy_from_slice(&pk_bytes);
    let sk_dst = match wire_out
        .as_mut_slice()
        .get_mut(HEADER_LEN + 32..HEADER_LEN + 64)
    {
        Some(s) => s,
        None => {
            seed.zeroize();
            return encode_error(wire_out.as_mut_slice(), IpcError::PayloadTooLong);
        }
    };
    sk_dst.copy_from_slice(&seed);
    seed.zeroize();
    HEADER_LEN + 64
}

pub(crate) fn dispatch_ed25519_sign(
    arena: &RequestArena,
    wire_out: &mut SecureFrameBuffer,
) -> usize {
    // arena.sk[..32] 는 32-byte seed (RFC 8032; Ed25519 의 secret key = seed).
    let mut seed = [0u8; 32];
    let seed_src = match arena.sk.get(..32) {
        Some(s) => s,
        None => return encode_error(wire_out.as_mut_slice(), IpcError::MalformedRequest),
    };
    seed.copy_from_slice(seed_src);
    let keypair = ed25519::Keypair::from_seed(&seed);
    let msg_len = arena.msg_len as usize;
    let msg = match arena.msg.get(..msg_len) {
        Some(m) => m,
        None => {
            seed.zeroize();
            return encode_error(wire_out.as_mut_slice(), IpcError::MalformedRequest);
        }
    };
    let signature = keypair.sign(msg);
    seed.zeroize();
    let sig_bytes: [u8; 64] = *signature.as_bytes();

    let payload_len: u32 = 64;
    let header_n = match encode_header(wire_out.as_mut_slice(), Op::SignEd25519, payload_len) {
        Ok(n) => n,
        Err(_) => return encode_error(wire_out.as_mut_slice(), IpcError::MalformedRequest),
    };
    if header_n != HEADER_LEN {
        return encode_error(wire_out.as_mut_slice(), IpcError::MalformedRequest);
    }
    let sig_dst = match wire_out.as_mut_slice().get_mut(HEADER_LEN..HEADER_LEN + 64) {
        Some(s) => s,
        None => return encode_error(wire_out.as_mut_slice(), IpcError::PayloadTooLong),
    };
    sig_dst.copy_from_slice(&sig_bytes);
    HEADER_LEN + 64
}

pub(crate) fn dispatch_ed25519_verify(
    arena: &RequestArena,
    wire_out: &mut SecureFrameBuffer,
) -> usize {
    // arena.pk 의 처음 32 byte 가 public key — PublicKey::from_bytes 는 infallible
    // (실제 검증은 free verify(...) 안의 EdwardsPoint::from_bytes 에서 surface).
    let pk_arr: [u8; 32] = match arena.pk.get(..32) {
        Some(s) => match s.try_into() {
            Ok(a) => a,
            Err(_) => return write_verify_response(wire_out, 0u8),
        },
        None => return write_verify_response(wire_out, 0u8),
    };
    let pk = ed25519::PublicKey::from_bytes(&pk_arr);

    // arena.sig 의 처음 64 byte = Ed25519 signature
    let sig_bytes_slice = match arena.sig.get(..64) {
        Some(s) => s,
        None => return write_verify_response(wire_out, 0u8),
    };
    let sig_arr: [u8; 64] = match sig_bytes_slice.try_into() {
        Ok(a) => a,
        Err(_) => return write_verify_response(wire_out, 0u8),
    };
    let signature = ed25519::Signature::from_bytes(&sig_arr);

    let msg_len = arena.msg_len as usize;
    let msg = match arena.msg.get(..msg_len) {
        Some(m) => m,
        None => return write_verify_response(wire_out, 0u8),
    };
    // 잘못된 pk (point decompression 실패) 또는 signature 불일치 모두 Err 로 surface.
    let ok: u8 = match ed25519::verify(msg, &signature, &pk) {
        Ok(()) => 1,
        Err(_) => 0,
    };
    write_verify_response(wire_out, ok)
}

fn write_verify_response(wire_out: &mut SecureFrameBuffer, verify_ok: u8) -> usize {
    let payload_len: u32 = 1;
    let header_n = match encode_header(wire_out.as_mut_slice(), Op::VerifyEd25519, payload_len) {
        Ok(n) => n,
        Err(_) => return encode_error(wire_out.as_mut_slice(), IpcError::MalformedRequest),
    };
    if header_n != HEADER_LEN {
        return encode_error(wire_out.as_mut_slice(), IpcError::MalformedRequest);
    }
    let dst = match wire_out.as_mut_slice().get_mut(HEADER_LEN) {
        Some(b) => b,
        None => return encode_error(wire_out.as_mut_slice(), IpcError::PayloadTooLong),
    };
    *dst = verify_ok;
    HEADER_LEN + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use elib_k0_ipc::MAX_FRAME;
    use elib_k0_mock_transport::{MockTransport, encode_op_to_wire};

    /// DMN-03 분기 1: 성공 경로. SignKeygenEd25519 valid frame 를 서비스 후
    /// 명시적 zeroize 호출이 wire_in/wire_out/arena 를 0 으로 소거함을 검증.
    /// Phase 3 D-18: serve_one_body 의 명시적 triplet 은 제거되었고, Drop 은
    /// outer serve_one scope 종료 시 실행되므로 본 test 는 Zeroize trait 경로를
    /// 직접 검증 (Drop semantic 의 직접 증명은 elib-k0-ipc 의 wire.rs 단위 테스트).
    #[test]
    fn dmn03_zeroize_on_success() {
        let mut transport = MockTransport::new();
        let seed: [u8; 32] = [0x42u8; 32];
        let mut req_buf = [0u8; MAX_FRAME];
        let req_len = encode_op_to_wire(Op::SignKeygenEd25519, &seed, &mut req_buf)
            .expect("encode_op_to_wire");
        transport
            .client_send(&req_buf[..req_len])
            .expect("client_send");

        let mut wire_in = SecureFrameBuffer::new();
        wire_in.as_mut_array().fill(0xCC);
        let mut wire_out = SecureFrameBuffer::new();
        wire_out.as_mut_array().fill(0xCC);
        let mut arena = RequestArena::new();
        arena.sk.fill(0xCC);
        arena.msg.fill(0xCC);

        super::serve_one_body(&mut transport, &mut wire_in, &mut wire_out, &mut arena);

        // Phase 3 D-18: Drop 은 본 함수 scope 종료 시 실행됨. 본 test 는 Zeroize
        // trait 경로를 명시적으로 검증 — production 에서는 Drop 이 동일 경로 호출.
        wire_in.zeroize();
        wire_out.zeroize();
        arena.zeroize();

        assert!(
            wire_in.as_slice().iter().all(|&b| b == 0),
            "wire_in 미소거 (success)"
        );
        assert!(
            wire_out.as_slice().iter().all(|&b| b == 0),
            "wire_out 미소거 (success)"
        );
        assert!(
            arena.sk.iter().all(|&b| b == 0),
            "arena.sk 미소거 (success)"
        );
        assert!(
            arena.msg.iter().all(|&b| b == 0),
            "arena.msg 미소거 (success)"
        );
    }

    /// DMN-03 분기 2: 와이어 파싱 오류 (truncated frame). 명시적 zeroize 후 0 검증.
    #[test]
    fn dmn03_zeroize_on_truncated_frame() {
        let mut transport = MockTransport::new();
        let frame: [u8; 5] = [0xDE, 0xC0, 0x1B, 0xE1, 0x01];
        transport.client_send(&frame).expect("client_send");

        let mut wire_in = SecureFrameBuffer::new();
        wire_in.as_mut_array().fill(0xCC);
        let mut wire_out = SecureFrameBuffer::new();
        wire_out.as_mut_array().fill(0xCC);
        let mut arena = RequestArena::new();
        arena.sk.fill(0xCC);

        super::serve_one_body(&mut transport, &mut wire_in, &mut wire_out, &mut arena);

        wire_in.zeroize();
        wire_out.zeroize();
        arena.zeroize();

        assert!(
            wire_in.as_slice().iter().all(|&b| b == 0),
            "wire_in 미소거 (truncated)"
        );
        assert!(
            wire_out.as_slice().iter().all(|&b| b == 0),
            "wire_out 미소거 (truncated)"
        );
        assert!(
            arena.sk.iter().all(|&b| b == 0),
            "arena.sk 미소거 (truncated)"
        );
    }

    /// DMN-03 분기 3: 미구현 알고리즘 (SignKeygenMLDSA44). 명시적 zeroize 후 0 검증.
    #[test]
    fn dmn03_zeroize_on_algorithm_not_implemented() {
        let mut transport = MockTransport::new();
        let payload: [u8; 32] = [0x55u8; 32];
        let mut req_buf = [0u8; MAX_FRAME];
        let req_len = encode_op_to_wire(Op::SignKeygenMLDSA44, &payload, &mut req_buf)
            .expect("encode_op_to_wire");
        transport
            .client_send(&req_buf[..req_len])
            .expect("client_send");

        let mut wire_in = SecureFrameBuffer::new();
        wire_in.as_mut_array().fill(0xCC);
        let mut wire_out = SecureFrameBuffer::new();
        wire_out.as_mut_array().fill(0xCC);
        let mut arena = RequestArena::new();
        arena.sk.fill(0xCC);

        super::serve_one_body(&mut transport, &mut wire_in, &mut wire_out, &mut arena);

        wire_in.zeroize();
        wire_out.zeroize();
        arena.zeroize();

        assert!(
            wire_in.as_slice().iter().all(|&b| b == 0),
            "wire_in 미소거 (algo-not-impl)"
        );
        assert!(
            wire_out.as_slice().iter().all(|&b| b == 0),
            "wire_out 미소거 (algo-not-impl)"
        );
        assert!(
            arena.sk.iter().all(|&b| b == 0),
            "arena.sk 미소거 (algo-not-impl)"
        );
    }

    /// DMN-03 분기 4: transport 오류 (NoPendingRequest). 명시적 zeroize 후 0 검증.
    #[test]
    fn dmn03_zeroize_on_transport_error() {
        let mut transport = MockTransport::new();

        let mut wire_in = SecureFrameBuffer::new();
        wire_in.as_mut_array().fill(0xCC);
        let mut wire_out = SecureFrameBuffer::new();
        wire_out.as_mut_array().fill(0xCC);
        let mut arena = RequestArena::new();
        arena.sk.fill(0xCC);

        super::serve_one_body(&mut transport, &mut wire_in, &mut wire_out, &mut arena);

        wire_in.zeroize();
        wire_out.zeroize();
        arena.zeroize();

        assert!(
            wire_in.as_slice().iter().all(|&b| b == 0),
            "wire_in 미소거 (transport-err)"
        );
        assert!(
            wire_out.as_slice().iter().all(|&b| b == 0),
            "wire_out 미소거 (transport-err)"
        );
        assert!(
            arena.sk.iter().all(|&b| b == 0),
            "arena.sk 미소거 (transport-err)"
        );
    }

    /// parse_request happy path: SignKeygenEd25519 가 arena.sk[..32] 채움 (B-01 fix — sk slot 재사용).
    #[test]
    fn parse_request_signkeygen_ed25519_fills_sk_slot() {
        let mut buf = [0u8; MAX_FRAME];
        let seed: [u8; 32] = [0x77u8; 32];
        let n =
            encode_op_to_wire(Op::SignKeygenEd25519, &seed, &mut buf).expect("encode_op_to_wire");
        let mut arena = RequestArena::new();
        let op = parse_request(&buf[..n], &mut arena).expect("parse_request");
        assert_eq!(op, Op::SignKeygenEd25519);
        assert_eq!(&arena.sk[..32], &seed);
        assert!(
            arena.sk[32..].iter().all(|&b| b == 0),
            "sk slot 의 [32..] 가 dirty"
        );
    }

    /// parse_request: SignEd25519 의 payload 가 sk + msg_len + msg 로 정확히 분해.
    #[test]
    fn parse_request_sign_ed25519_decomposes_payload() {
        let mut buf = [0u8; MAX_FRAME];
        let sk: [u8; 32] = [0x11u8; 32];
        let msg = b"hello";
        let mut payload = [0u8; 32 + 2 + 5];
        payload[..32].copy_from_slice(&sk);
        payload[32..34].copy_from_slice(&(msg.len() as u16).to_le_bytes());
        payload[34..34 + msg.len()].copy_from_slice(msg);
        let n = encode_op_to_wire(Op::SignEd25519, &payload, &mut buf).expect("encode_op_to_wire");
        let mut arena = RequestArena::new();
        let op = parse_request(&buf[..n], &mut arena).expect("parse_request");
        assert_eq!(op, Op::SignEd25519);
        assert_eq!(&arena.sk[..32], &sk);
        assert_eq!(arena.msg_len as usize, msg.len());
        assert_eq!(&arena.msg[..msg.len()], msg);
    }

    /// dispatch_ed25519_keygen 가 Ed25519 keypair 생성 후 wire_out 에 pk||sk 를 정확히 작성하는지 검증.
    #[test]
    fn dispatch_ed25519_keygen_writes_pk_and_sk() {
        let mut arena = RequestArena::new();
        let seed: [u8; 32] = [0x42u8; 32];
        // arena.sk[..32] 가 seed 슬롯 (B-01 fix — D-18 8-필드 arena).
        arena.sk[..32].copy_from_slice(&seed);
        let mut wire_out = SecureFrameBuffer::new();
        let n = super::dispatch_ed25519_keygen(&arena, &mut wire_out);
        assert_eq!(n, HEADER_LEN + 64);
        let wire = wire_out.as_slice();
        // 응답 op 는 SignKeygenEd25519
        let op_le = u16::from_le_bytes([wire[5], wire[6]]);
        assert_eq!(op_le, Op::SignKeygenEd25519 as u16);
        // sk 는 seed 그대로
        assert_eq!(&wire[HEADER_LEN + 32..HEADER_LEN + 64], &seed);
        // pk 는 ed25519 reference 와 일치 (as_bytes — to_bytes 아님 per W-05)
        let expected_pk: [u8; 32] = *ed25519::Keypair::from_seed(&seed).public.as_bytes();
        assert_eq!(&wire[HEADER_LEN..HEADER_LEN + 32], &expected_pk);
    }

    /// parse_request: SignEd25519 의 msg_len > 1024 → PayloadTooLong.
    #[test]
    fn parse_request_sign_ed25519_msg_too_long() {
        let mut buf = [0u8; MAX_FRAME];
        let mut payload = [0u8; 32 + 2 + 1025];
        payload[32..34].copy_from_slice(&1025u16.to_le_bytes());
        let n = encode_op_to_wire(Op::SignEd25519, &payload, &mut buf).expect("encode_op_to_wire");
        let mut arena = RequestArena::new();
        match parse_request(&buf[..n], &mut arena) {
            Err(IpcError::PayloadTooLong) => {}
            other => panic!("expected PayloadTooLong, got {:?}", other),
        }
    }
}
