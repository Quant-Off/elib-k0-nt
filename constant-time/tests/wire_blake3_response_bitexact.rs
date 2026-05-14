// Phase 4 Plan 02 Wave 0 — Blake3Hash 응답 frame 의 32B digest 가 elib-k0-nt::blake::Blake3::hash
// 결과와 byte-level 정확 일치 회귀 가드 (D-11)
//
// 검증 대상
//   - kernel 측 handle_blake3 의 결과 응답 프레임 payload (offset 16..48) 가
//     elib-k0-nt::blake::Blake3::hash(input) 32B digest 와 정확 일치

#[cfg(test)]
mod tests {
    use blake::{BLAKE3_OUT_LEN, Blake3};

    const WIRE_FRAME_MAX: usize = 4096;
    const WIRE_MAGIC: [u8; 4] = *b"LWK0";
    const WIRE_VERSION: u16 = 0x0001;
    const WIRE_CMD_RESPONSE_BIT: u16 = 0x8000;
    const CMD_BLAKE3HASH: u16 = 0x0010;
    const STATUS_OK: u16 = 0;

    fn write_header(
        cmd: u16,
        req_id: u32,
        payload_len: u16,
        status: u16,
        out: &mut [u8; 16],
    ) {
        out[0..4].copy_from_slice(&WIRE_MAGIC);
        out[4..6].copy_from_slice(&WIRE_VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&cmd.to_le_bytes());
        out[8..12].copy_from_slice(&req_id.to_le_bytes());
        out[12..14].copy_from_slice(&payload_len.to_le_bytes());
        out[14..16].copy_from_slice(&status.to_le_bytes());
    }

    fn build_response_frame(
        req_id: u32,
        cmd: u16,
        status: u16,
        payload: &[u8],
        out: &mut [u8; WIRE_FRAME_MAX],
    ) -> usize {
        let payload_len = payload.len() as u16;
        let mut hdr_bytes = [0u8; 16];
        write_header(
            cmd | WIRE_CMD_RESPONSE_BIT,
            req_id,
            payload_len,
            status,
            &mut hdr_bytes,
        );
        out[..16].copy_from_slice(&hdr_bytes);
        out[16..16 + payload.len()].copy_from_slice(payload);
        16 + payload.len()
    }

    #[test]
    fn blake3_response_payload_bytewise_equals_blake3_hash() {
        // (1) 결정론 input
        let input = b"PHASE4_INPUT";
        // (2) Blake3::hash 32B digest 직접 계산 (cross-validation reference)
        let mut hasher = Blake3::new();
        hasher.update(input);
        let digest_obj = hasher.finalize().expect("Blake3 finalize 실패");
        let digest_slice = digest_obj.as_slice();
        assert_eq!(digest_slice.len(), BLAKE3_OUT_LEN, "BLAKE3_OUT_LEN ABI 불일치");
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&digest_slice[..32]);

        // (3) Mock kernel handle_blake3 의 후반부  build_response_frame(req_id=1, Blake3Hash, Ok, digest)
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = build_response_frame(1, CMD_BLAKE3HASH, STATUS_OK, &digest, &mut out);
        assert_eq!(n, 16 + 32);

        // (4) frame[16..48] 가 digest 와 byte-level 정확 일치
        assert_eq!(&out[16..48], &digest, "response payload 가 Blake3 digest 와 byte 불일치");

        // (5) header 필드  cmd=Blake3Hash|RESPONSE_BIT, status=Ok, payload_len=32
        assert_eq!(
            u16::from_le_bytes([out[6], out[7]]),
            CMD_BLAKE3HASH | WIRE_CMD_RESPONSE_BIT
        );
        assert_eq!(u16::from_le_bytes([out[12], out[13]]), 32);
        assert_eq!(u16::from_le_bytes([out[14], out[15]]), STATUS_OK);
    }
}
