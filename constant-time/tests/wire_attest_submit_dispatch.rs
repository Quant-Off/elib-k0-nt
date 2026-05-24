// Phase 5.1 Plan 05.1-04 GREEN — wire AttestSubmit dispatcher 성공/실패 경로 회귀 가드
//
// 검증 대상 (frame-layer-only — cryptographic-layer 는 Plan 05.1-05 책임)
//   - handle_attest_submit 의 Leg 1 (valid payload) 가 Ok 응답 16 옥텟 header only
//   - Leg 2 (mutated sig) 가 Denied 응답 cmd 0xFFFF status 3
//   - Leg 3 (payload_len != 3733) 가 BadFrame 응답
//
// host-side mock dispatcher 는 iso-light-k0 src/bus.rs::handle_attest_submit 의 6-step 본문을 byte-level mirror
// 실 ML-DSA-44 verify 는 mock_verify_attest (sig[0]==0xAA → Ok) 로 우회

#[cfg(test)]
mod tests {
    /// wire frame 최대 길이 Phase 4 D-15 lock
    const WIRE_FRAME_MAX: usize = 4096;
    /// wire magic LWK0
    const WIRE_MAGIC: [u8; 4] = *b"LWK0";
    /// wire version v1
    const WIRE_VERSION: u16 = 0x0001;
    /// 응답 비트 마스크
    const WIRE_CMD_RESPONSE_BIT: u16 = 0x8000;
    /// Phase 5.1 신규 dispatcher AttestSubmit
    const CMD_ATTEST_SUBMIT: u16 = 0x0040;
    /// 성공 status
    const STATUS_OK: u16 = 0;
    /// bad frame status
    const STATUS_BAD_FRAME: u16 = 1;
    /// denied status
    const STATUS_DENIED: u16 = 3;
    /// 에러 frame cmd
    const CMD_ERROR: u16 = 0xFFFF;
    /// Phase 5.1 D-01 ABI lock = MLDSA44 PK_LEN 1312 + 1 bus_kind + SIG_LEN 2420
    const WIRE_ATTEST_LEN: usize = 3733;
    /// PK 길이 잠금
    const PK_LEN: usize = 1312;
    /// SIG 길이 잠금
    const SIG_LEN: usize = 2420;

    // 컴파일-타임 ABI 가드
    const _: () = assert!(WIRE_ATTEST_LEN == PK_LEN + 1 + SIG_LEN);

    /// 16 옥텟 wire header 직렬화 Phase 4 wire_blake3_response_bitexact L19-32 mirror
    fn write_header(cmd: u16, req_id: u32, payload_len: u16, status: u16, out: &mut [u8; 16]) {
        out[0..4].copy_from_slice(&WIRE_MAGIC);
        out[4..6].copy_from_slice(&WIRE_VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&cmd.to_le_bytes());
        out[8..12].copy_from_slice(&req_id.to_le_bytes());
        out[12..14].copy_from_slice(&payload_len.to_le_bytes());
        out[14..16].copy_from_slice(&status.to_le_bytes());
    }

    /// 응답 frame 빌더 Phase 4 wire_blake3_response_bitexact L34-53 mirror
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
        if !payload.is_empty() {
            out[16..16 + payload.len()].copy_from_slice(payload);
        }
        16 + payload.len()
    }

    /// 에러 frame 빌더 iso-light-k0 src/bus.rs::build_error_frame_inplace mirror
    /// cmd = 0xFFFF, payload_len = 0 (D-18 size-side-channel 제거)
    fn build_error_frame(req_id: u32, status: u16, out: &mut [u8; WIRE_FRAME_MAX]) -> usize {
        let mut hdr_bytes = [0u8; 16];
        write_header(CMD_ERROR, req_id, 0, status, &mut hdr_bytes);
        out[..16].copy_from_slice(&hdr_bytes);
        16
    }

    /// host-side mock verify_attest Plan 05.1-02 의 mldsa::MLDSA44::verify 자리
    /// 단순화 sig[0]==0xAA → Ok 외 → Err  cryptographic-layer 는 Plan 05.1-05 책임
    fn mock_verify_attest(
        _pk: &[u8; PK_LEN],
        _bus_kind: u8,
        sig: &[u8; SIG_LEN],
    ) -> Result<(), ()> {
        if sig[0] == 0xAAu8 { Ok(()) } else { Err(()) }
    }

    /// host-side mock dispatcher iso-light-k0 src/bus.rs::handle_attest_submit L243-280 byte-level mirror
    /// 6-step (length sanity → split → BusKind decode → verify → audit → response)
    fn mock_handle_attest_submit(
        req_id: u32,
        payload: &[u8],
        out: &mut [u8; WIRE_FRAME_MAX],
    ) -> usize {
        // (1) payload 길이 정확 3733 옥텟 (Pitfall 1)
        if payload.len() != WIRE_ATTEST_LEN {
            return build_error_frame(req_id, STATUS_BAD_FRAME, out);
        }
        // (2) split pk 1312 || bus_kind 1 || sig 2420
        // SAFETY  payload.len == WIRE_ATTEST_LEN 검증 통과, repr 균등 byte stream
        let pk: &[u8; PK_LEN] = unsafe { &*(payload.as_ptr() as *const [u8; PK_LEN]) };
        let bus_octet = payload[PK_LEN];
        let sig: &[u8; SIG_LEN] =
            unsafe { &*(payload[PK_LEN + 1..].as_ptr() as *const [u8; SIG_LEN]) };
        // (3) bus_kind octet decode
        if !matches!(bus_octet, 0 | 1) {
            return build_error_frame(req_id, STATUS_BAD_FRAME, out);
        }
        // (4) mock verify
        match mock_verify_attest(pk, bus_octet, sig) {
            // (6) Ok → 16 옥텟 header only (payload_len = 0)
            Ok(()) => build_response_frame(req_id, CMD_ATTEST_SUBMIT, STATUS_OK, &[], out),
            // (6) Err → error frame status=3 Denied
            Err(()) => build_error_frame(req_id, STATUS_DENIED, out),
        }
    }

    /// 유효 payload AttestSubmit 가 Ok 응답 produce 회귀
    #[test]
    fn valid_payload_ok() {
        // (1) 유효 payload 빌드 pk=[0;1312] || bus_kind=0 || sig[0]=0xAA 외 임의
        let mut payload = [0u8; WIRE_ATTEST_LEN];
        payload[PK_LEN] = 0u8; // bus_kind = Software
        payload[PK_LEN + 1] = 0xAAu8; // sig[0] = mock-trusted
        // (2) mock dispatcher 호출
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = mock_handle_attest_submit(7, &payload, &mut out);
        // (3) 응답 16 옥텟 header only
        assert_eq!(n, 16, "Ok 응답은 header only 16 옥텟");
        // (4) magic + version 보존
        assert_eq!(&out[0..4], &WIRE_MAGIC);
        assert_eq!(u16::from_le_bytes([out[4], out[5]]), WIRE_VERSION);
        // (5) cmd = CMD_ATTEST_SUBMIT | RESPONSE_BIT = 0x8040
        assert_eq!(
            u16::from_le_bytes([out[6], out[7]]),
            CMD_ATTEST_SUBMIT | WIRE_CMD_RESPONSE_BIT,
            "cmd byte-exact"
        );
        // (6) req_id 보존
        assert_eq!(u32::from_le_bytes([out[8], out[9], out[10], out[11]]), 7);
        // (7) payload_len == 0
        assert_eq!(
            u16::from_le_bytes([out[12], out[13]]),
            0u16,
            "Ok 응답 payload_len 0"
        );
        // (8) status == STATUS_OK
        assert_eq!(u16::from_le_bytes([out[14], out[15]]), STATUS_OK);
    }

    /// 변조 서명 payload 가 Denied 응답 produce 회귀
    #[test]
    fn tampered_sig_denied() {
        // (1) 유효 payload 빌드 후 sig[0] ^= 0xFF 변조 (0xAA → 0x55)
        let mut payload = [0u8; WIRE_ATTEST_LEN];
        payload[PK_LEN] = 0u8;
        payload[PK_LEN + 1] = 0xAAu8;
        payload[PK_LEN + 1] ^= 0xFFu8; // 0x55 → mock_verify Err
        // (2) mock dispatcher 호출
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = mock_handle_attest_submit(11, &payload, &mut out);
        // (3) error frame 16 옥텟 header only
        assert_eq!(
            n, 16,
            "Denied 응답도 header only 16 옥텟 (size-side-channel 제거)"
        );
        // (4) cmd == CMD_ERROR
        assert_eq!(
            u16::from_le_bytes([out[6], out[7]]),
            CMD_ERROR,
            "Denied 시 cmd 0xFFFF"
        );
        // (5) payload_len == 0
        assert_eq!(u16::from_le_bytes([out[12], out[13]]), 0u16);
        // (6) status == STATUS_DENIED
        assert_eq!(
            u16::from_le_bytes([out[14], out[15]]),
            STATUS_DENIED,
            "tampered sig 시 status 3"
        );
    }

    /// payload 길이 불일치 시 BadFrame 응답 produce 회귀
    #[test]
    fn wrong_payload_len_bad_frame() {
        // (1) 3732 옥텟 payload (1 옥텟 누락) 빌드
        let payload = [0u8; WIRE_ATTEST_LEN - 1];
        // (2) mock dispatcher 호출
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = mock_handle_attest_submit(13, &payload, &mut out);
        // (3) error frame
        assert_eq!(n, 16);
        // (4) cmd == CMD_ERROR
        assert_eq!(
            u16::from_le_bytes([out[6], out[7]]),
            CMD_ERROR,
            "BadFrame 시 cmd 0xFFFF"
        );
        // (5) status == STATUS_BAD_FRAME
        assert_eq!(
            u16::from_le_bytes([out[14], out[15]]),
            STATUS_BAD_FRAME,
            "잘못된 length 시 status 1"
        );
        // (6) payload_len == 0
        assert_eq!(u16::from_le_bytes([out[12], out[13]]), 0u16);
    }
}
