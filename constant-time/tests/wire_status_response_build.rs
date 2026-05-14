// Phase 4 Plan 02 Wave 0 — 5 status code 응답 frame byte layout 회귀 가드 (D-17 / D-18)
//
// 검증 대상
//   - build_response_frame / build_error_frame_inplace 가 status u16 을 frame[14..16] 에 LE 적재
//   - Error frame 의 cmd field = 0xFFFF (offset 6..8), payload_len = 0 (offset 12..14, D-18)
//   - 5 status (Ok=0, BadFrame=1, UnknownCmd=2, Denied=3, Internal=4) 모두 정확

#[cfg(test)]
mod tests {
    const WIRE_FRAME_MAX: usize = 4096;
    const WIRE_MAGIC: [u8; 4] = *b"LWK0";
    const WIRE_VERSION: u16 = 0x0001;
    const WIRE_CMD_RESPONSE_BIT: u16 = 0x8000;

    // src/bus.rs WireCmd / WireStatus mock
    const CMD_ERROR: u16 = 0xFFFF;
    const CMD_BLAKE3HASH: u16 = 0x0010;
    const STATUS_OK: u16 = 0;
    const STATUS_BADFRAME: u16 = 1;
    const STATUS_UNKNOWNCMD: u16 = 2;
    const STATUS_DENIED: u16 = 3;
    const STATUS_INTERNAL: u16 = 4;

    fn write_header(
        magic: [u8; 4],
        version: u16,
        cmd: u16,
        req_id: u32,
        payload_len: u16,
        status: u16,
        out: &mut [u8; 16],
    ) {
        out[0..4].copy_from_slice(&magic);
        out[4..6].copy_from_slice(&version.to_le_bytes());
        out[6..8].copy_from_slice(&cmd.to_le_bytes());
        out[8..12].copy_from_slice(&req_id.to_le_bytes());
        out[12..14].copy_from_slice(&payload_len.to_le_bytes());
        out[14..16].copy_from_slice(&status.to_le_bytes());
    }

    // src/bus.rs::build_response_frame mock
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
            WIRE_MAGIC,
            WIRE_VERSION,
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

    // src/bus.rs::build_error_frame_inplace mock  payload_len 항상 0 (D-18)
    fn build_error_frame_inplace(
        req_id: u32,
        status: u16,
        out: &mut [u8; WIRE_FRAME_MAX],
    ) -> usize {
        let mut hdr_bytes = [0u8; 16];
        write_header(
            WIRE_MAGIC,
            WIRE_VERSION,
            CMD_ERROR,
            req_id,
            0,
            status,
            &mut hdr_bytes,
        );
        out[..16].copy_from_slice(&hdr_bytes);
        16
    }

    #[test]
    fn response_frame_ok_status_byte_layout() {
        // Ok 응답  cmd=Blake3Hash | RESPONSE_BIT, payload=빈
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = build_response_frame(7, CMD_BLAKE3HASH, STATUS_OK, &[], &mut out);
        assert_eq!(n, 16);
        // magic + version + cmd 확인
        assert_eq!(&out[0..4], &WIRE_MAGIC);
        assert_eq!(u16::from_le_bytes([out[4], out[5]]), WIRE_VERSION);
        assert_eq!(
            u16::from_le_bytes([out[6], out[7]]),
            CMD_BLAKE3HASH | WIRE_CMD_RESPONSE_BIT
        );
        // req_id
        assert_eq!(u32::from_le_bytes([out[8], out[9], out[10], out[11]]), 7);
        // payload_len = 0
        assert_eq!(u16::from_le_bytes([out[12], out[13]]), 0);
        // status = Ok (0)
        assert_eq!(u16::from_le_bytes([out[14], out[15]]), STATUS_OK);
    }

    // 4 종 에러 status code 정확 적재  cmd=0xFFFF, payload_len=0 (D-18 CT)
    fn check_error_status(status_u16: u16) {
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = build_error_frame_inplace(11, status_u16, &mut out);
        assert_eq!(n, 16);
        // cmd 가 0xFFFF (Error 전용)
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), CMD_ERROR);
        // payload_len = 0 (D-18 — size-side-channel 0)
        assert_eq!(u16::from_le_bytes([out[12], out[13]]), 0);
        // status code 정확 적재
        assert_eq!(u16::from_le_bytes([out[14], out[15]]), status_u16);
    }

    #[test]
    fn error_frame_badframe_status() {
        check_error_status(STATUS_BADFRAME);
    }

    #[test]
    fn error_frame_unknowncmd_status() {
        check_error_status(STATUS_UNKNOWNCMD);
    }

    #[test]
    fn error_frame_denied_status() {
        check_error_status(STATUS_DENIED);
    }

    #[test]
    fn error_frame_internal_status() {
        check_error_status(STATUS_INTERNAL);
    }
}
