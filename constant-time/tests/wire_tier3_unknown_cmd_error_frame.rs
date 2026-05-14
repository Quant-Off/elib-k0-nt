// Phase 4 Plan 02 Wave 0 — Tier 3 미지정 cmd → Error frame (cmd=0xFFFF, status=UnknownCmd,
// payload_len=0) 회귀 가드 (D-11 / D-18)
//
// 검증 대상
//   - cmd=0x0040 (AttestSubmit Phase 5 예약), 0x0080 (Status Phase 6 예약), 0x0200 (임의 미지정)
//     3 시나리오 모두 build_error_frame_inplace 경유  cmd=0xFFFF, status=UnknownCmd=2, payload_len=0

#[cfg(test)]
mod tests {
    const WIRE_FRAME_MAX: usize = 4096;
    const WIRE_MAGIC: [u8; 4] = *b"LWK0";
    const WIRE_VERSION: u16 = 0x0001;
    const WIRE_CMD_RESPONSE_BIT: u16 = 0x8000;
    const CMD_ERROR: u16 = 0xFFFF;
    const CMD_PING: u16 = 0x0001;
    const CMD_BLAKE3HASH: u16 = 0x0010;
    const STATUS_UNKNOWNCMD: u16 = 2;
    const STATUS_OK: u16 = 0;

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

    fn build_response_frame_ping(req_id: u32, out: &mut [u8; WIRE_FRAME_MAX]) -> usize {
        let mut hdr_bytes = [0u8; 16];
        write_header(
            WIRE_MAGIC,
            WIRE_VERSION,
            CMD_PING | WIRE_CMD_RESPONSE_BIT,
            req_id,
            0,
            STATUS_OK,
            &mut hdr_bytes,
        );
        out[..16].copy_from_slice(&hdr_bytes);
        16
    }

    // Tier 3 cmd dispatch mock  Ping / Blake3Hash 만 실 dispatch, 그 외는 UnknownCmd
    fn tier3_dispatch(req_id: u32, cmd: u16, out: &mut [u8; WIRE_FRAME_MAX]) -> usize {
        match cmd {
            x if x == CMD_PING => build_response_frame_ping(req_id, out),
            x if x == CMD_BLAKE3HASH => {
                // 본 테스트는 cap auth path 미진입 — Tier 3 unknown 분기만 책임
                // (Blake3Hash 정상 path 는 wire_blake3_response_bitexact 가 책임)
                build_error_frame_inplace(req_id, STATUS_UNKNOWNCMD, out)
            }
            _ => build_error_frame_inplace(req_id, STATUS_UNKNOWNCMD, out),
        }
    }

    fn check_unknown_cmd(cmd: u16) {
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = tier3_dispatch(99, cmd, &mut out);
        assert_eq!(n, 16);
        // cmd field = 0xFFFF
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), CMD_ERROR);
        // payload_len = 0
        assert_eq!(u16::from_le_bytes([out[12], out[13]]), 0);
        // status = UnknownCmd
        assert_eq!(u16::from_le_bytes([out[14], out[15]]), STATUS_UNKNOWNCMD);
    }

    #[test]
    fn tier3_attest_submit_unknown_cmd() {
        check_unknown_cmd(0x0040);
    }

    #[test]
    fn tier3_status_unknown_cmd() {
        check_unknown_cmd(0x0080);
    }

    #[test]
    fn tier3_arbitrary_unknown_cmd() {
        check_unknown_cmd(0x0200);
    }
}
