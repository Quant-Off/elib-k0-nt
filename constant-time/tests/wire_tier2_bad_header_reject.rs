// Phase 4 Plan 02 Wave 0 — Tier 2 magic/version/payload_len/cmd_is_request invariant
// 위반 시 단일 collapse (어느 invariant 가 실패했는지 변별 0) 회귀 가드 (D-16)
//
// 검증 대상
//   - magic 위조, version 위조, payload_len overflow, cmd_is_request 위반 4 시나리오 모두
//     동일 Err(BusError::Internal) 반환 + pending_response 미변경

#[cfg(test)]
mod tests {
    use constant_time::CtEqOps;

    const WIRE_FRAME_MAX: usize = 4096;
    const WIRE_PAYLOAD_MAX: usize = WIRE_FRAME_MAX - 16;
    const WIRE_MAGIC: [u8; 4] = *b"LWK0";
    const WIRE_VERSION: u16 = 0x0001;
    const WIRE_CMD_RESPONSE_BIT: u16 = 0x8000;
    const CMD_ERROR: u16 = 0xFFFF;

    #[derive(Debug, PartialEq, Eq)]
    enum BusError {
        Internal,
    }

    // src/bus.rs::Ring3ProcessBus::write 의 Tier 1 + Tier 2 검사 mock (Tier 3 미진입)
    fn dispatcher_write_tier12(
        data: &[u8],
        pending: &mut [u8; WIRE_FRAME_MAX],
    ) -> Result<usize, BusError> {
        if data.len() < 16 || data.len() > WIRE_FRAME_MAX {
            return Err(BusError::Internal);
        }
        // header parse  raw byte
        let magic = [data[0], data[1], data[2], data[3]];
        let version = u16::from_le_bytes([data[4], data[5]]);
        let cmd = u16::from_le_bytes([data[6], data[7]]);
        let payload_len = u16::from_le_bytes([data[12], data[13]]);
        // Tier 2 4 invariant  CT-friendly  단일 collapse
        let magic_u32 = u32::from_le_bytes(magic);
        let wire_magic_u32 = u32::from_le_bytes(WIRE_MAGIC);
        let magic_ok = CtEqOps::eq(&magic_u32, &wire_magic_u32).unwrap_u8() == 1;
        let version_ok = CtEqOps::eq(&version, &WIRE_VERSION).unwrap_u8() == 1;
        let len_ok =
            (payload_len as usize) + 16 <= data.len() && (payload_len as usize) <= WIRE_PAYLOAD_MAX;
        let cmd_is_request = (cmd & WIRE_CMD_RESPONSE_BIT) == 0 && cmd != CMD_ERROR;
        if !(magic_ok && version_ok && len_ok && cmd_is_request) {
            return Err(BusError::Internal);
        }
        // Tier 2 통과  pending 적재 (mock 은 본문 단순 echo)
        pending[..16].copy_from_slice(&data[..16]);
        Ok(data.len())
    }

    fn build_frame_bytes(
        magic: [u8; 4],
        version: u16,
        cmd: u16,
        req_id: u32,
        payload_len: u16,
        payload_pad: usize,
    ) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + payload_pad);
        v.extend_from_slice(&magic);
        v.extend_from_slice(&version.to_le_bytes());
        v.extend_from_slice(&cmd.to_le_bytes());
        v.extend_from_slice(&req_id.to_le_bytes());
        v.extend_from_slice(&payload_len.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // status = 0
        v.resize(16 + payload_pad, 0);
        v
    }

    #[test]
    fn tier2_bad_magic_rejected() {
        let data = build_frame_bytes([0x00, 0x57, 0x4B, 0x30], WIRE_VERSION, 0x0010, 1, 0, 0);
        let mut pending = [0u8; WIRE_FRAME_MAX];
        let r = dispatcher_write_tier12(&data, &mut pending);
        assert_eq!(r, Err(BusError::Internal));
        assert!(
            pending.iter().all(|&b| b == 0),
            "magic 위조 거부 후 pending 변경"
        );
    }

    #[test]
    fn tier2_bad_version_rejected() {
        let data = build_frame_bytes(WIRE_MAGIC, 0x0002, 0x0010, 1, 0, 0);
        let mut pending = [0u8; WIRE_FRAME_MAX];
        let r = dispatcher_write_tier12(&data, &mut pending);
        assert_eq!(r, Err(BusError::Internal));
        assert!(
            pending.iter().all(|&b| b == 0),
            "version 위조 거부 후 pending 변경"
        );
    }

    #[test]
    fn tier2_payload_len_overflow_rejected() {
        // payload_len = 4081 > WIRE_PAYLOAD_MAX (4080)
        let data = build_frame_bytes(WIRE_MAGIC, WIRE_VERSION, 0x0010, 1, 4081, 0);
        let mut pending = [0u8; WIRE_FRAME_MAX];
        let r = dispatcher_write_tier12(&data, &mut pending);
        assert_eq!(r, Err(BusError::Internal));
        assert!(
            pending.iter().all(|&b| b == 0),
            "payload_len overflow 거부 후 pending 변경"
        );
    }

    #[test]
    fn tier2_cmd_is_request_violation_rejected() {
        // cmd = 0xFFFF (Error)  request 분기 거부
        let data1 = build_frame_bytes(WIRE_MAGIC, WIRE_VERSION, CMD_ERROR, 1, 0, 0);
        let mut pending1 = [0u8; WIRE_FRAME_MAX];
        assert_eq!(
            dispatcher_write_tier12(&data1, &mut pending1),
            Err(BusError::Internal)
        );
        assert!(pending1.iter().all(|&b| b == 0));
        // cmd = 0x8001 (response bit set)  request 분기 거부
        let data2 = build_frame_bytes(WIRE_MAGIC, WIRE_VERSION, 0x8001, 1, 0, 0);
        let mut pending2 = [0u8; WIRE_FRAME_MAX];
        assert_eq!(
            dispatcher_write_tier12(&data2, &mut pending2),
            Err(BusError::Internal)
        );
        assert!(pending2.iter().all(|&b| b == 0));
    }
}
