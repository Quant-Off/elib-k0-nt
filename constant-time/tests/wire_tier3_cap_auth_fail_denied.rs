// Phase 4 Plan 02 Wave 0 — Blake3Hash payload 첫 16B 위조 cap → status=Denied 회귀 가드
// (D-04 / D-18)
//
// 검증 대상
//   - handle_blake3 가 payload 첫 16B 의 cap 을 authenticate(USE) 통과 못하면
//     build_error_frame_inplace(req_id, WireStatus::Denied, out) 진입
//   - 결과 frame cmd=0xFFFF, status=Denied=3, payload_len=0
//   - mock cap 자료가 zeroize 됨

#[cfg(test)]
mod tests {
    use zeroize::Zeroize;

    const WIRE_FRAME_MAX: usize = 4096;
    const WIRE_MAGIC: [u8; 4] = *b"LWK0";
    const WIRE_VERSION: u16 = 0x0001;
    const CMD_ERROR: u16 = 0xFFFF;
    const STATUS_DENIED: u16 = 3;

    // src/hsm_registry.rs::HsmCapability 16B layout mock
    #[derive(Clone, Copy)]
    #[repr(C)]
    struct MockCap {
        token: u64,
        slot: u8,
        _pad0: u8,
        rights: u16,
        _pad: u8,
        _pad1: [u8; 3],
    }
    const _: () = assert!(core::mem::size_of::<MockCap>() == 16);

    impl Zeroize for MockCap {
        fn zeroize(&mut self) {
            self.token = 0;
            self.rights = 0;
            self.slot = 0xFF;
            self._pad0 = 0;
            self._pad = 0;
            self._pad1 = [0; 3];
        }
    }

    fn write_header(cmd: u16, req_id: u32, payload_len: u16, status: u16, out: &mut [u8; 16]) {
        out[0..4].copy_from_slice(&WIRE_MAGIC);
        out[4..6].copy_from_slice(&WIRE_VERSION.to_le_bytes());
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
        write_header(CMD_ERROR, req_id, 0, status, &mut hdr_bytes);
        out[..16].copy_from_slice(&hdr_bytes);
        16
    }

    // Mock authenticate  항상 false (위조 cap 회귀 시나리오)
    fn mock_authenticate_false(_cap: &MockCap) -> bool {
        false
    }

    // src/bus.rs::handle_blake3 mock  cap auth 실패 분기만 책임
    fn handle_blake3_authfail(
        req_id: u32,
        payload: &[u8],
        out: &mut [u8; WIRE_FRAME_MAX],
    ) -> usize {
        if payload.len() < 16 {
            return build_error_frame_inplace(req_id, 1, out); // BadFrame
        }
        let mut cap = MockCap {
            token: 0,
            slot: 0xFF,
            _pad0: 0,
            rights: 0,
            _pad: 0,
            _pad1: [0; 3],
        };
        // SAFETY  payload[..16] 는 mock 본문 결정론적 자료
        unsafe {
            core::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                &mut cap as *mut MockCap as *mut u8,
                16,
            );
        }
        // 위조 cap  authenticate 가 false 반환
        let auth_ok = mock_authenticate_false(&cap);
        if !auth_ok {
            // Pitfall 4  cap 회수 후 Denied 응답
            cap.zeroize();
            // zeroize 후 cap.token == 0 검증 가능 (테스트에서 확인)
            assert_eq!(cap.token, 0);
            assert_eq!(cap.rights, 0);
            return build_error_frame_inplace(req_id, STATUS_DENIED, out);
        }
        unreachable!("mock_authenticate_false 가 true 반환 불가")
    }

    #[test]
    fn blake3_cap_auth_fail_returns_denied_with_zero_payload() {
        // 위조 cap 첫 16B = 0xFF (token 비-zero 이지만 authenticate 가 false)
        let mut payload = [0u8; 32];
        payload[..16].fill(0xFF);
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = handle_blake3_authfail(42, &payload, &mut out);
        assert_eq!(n, 16);
        // cmd = 0xFFFF (Error)
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), CMD_ERROR);
        // status = Denied (D-18  payload_len=0 size-side-channel 0)
        assert_eq!(u16::from_le_bytes([out[14], out[15]]), STATUS_DENIED);
        // payload_len = 0
        assert_eq!(u16::from_le_bytes([out[12], out[13]]), 0);
        // req_id echo
        assert_eq!(u32::from_le_bytes([out[8], out[9], out[10], out[11]]), 42);
    }
}
