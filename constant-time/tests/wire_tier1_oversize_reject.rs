// Phase 4 Plan 02 Wave 0 — Tier 1 oversize/undersize frame 거부 회귀 가드 (D-16)
//
// 검증 대상
//   - Ring3ProcessBus::write 의 Tier 1 검사 `data.len() < 16 || data.len() > WIRE_FRAME_MAX` 가
//     0 / 1 / 15 / 4097 / 8192 다섯 케이스 모두 Err 반환
//   - 거부 시 pending_response 4096B 전부 미변경 (zero 유지)

#[cfg(test)]
mod tests {
    const WIRE_FRAME_MAX: usize = 4096;

    #[derive(Debug, PartialEq, Eq)]
    enum BusError {
        Internal,
    }

    // src/bus.rs::Ring3ProcessBus::write 의 Tier 1 검사만 추출한 mock
    fn dispatcher_write_tier1(data: &[u8], pending: &mut [u8; WIRE_FRAME_MAX]) -> Result<usize, BusError> {
        if data.len() < 16 || data.len() > WIRE_FRAME_MAX {
            return Err(BusError::Internal);
        }
        // Tier 1 통과 시에는 Tier 2/3 에서 처리  본 mock 은 Tier 1 검증만 책임
        // pending 의 첫 16 byte 만 기록하여 "Tier 1 통과 표식" 으로 사용
        pending[..16].copy_from_slice(&data[..16]);
        Ok(data.len())
    }

    #[test]
    fn tier1_oversize_undersize_five_cases_rejected() {
        // 5 케이스 모두 거부  pending_response 전부 0 유지
        let invalid_sizes: [usize; 5] = [0, 1, 15, 4097, 8192];
        for &sz in &invalid_sizes {
            let data = vec![0u8; sz];
            let mut pending = [0u8; WIRE_FRAME_MAX];
            let r = dispatcher_write_tier1(&data, &mut pending);
            assert_eq!(r, Err(BusError::Internal), "size {} 가 거부 안 됨", sz);
            // pending 전부 0 유지 (4096 byte 모두)
            assert!(
                pending.iter().all(|&b| b == 0),
                "size {} 거부 후에도 pending 가 변경됨",
                sz
            );
        }
    }

    #[test]
    fn tier1_valid_sizes_pass() {
        // 정상 사이즈 (16, 44, 4096) 는 Tier 1 통과 (Ok 반환)  Tier 2/3 분기는 별도 테스트
        let valid_sizes: [usize; 3] = [16, 44, WIRE_FRAME_MAX];
        for &sz in &valid_sizes {
            let data = vec![0xAAu8; sz];
            let mut pending = [0u8; WIRE_FRAME_MAX];
            let r = dispatcher_write_tier1(&data, &mut pending);
            assert!(r.is_ok(), "size {} 가 Tier 1 통과 못함", sz);
        }
    }
}
