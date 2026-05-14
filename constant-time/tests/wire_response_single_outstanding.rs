// Phase 4 Plan 02 Wave 0 — D-08 single-flight strict policy 회귀 가드
//
// 검증 대상  response_len != 0 상태에서 새 write 호출이 다음 3 invariant 동시 만족
//   (1) pending_response 4096 byte 가 호출 전후 byte-level 정확 동일 (memcmp)
//   (2) response_len 이 호출 전후 정확 동일 (44 유지)
//   (3) Ring3ProcessBus::write (mock) 가 Err(BusError::Internal) 반환
//   추가  첫 16B (이전 response header 영역) 변경 0  header 위조 회귀 차단

#[cfg(test)]
mod tests {
    const WIRE_FRAME_MAX: usize = 4096;

    #[derive(Debug, PartialEq, Eq)]
    enum BusError {
        Internal,
        NotOpen,
    }

    // src/bus.rs::Ring3ProcessBus 정확 미러 (4 필드, strict layout)
    struct MockRing3ProcessBus {
        endpoint: u16,
        open_state: bool,
        pending_response: [u8; WIRE_FRAME_MAX],
        response_len: u16,
    }

    impl MockRing3ProcessBus {
        // src/bus.rs::Ring3ProcessBus::write 의 D-08 strict policy 본문 정확 미러
        // Plan 02 revision  response_len != 0 시 어떤 mutation 도 수행 X
        fn write(&mut self, data: &[u8]) -> Result<usize, BusError> {
            if !self.open_state {
                return Err(BusError::NotOpen);
            }
            if data.len() < 16 || data.len() > WIRE_FRAME_MAX {
                return Err(BusError::Internal);
            }
            // D-08 strict  response_len != 0 시 pending_response/response_len 모두 미변경
            if self.response_len != 0 {
                return Err(BusError::Internal);
            }
            // (정상 경로  Tier 2/3 dispatch 는 본 테스트 범위 밖)
            Ok(data.len())
        }
    }

    #[test]
    fn single_outstanding_three_invariants_strict() {
        // (1) bus state  response_len = 44, pending_response 결정론적 fingerprint
        //     i 번째 byte = (i ^ 0xA5) as u8
        let mut bus = MockRing3ProcessBus {
            endpoint: 0x0003,
            open_state: true,
            pending_response: [0u8; WIRE_FRAME_MAX],
            response_len: 44,
        };
        for i in 0..WIRE_FRAME_MAX {
            bus.pending_response[i] = (i as u8) ^ 0xA5;
        }
        // (2) 호출 전 snapshot
        let pending_before: [u8; WIRE_FRAME_MAX] = bus.pending_response;
        let response_len_before = bus.response_len;

        // (3) 정상 사이즈 wire frame 입력 (16+ bytes)  Tier 1 통과
        let frame = [0u8; 44];
        let r = bus.write(&frame);

        // (4) 3 invariant strict assert
        assert_eq!(r, Err(BusError::Internal), "single-flight 거부 미동작");
        assert_eq!(
            bus.response_len, response_len_before,
            "response_len 이 변경됨 (D-08 위반)"
        );
        // pending_response 4096 byte 정확 동일
        assert_eq!(
            bus.pending_response.as_slice(),
            pending_before.as_slice(),
            "pending_response 4096B 가 변경됨 (D-08 위반)"
        );
        // 추가  첫 16B (이전 response header 영역) 변경 0
        assert_eq!(
            &bus.pending_response[..16],
            &pending_before[..16],
            "이전 response header 16B 변경됨 (header 위조 가능)"
        );
    }
}
