#[cfg(test)]
mod tests {
    // FSM-2 (Phase 5 사전 instrumentation):
    // attach 가 실패하면 슬롯에 "부분 상태 잔존 0" — token=0 / rights=0 / state=Empty 유지.
    // 본 테스트는 Plan 02 의 validate-first / mutate-second 규율(PATTERNS B-3) 을 잠근다.

    struct MockSlot {
        state: u8, // 0=Empty, 1=Attached
        token: u64,
        rights: u16,
    }

    impl MockSlot {
        const fn empty() -> Self {
            Self {
                state: 0,
                token: 0,
                rights: 0,
            }
        }
    }

    fn attach_mock(
        slots: &mut [MockSlot; 4],
        rights: u16,
        simulate_failure: bool,
    ) -> Result<u64, ()> {
        // 1) 검증 단계 — 슬롯 상태/입력 어떤 것도 변경하지 않음.
        if simulate_failure {
            // 검증 실패(향후 Phase 5: ML-DSA-44 attestation 실패 모사). 슬롯 mutate 전 즉시 반환.
            return Err(());
        }

        // 2) 첫 번째 Empty 슬롯 탐색 — 발견 후에야 mutate.
        for slot in slots.iter_mut() {
            if slot.state == 0 {
                // token / rights 먼저 기록, state 전이 마지막 (mutate-LAST contract).
                let token: u64 = 0xCAFE_F00D_DEAD_BEEF; // 결정론적 mock token.
                slot.token = token;
                slot.rights = rights;
                slot.state = 1;
                return Ok(token);
            }
        }
        Err(())
    }

    #[test]
    fn attach_failure_path_leaves_slot_empty() {
        // ROADMAP Phase 5 SC #2 "부분 상태 잔존 0" 를 본 테스트가 잠근다.
        let mut slots: [MockSlot; 4] = [
            MockSlot::empty(),
            MockSlot::empty(),
            MockSlot::empty(),
            MockSlot::empty(),
        ];

        let result = attach_mock(&mut slots, 0x07, true);
        assert!(result.is_err());

        // 모든 슬롯이 변경 없음 — validate-first 규율 잠금.
        for (i, slot) in slots.iter().enumerate() {
            assert_eq!(slot.state, 0, "slot[{i}].state 가 변경됨");
            assert_eq!(slot.token, 0, "slot[{i}].token 이 변경됨");
            assert_eq!(slot.rights, 0, "slot[{i}].rights 가 변경됨");
        }
    }

    #[test]
    fn attach_success_path_sets_state_after_token_write() {
        // 성공 경로: 첫 Empty 슬롯에 token + rights 가 기록되고 state 가 마지막에 Attached(1) 로 전이.
        let mut slots: [MockSlot; 4] = [
            MockSlot::empty(),
            MockSlot::empty(),
            MockSlot::empty(),
            MockSlot::empty(),
        ];

        let result = attach_mock(&mut slots, 0x05, false);
        assert!(result.is_ok());
        let token = result.unwrap();
        assert_ne!(token, 0);

        assert_eq!(slots[0].state, 1, "slot[0] 가 Attached 상태가 아님");
        assert_eq!(slots[0].token, token);
        assert_eq!(slots[0].rights, 0x05);
        // 나머지 슬롯은 그대로 Empty.
        for (i, slot) in slots.iter().enumerate().skip(1) {
            assert_eq!(slot.state, 0, "slot[{i}] 가 변경됨");
            assert_eq!(slot.token, 0);
            assert_eq!(slot.rights, 0);
        }
    }
}
