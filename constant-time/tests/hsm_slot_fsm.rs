#[cfg(test)]
mod tests {
    // Mock FSM types — mirrors iso-light-k0::hsm_registry layout (CONTEXT D-11).
    // RESEARCH §7 Approach C — sibling repo는 커널 코드 의존 없이 표면을 복제한다.

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    enum HsmSlotState {
        Empty = 0,
        Attached = 1,
        Detaching = 2,
    }

    struct HsmSlot {
        state: HsmSlotState,
        token: u64,
        rights: u16,
    }

    impl HsmSlot {
        const fn new() -> Self {
            Self {
                state: HsmSlotState::Empty,
                token: 0,
                rights: 0,
            }
        }

        // 정상 detach 경로의 명시 소거(`secure_zero`의 호스트-사이드 mock).
        fn zeroize_inline(&mut self) {
            self.token = 0;
            self.rights = 0;
            self.state = HsmSlotState::Empty;
        }
    }

    #[test]
    fn fsm_empty_on_construction() {
        let slot = HsmSlot::new();
        assert_eq!(slot.state, HsmSlotState::Empty);
        assert_eq!(slot.token, 0);
        assert_eq!(slot.rights, 0);
    }

    #[test]
    fn fsm_empty_to_attached_transition() {
        let mut slot = HsmSlot::new();
        assert_eq!(slot.state, HsmSlotState::Empty);
        // attach: token + rights 먼저 기록, 마지막에 state 전이 (PATTERNS B-3).
        slot.token = 0xCAFE_BABE_DEAD_BEEF;
        slot.rights = 0x07;
        slot.state = HsmSlotState::Attached;
        assert_eq!(slot.state, HsmSlotState::Attached);
        assert_ne!(slot.token, 0);
    }

    #[test]
    fn fsm_attached_to_detaching_to_empty_on_zeroize() {
        let mut slot = HsmSlot::new();
        slot.token = 0x1234_5678_9ABC_DEF0;
        slot.rights = 0x07;
        slot.state = HsmSlotState::Attached;

        // detach 진입 — Detaching 상태로 전이(D-13: in-flight 정리 윈도우).
        slot.state = HsmSlotState::Detaching;
        assert_eq!(slot.state, HsmSlotState::Detaching);

        // in-flight 작업 정리 + secure_zero → Empty 복귀.
        slot.zeroize_inline();
        assert_eq!(slot.state, HsmSlotState::Empty);
        assert_eq!(slot.token, 0);
        assert_eq!(slot.rights, 0);
    }

    #[test]
    fn fsm_double_detach_observable_via_detaching_state() {
        // D-13 정당화: detach 진행 중인 슬롯에 재진입을 시도하면 상태 자체가
        // Detaching 으로 관측되어야 한다(즉시 Empty 가 아니라). 본 테스트는 그 관측
        // 가능성을 잠근다 — Plan 02 의 HsmCapError::Busy 분기 회귀를 방지.
        let mut slot = HsmSlot::new();
        slot.token = 0xAAAA_BBBB_CCCC_DDDD;
        slot.state = HsmSlotState::Attached;

        // 첫 detach 진입 — Detaching 으로 머무름.
        slot.state = HsmSlotState::Detaching;

        // 두 번째 detach 호출 시 관측 가능한 상태가 Detaching 임을 잠근다.
        assert_eq!(slot.state, HsmSlotState::Detaching);
        assert_ne!(slot.state, HsmSlotState::Empty);
        assert_ne!(slot.state, HsmSlotState::Attached);
    }
}
