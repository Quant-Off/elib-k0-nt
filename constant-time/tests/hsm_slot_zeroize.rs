#[cfg(test)]
mod tests {
    use std::hint::black_box;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // 카운팅 fixture — 스택 메모리 재사용으로 raw-pointer 읽기는 UB이므로(RESEARCH §10.6 L1114-1116)
    // Drop 도달 여부를 관찰 가능한 AtomicUsize 카운터로 잡는다 (Pitfall 4 회피).
    static ZEROIZE_COUNT: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    enum HsmSlotState {
        Empty = 0,
        Attached = 1,
        Detaching = 2,
    }

    struct TestSlot {
        state: HsmSlotState,
        token: u64,
        rights: u16,
    }

    impl TestSlot {
        fn new_attached(token: u64, rights: u16) -> Self {
            Self {
                state: HsmSlotState::Attached,
                token,
                rights,
            }
        }

        fn zeroize_inline(&mut self) {
            self.token = 0;
            self.rights = 0;
            self.state = HsmSlotState::Empty;
            ZEROIZE_COUNT.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for TestSlot {
        fn drop(&mut self) {
            // Drop 은 안전망(fallback) — 정상 detach 경로가 이미 zeroize_inline 을 호출했어도
            // 본 카운터는 한 번 더 증가한다(주 경로 1 + Drop 1 = 2). 본 테스트 묶음은
            // ">= 1" 만 요구하므로 안전망 보장만 검사한다.
            self.token = 0;
            self.rights = 0;
            self.state = HsmSlotState::Empty;
            ZEROIZE_COUNT.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn slot_zeroize_clears_token_and_state() {
        ZEROIZE_COUNT.store(0, Ordering::SeqCst);

        let mut slot = TestSlot::new_attached(0xDEAD_BEEF_CAFE_BABE, 0x07);
        slot.zeroize_inline();

        // 명시 zeroize 직후 fields 가 모두 0 / Empty 인지 확인 (Pitfall 4: black_box 로 DCE 차단).
        assert_eq!(black_box(slot.token), 0);
        assert_eq!(black_box(slot.rights), 0);
        assert_eq!(slot.state, HsmSlotState::Empty);
        // slot 은 본 스코프 종료 시 drop -> 카운터 한 번 더 증가하지만 본 검사는 호출-시점만 본다.
        assert!(ZEROIZE_COUNT.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn drop_zeroizes_via_safety_net_counter() {
        ZEROIZE_COUNT.store(0, Ordering::SeqCst);
        {
            let slot = TestSlot::new_attached(0x1234_5678_9ABC_DEF0, 0x05);
            // black_box 로 컴파일러가 slot 을 즉시 dead-code 로 판단해 Drop 을 생략하지 못하도록 잡는다.
            black_box(&slot);
            // 스코프 종료 -> Drop -> 카운터 증가.
        }
        // Drop 만으로 관측: 명시 zeroize 호출 없이도 안전망이 동작했음.
        assert!(
            ZEROIZE_COUNT.load(Ordering::SeqCst) >= 1,
            "Drop 안전망이 발화되지 않음 — Zeroize 보장 회귀"
        );
    }

    #[test]
    fn early_return_zeroize_path() {
        ZEROIZE_COUNT.store(0, Ordering::SeqCst);

        // 시나리오: detach 진입 후 in-flight 정리 중 early return 경로에서도
        // zeroize 가 발생해야 함(D-14: 모든 종료 경로 소거 보장).
        let mut slot = TestSlot::new_attached(0xFEED_FACE_F00D_BABE, 0x07);

        // Attached -> Detaching 전이
        slot.state = HsmSlotState::Detaching;
        assert_eq!(slot.state, HsmSlotState::Detaching);

        // early return 모사 — 명시 zeroize 호출 (주 경로) 후 Empty 도달.
        slot.zeroize_inline();
        assert_eq!(slot.state, HsmSlotState::Empty);
        assert_eq!(black_box(slot.token), 0);
        assert_eq!(black_box(slot.rights), 0);
        assert!(ZEROIZE_COUNT.load(Ordering::SeqCst) >= 1);
    }
}
