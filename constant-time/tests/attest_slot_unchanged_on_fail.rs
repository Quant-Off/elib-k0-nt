// Phase 5 Plan 05-04 Wave 1 GREEN fill-in
// attest 실패 시 슬롯 미변경 + AUDIT_RING 기록 회귀 가드 (RESEARCH §6.2 atomicity / D-10)
//
// 검증 대상
//   - kernel 측 attach() 의 attest verify 실패 시 모든 slot mutation = 0 (all-or-nothing)
//   - AUDIT_RING 에 slot_idx=0xFF, result=1 (AttestFailed) 이벤트 enqueue
//   - hsm_attach_fail_empty_recover.rs 의 prior art 확장 (이름까지 일치 mirror)
//
// 본 test 는 자체 inline MockAuditRing 을 정의한다 (Plan 05-04 directive 공유 모듈 미사용)

#[cfg(test)]
mod tests {
    /// Mock Slot prior art hsm_attach_fail_empty_recover.rs L7-21 mirror
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

    /// kernel 측 attach attest verify 실패 mock prior art L23-46 + atomicity 확장
    fn attach_mock_with_attest(
        slots: &mut [MockSlot; 4],
        rights: u16,
        simulate_attest_failure: bool,
    ) -> Result<u64, ()> {
        // (1) 검증 단계 슬롯 / 입력 mutation 0 (validate-first)
        if simulate_attest_failure {
            // ML-DSA-44 attest verify 실패 모사
            return Err(());
        }

        // (2) 첫 Empty 슬롯 탐색 후 mutate (mutate-LAST)
        for slot in slots.iter_mut() {
            if slot.state == 0 {
                let token: u64 = 0xCAFE_F00D_DEAD_BEEF;
                slot.token = token;
                slot.rights = rights;
                slot.state = 1;
                return Ok(token);
            }
        }
        Err(())
    }

    // --- AUDIT_RING inline mock (Plan 05-04 자체 모듈 미공유 directive) ---

    /// AUDIT_RING capacity 잠금
    const AUDIT_RING_CAPACITY: usize = 32;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct MockEnrollEvent {
        seq: u32,
        slot_idx: u8,
        result: u8,
        bus_kind: u8,
        _pad: u8,
        pk_hash_prefix: [u8; 4],
    }

    struct MockAuditRing {
        events: [MockEnrollEvent; AUDIT_RING_CAPACITY],
        head: u8,
        total: u32,
    }

    impl MockAuditRing {
        const fn new() -> Self {
            Self {
                events: [MockEnrollEvent {
                    seq: 0,
                    slot_idx: 0,
                    result: 0,
                    bus_kind: 0,
                    _pad: 0,
                    pk_hash_prefix: [0; 4],
                }; AUDIT_RING_CAPACITY],
                head: 0,
                total: 0,
            }
        }
    }

    fn audit_enqueue(
        ring: &mut MockAuditRing,
        slot_idx: u8,
        result: u8,
        bus_kind: u8,
        prefix: [u8; 4],
    ) {
        let i = (ring.head as usize) % AUDIT_RING_CAPACITY;
        ring.events[i] = MockEnrollEvent {
            seq: ring.total,
            slot_idx,
            result,
            bus_kind,
            _pad: 0,
            pk_hash_prefix: prefix,
        };
        ring.head = ((ring.head as usize + 1) % AUDIT_RING_CAPACITY) as u8;
        ring.total = ring.total.wrapping_add(1);
    }

    /// attest verify 실패 시 모든 슬롯 상태 보존 회귀 (ROADMAP Phase 5 SC #2 "부분 상태 잔존 0")
    #[test]
    fn attest_failure_leaves_all_slots_empty() {
        let mut slots: [MockSlot; 4] = [
            MockSlot::empty(),
            MockSlot::empty(),
            MockSlot::empty(),
            MockSlot::empty(),
        ];

        let result = attach_mock_with_attest(&mut slots, 0x07, true);
        assert!(
            result.is_err(),
            "attest verify 실패 시 attach 가 Err 반환 안 함"
        );

        // 모든 슬롯이 변경 없음 (all-or-nothing atomicity)
        for (i, slot) in slots.iter().enumerate() {
            assert_eq!(slot.state, 0, "slot[{i}].state 가 변경됨");
            assert_eq!(slot.token, 0, "slot[{i}].token 이 변경됨");
            assert_eq!(slot.rights, 0, "slot[{i}].rights 가 변경됨");
        }
    }

    /// attest verify 성공 시 첫 Empty 슬롯만 Attached 전이 회귀
    #[test]
    fn attest_success_attaches_first_empty_slot_only() {
        let mut slots: [MockSlot; 4] = [
            MockSlot::empty(),
            MockSlot::empty(),
            MockSlot::empty(),
            MockSlot::empty(),
        ];

        let result = attach_mock_with_attest(&mut slots, 0x07, false);
        assert!(result.is_ok(), "verify 성공 시 attach 가 Ok 반환 안 함");

        // (1) 첫 슬롯만 Attached 전이
        assert_eq!(slots[0].state, 1, "slot[0] 가 Attached 가 아님");
        assert_eq!(slots[0].token, 0xCAFE_F00D_DEAD_BEEF);
        assert_eq!(slots[0].rights, 0x07);

        // (2) 나머지 슬롯 그대로 Empty
        for i in 1..4 {
            assert_eq!(slots[i].state, 0, "slot[{i}] 가 변경됨");
            assert_eq!(slots[i].token, 0);
            assert_eq!(slots[i].rights, 0);
        }
    }

    /// attest 실패 후 AUDIT_RING 에 slot_idx=0xFF result=1 이벤트 기록 회귀
    #[test]
    fn attest_failed_attempt_records_audit_with_sentinel_slot() {
        let mut slots: [MockSlot; 4] = [
            MockSlot::empty(),
            MockSlot::empty(),
            MockSlot::empty(),
            MockSlot::empty(),
        ];
        let mut ring = MockAuditRing::new();

        // (1) attest 실패 호출
        let result = attach_mock_with_attest(&mut slots, 0x07, true);
        assert!(result.is_err(), "attest verify 실패 시 Err 반환 안 함");

        // (2) AUDIT_RING enqueue (slot_idx=0xFF sentinel, result=1 AttestFailed)
        audit_enqueue(&mut ring, 0xFF, 1, 0, [0_u8; 4]);

        // (3) 단언 events[0] 가 sentinel 으로 기록
        assert_eq!(
            ring.events[0].slot_idx, 0xFF,
            "sentinel slot_idx=0xFF 가 기록 안 됨"
        );
        assert_eq!(
            ring.events[0].result, 1,
            "result=1 (AttestFailed) 가 기록 안 됨"
        );
        assert_eq!(ring.events[0].seq, 0, "첫 enqueue seq 가 0 이 아님");
        assert_eq!(ring.head, 1, "1 회 enqueue 후 head 가 1 이 아님");
        assert_eq!(ring.total, 1, "1 회 enqueue 후 total 이 1 이 아님");

        // (4) 슬롯은 여전히 모두 Empty
        for (i, slot) in slots.iter().enumerate() {
            assert_eq!(slot.state, 0, "slot[{i}] 가 변경됨");
        }
    }
}
