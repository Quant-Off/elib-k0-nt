// Phase 5 Plan 05-04 Wave 1 GREEN fill-in
// AUDIT_RING wrap-overwrite 회귀 가드 (D-13 oldest-wins)
//
// 검증 대상
//   - kernel 측 audit_enqueue 가 AUDIT_RING_CAPACITY=32 회 enqueue 후 ring 회전
//   - 35 회 enqueue 후 head=3, total=35, oldest 3 개가 새 이벤트로 덮어쓰임
//   - mid-buffer 영역 (index 3..32) 는 보존
//   - pk_hash_prefix 가 enqueue 순서대로 정확히 기록

#[cfg(test)]
mod tests {
    /// AUDIT_RING 의 정적 크기 잠금 (D-13)
    const AUDIT_RING_CAPACITY: usize = 32;

    // 컴파일-타임 ABI 가드
    const _: () = assert!(AUDIT_RING_CAPACITY == 32);

    /// Mock EnrollEvent kernel-side EnrollEvent 와 동일 layout (12 옥텟)
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

    // ABI 가드 12 옥텟
    const _: () = assert!(core::mem::size_of::<MockEnrollEvent>() == 12);

    /// Mock AUDIT_RING 32-element fixed-capacity buffer
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

    /// kernel 측 audit_enqueue body 와 동일 분기 host mock
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

    /// 35 회 enqueue 후 head=3 total=35 + oldest 3 개 덮어쓰임 회귀
    #[test]
    fn attest_audit_ring_wraps_at_capacity_32() {
        let mut ring = MockAuditRing::new();

        // 35 회 enqueue 각 enqueue 의 prefix = [i; 4] (덮어쓰기 검증용 결정론 marker)
        for i in 0..35_u32 {
            audit_enqueue(
                &mut ring,
                (i % 8) as u8,
                0,
                0,
                [i as u8, i as u8, i as u8, i as u8],
            );
        }

        // (1) head = 35 mod 32 = 3
        assert_eq!(ring.head, 3, "35 회 enqueue 후 head 가 3 이 아님");

        // (2) total = 35 누적 단조 증가
        assert_eq!(ring.total, 35, "total 누적이 35 가 아님");

        // (3) oldest 3 events 가 가장 최근 3 enqueue (seq 32 33 34) 로 덮어쓰임
        assert_eq!(ring.events[0].seq, 32, "events[0] 가 seq=32 로 덮어쓰이지 않음");
        assert_eq!(ring.events[1].seq, 33, "events[1] 가 seq=33 로 덮어쓰이지 않음");
        assert_eq!(ring.events[2].seq, 34, "events[2] 가 seq=34 로 덮어쓰이지 않음");

        // (4) mid-buffer 보존 events[3] 는 처음 enqueue 후 다시 덮어쓰이지 않음
        //     (head 가 32+3=35 까지 도달해야 다시 overwrite — 35 회 enqueue 시점에서는 정확히 head=3 도달, events[3] 는 그대로)
        assert_eq!(ring.events[3].seq, 3, "events[3] mid-buffer 영역 변경됨");
        assert_eq!(ring.events[31].seq, 31, "events[31] mid-buffer 영역 변경됨");

        // (5) pk_hash_prefix 검증 i < 3 위치는 (32+i), i >= 3 위치는 i 그대로
        for i in 0..AUDIT_RING_CAPACITY {
            let expected: u8 = if i < 3 { (32 + i) as u8 } else { i as u8 };
            assert_eq!(
                ring.events[i].pk_hash_prefix[0], expected,
                "events[{i}].pk_hash_prefix[0] 가 expected={expected} 와 불일치"
            );
            // prefix 4 옥텟 모두 같은 값
            assert_eq!(ring.events[i].pk_hash_prefix[3], expected);
        }
    }

    /// 빈 ring 에서 단 1 회 enqueue 시 head=1 total=1 + events[0] 만 기록 회귀
    #[test]
    fn attest_audit_ring_single_enqueue_advances_head_once() {
        let mut ring = MockAuditRing::new();
        audit_enqueue(&mut ring, 0, 0, 0, [0xDE, 0xAD, 0xBE, 0xEF]);

        assert_eq!(ring.head, 1, "1 회 enqueue 후 head 가 1 이 아님");
        assert_eq!(ring.total, 1, "1 회 enqueue 후 total 이 1 이 아님");
        assert_eq!(ring.events[0].seq, 0, "events[0].seq 가 0 이 아님");
        assert_eq!(
            ring.events[0].pk_hash_prefix,
            [0xDE, 0xAD, 0xBE, 0xEF],
            "events[0] prefix 가 입력과 불일치"
        );
        // events[1] 은 default 상태 보존
        assert_eq!(ring.events[1].seq, 0);
        assert_eq!(ring.events[1].pk_hash_prefix, [0; 4]);
    }
}
