// Phase 5.1 Plan 05.1-04 GREEN — re-attestation 시 slot mutation 0 회귀 가드
//
// 검증 대상 (host-side mock registry — 실 HsmRegistry 는 Plan 05.1-05 책임)
//   - wire AttestSubmit 성공 시 attached_count delta = 0 (re-attest 는 신뢰 재확인일 뿐 slot 미생성)
//   - wire AttestSubmit 실패 시 attached_count delta = 0 + audit enqueue (result=6)
//   - 어떠한 경우에도 mock registry slot[*].state / token / rights 변경 = 0
//
// Phase 5 attest_slot_unchanged_on_fail.rs (이름 mirror) + Phase 1 hsm_attach_fail_empty_recover.rs 확장
// host-side mock 만으로 frame-layer + registry mutation invariant 회귀

#[cfg(test)]
mod tests {
    /// AUDIT_RING 용량 Phase 5 D-13 lock
    const AUDIT_RING_CAPACITY: usize = 32;
    /// WireReattestOk result code Phase 5.1 RESEARCH §4.5
    const RESULT_WIRE_REATTEST_OK: u8 = 5;
    /// WireReattestFail result code Phase 5.1 RESEARCH §4.5
    const RESULT_WIRE_REATTEST_FAIL: u8 = 6;
    /// re-attestation sentinel slot index (slot 미특정 시 사용)
    const SLOT_SENTINEL: u8 = 0xFE;
    /// wire frame 최대 길이
    const WIRE_FRAME_MAX: usize = 4096;
    /// PK 길이
    const PK_LEN: usize = 1312;
    /// SIG 길이
    const SIG_LEN: usize = 2420;
    /// AttestSubmit payload 길이
    const WIRE_ATTEST_LEN: usize = PK_LEN + 1 + SIG_LEN;
    /// AttestSubmit cmd
    const CMD_ATTEST_SUBMIT: u16 = 0x0040;
    /// 응답 비트 마스크
    const WIRE_CMD_RESPONSE_BIT: u16 = 0x8000;
    /// 성공 status
    const STATUS_OK: u16 = 0;
    /// denied status
    const STATUS_DENIED: u16 = 3;
    /// 에러 frame cmd
    const CMD_ERROR: u16 = 0xFFFF;
    /// wire magic LWK0
    const WIRE_MAGIC: [u8; 4] = *b"LWK0";
    /// wire version v1
    const WIRE_VERSION: u16 = 0x0001;

    // 컴파일-타임 ABI 가드
    const _: () = assert!(AUDIT_RING_CAPACITY == 32);
    const _: () = assert!(WIRE_ATTEST_LEN == 3733);

    /// host-side mock registry slot state Phase 1 HsmSlot mirror (단순화)
    #[derive(Clone, Copy, Default)]
    struct MockSlot {
        state: u8,
        token: u64,
        rights: u32,
    }

    /// host-side mock registry Phase 1 HsmRegistry mirror (단순화)
    /// re-attest 가 attached_count / slot[*] 어떤 필드도 변경하지 않음을 회귀
    struct MockRegistry {
        slots: [MockSlot; 4],
        attached_count: usize,
    }

    impl MockRegistry {
        fn new_empty() -> Self {
            Self {
                slots: [MockSlot::default(); 4],
                attached_count: 0,
            }
        }

        /// 모든 slot snapshot byte-exact 비교용 raw
        fn slots_raw(&self) -> [(u8, u64, u32); 4] {
            [
                (
                    self.slots[0].state,
                    self.slots[0].token,
                    self.slots[0].rights,
                ),
                (
                    self.slots[1].state,
                    self.slots[1].token,
                    self.slots[1].rights,
                ),
                (
                    self.slots[2].state,
                    self.slots[2].token,
                    self.slots[2].rights,
                ),
                (
                    self.slots[3].state,
                    self.slots[3].token,
                    self.slots[3].rights,
                ),
            ]
        }
    }

    /// host-side mock audit event Phase 5 EnrollEvent 12옥텟 mirror (단순화)
    #[derive(Clone, Copy, Default)]
    #[allow(dead_code)]
    struct MockEvent {
        slot_idx: u8,
        result: u8,
        bus_kind: u8,
    }

    /// host-side mock audit ring (in-memory Vec replacement — 고정 32 슬롯)
    struct MockAuditRing {
        events: [MockEvent; AUDIT_RING_CAPACITY],
        head: usize,
        total: u32,
    }

    impl MockAuditRing {
        fn new_empty() -> Self {
            Self {
                events: [MockEvent::default(); AUDIT_RING_CAPACITY],
                head: 0,
                total: 0,
            }
        }

        fn enqueue(&mut self, slot_idx: u8, result: u8, bus_kind: u8) {
            self.events[self.head] = MockEvent {
                slot_idx,
                result,
                bus_kind,
            };
            self.head = (self.head + 1) % AUDIT_RING_CAPACITY;
            self.total = self.total.saturating_add(1);
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

    fn build_response_frame(
        req_id: u32,
        cmd: u16,
        status: u16,
        payload: &[u8],
        out: &mut [u8; WIRE_FRAME_MAX],
    ) -> usize {
        let mut hdr = [0u8; 16];
        write_header(
            cmd | WIRE_CMD_RESPONSE_BIT,
            req_id,
            payload.len() as u16,
            status,
            &mut hdr,
        );
        out[..16].copy_from_slice(&hdr);
        if !payload.is_empty() {
            out[16..16 + payload.len()].copy_from_slice(payload);
        }
        16 + payload.len()
    }

    fn build_error_frame(req_id: u32, status: u16, out: &mut [u8; WIRE_FRAME_MAX]) -> usize {
        let mut hdr = [0u8; 16];
        write_header(CMD_ERROR, req_id, 0, status, &mut hdr);
        out[..16].copy_from_slice(&hdr);
        16
    }

    fn mock_verify_attest(
        _pk: &[u8; PK_LEN],
        _bus_kind: u8,
        sig: &[u8; SIG_LEN],
    ) -> Result<(), ()> {
        if sig[0] == 0xAAu8 { Ok(()) } else { Err(()) }
    }

    /// host-side mock dispatcher iso-light-k0 src/bus.rs::handle_attest_submit byte-level mirror
    /// 핵심 invariant registry 변경 0 + AUDIT_RING enqueue 1 (slot=0xFE)
    /// `registry` 인자는 의도적으로 mutable 차용  본 함수가 어떤 필드도 변경하지 않음을
    /// 호출자에서 baseline diff 로 회귀 (D-10 atomicity invariant)
    #[allow(unused_variables)]
    fn mock_handle_attest_submit(
        req_id: u32,
        payload: &[u8],
        registry: &mut MockRegistry,
        audit_ring: &mut MockAuditRing,
        out: &mut [u8; WIRE_FRAME_MAX],
    ) -> usize {
        if payload.len() != WIRE_ATTEST_LEN {
            return build_error_frame(req_id, 1u16, out); // BadFrame
        }
        // SAFETY  payload.len 검증 통과
        let pk: &[u8; PK_LEN] = unsafe { &*(payload.as_ptr() as *const [u8; PK_LEN]) };
        let bus_octet = payload[PK_LEN];
        let sig: &[u8; SIG_LEN] =
            unsafe { &*(payload[PK_LEN + 1..].as_ptr() as *const [u8; SIG_LEN]) };
        if !matches!(bus_octet, 0 | 1) {
            return build_error_frame(req_id, 1u16, out);
        }
        let result = mock_verify_attest(pk, bus_octet, sig);
        let (audit_result_code, status) = match result {
            Ok(()) => (RESULT_WIRE_REATTEST_OK, STATUS_OK),
            Err(()) => (RESULT_WIRE_REATTEST_FAIL, STATUS_DENIED),
        };
        // 핵심  registry 는 절대 mutation 하지 않음  audit_ring 만 enqueue
        audit_ring.enqueue(SLOT_SENTINEL, audit_result_code, bus_octet);
        // registry 미변경 (attached_count + slot[*] 둘 다 보존)
        match status {
            STATUS_OK => build_response_frame(req_id, CMD_ATTEST_SUBMIT, STATUS_OK, &[], out),
            _ => build_error_frame(req_id, STATUS_DENIED, out),
        }
    }

    fn build_valid_payload() -> [u8; WIRE_ATTEST_LEN] {
        let mut p = [0u8; WIRE_ATTEST_LEN];
        p[PK_LEN] = 0u8; // bus_kind = Software
        p[PK_LEN + 1] = 0xAAu8; // sig[0] = mock-trusted
        p
    }

    fn build_tampered_payload() -> [u8; WIRE_ATTEST_LEN] {
        let mut p = build_valid_payload();
        p[PK_LEN + 1] ^= 0xFFu8; // 0xAA → 0x55  mock_verify Err
        p
    }

    /// wire AttestSubmit 성공 leg 가 slot 0 변경 회귀 (re-attest 는 신뢰 재확인 only)
    #[test]
    fn no_mutation_on_success() {
        let mut registry = MockRegistry::new_empty();
        let mut audit = MockAuditRing::new_empty();
        // (1) baseline snapshot
        let baseline_attached = registry.attached_count;
        let baseline_slots = registry.slots_raw();
        let baseline_total = audit.total;
        // (2) valid payload leg
        let payload = build_valid_payload();
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = mock_handle_attest_submit(1, &payload, &mut registry, &mut audit, &mut out);
        // (3) Ok 응답 (16 옥텟 header only)
        assert_eq!(n, 16);
        assert_eq!(
            u16::from_le_bytes([out[6], out[7]]),
            CMD_ATTEST_SUBMIT | WIRE_CMD_RESPONSE_BIT
        );
        assert_eq!(u16::from_le_bytes([out[14], out[15]]), STATUS_OK);
        // (4) registry mutation 0
        assert_eq!(
            registry.attached_count, baseline_attached,
            "성공 leg attached_count delta 0"
        );
        assert_eq!(
            registry.slots_raw(),
            baseline_slots,
            "성공 leg slot[*] state/token/rights 변경 0"
        );
        // (5) audit ring enqueue 1 (slot=0xFE, result=5)
        assert_eq!(audit.total, baseline_total + 1, "audit total +1");
        let last_idx = (audit.head + AUDIT_RING_CAPACITY - 1) % AUDIT_RING_CAPACITY;
        assert_eq!(audit.events[last_idx].slot_idx, SLOT_SENTINEL);
        assert_eq!(audit.events[last_idx].result, RESULT_WIRE_REATTEST_OK);
    }

    /// wire AttestSubmit 실패 leg 가 slot 0 변경 회귀 (Phase 5 D-10 atomicity)
    #[test]
    fn no_mutation_on_failure() {
        let mut registry = MockRegistry::new_empty();
        let mut audit = MockAuditRing::new_empty();
        let baseline_attached = registry.attached_count;
        let baseline_slots = registry.slots_raw();
        let baseline_total = audit.total;
        // tampered payload leg
        let payload = build_tampered_payload();
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = mock_handle_attest_submit(2, &payload, &mut registry, &mut audit, &mut out);
        // Denied 응답
        assert_eq!(n, 16);
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), CMD_ERROR);
        assert_eq!(u16::from_le_bytes([out[14], out[15]]), STATUS_DENIED);
        // registry mutation 0
        assert_eq!(
            registry.attached_count, baseline_attached,
            "실패 leg attached_count delta 0 D-10 atomicity"
        );
        assert_eq!(
            registry.slots_raw(),
            baseline_slots,
            "실패 leg slot[*] 보존 D-10 all-or-nothing"
        );
        // audit enqueue 1 (slot=0xFE, result=6 WireReattestFail)
        assert_eq!(audit.total, baseline_total + 1);
        let last_idx = (audit.head + AUDIT_RING_CAPACITY - 1) % AUDIT_RING_CAPACITY;
        assert_eq!(audit.events[last_idx].slot_idx, SLOT_SENTINEL);
        assert_eq!(audit.events[last_idx].result, RESULT_WIRE_REATTEST_FAIL);
    }

    /// registry attached_count delta = 0 회귀 (성공/실패 양측 5 회 반복)
    #[test]
    fn registry_attached_count_delta_zero() {
        let mut registry = MockRegistry::new_empty();
        let mut audit = MockAuditRing::new_empty();
        let baseline_attached = registry.attached_count;
        let baseline_slots = registry.slots_raw();
        // 5 회 attest valid 3 + tampered 2
        let valid = build_valid_payload();
        let tampered = build_tampered_payload();
        let mut out = [0u8; WIRE_FRAME_MAX];
        // valid * 3
        mock_handle_attest_submit(100, &valid, &mut registry, &mut audit, &mut out);
        mock_handle_attest_submit(101, &valid, &mut registry, &mut audit, &mut out);
        mock_handle_attest_submit(102, &valid, &mut registry, &mut audit, &mut out);
        // tampered * 2
        mock_handle_attest_submit(200, &tampered, &mut registry, &mut audit, &mut out);
        mock_handle_attest_submit(201, &tampered, &mut registry, &mut audit, &mut out);
        // attached_count delta 0
        assert_eq!(
            registry.attached_count, baseline_attached,
            "5 회 attest 후 attached_count delta 0"
        );
        assert_eq!(
            registry.slots_raw(),
            baseline_slots,
            "5 회 attest 후 slot[*] 보존"
        );
        // audit total = 5 (각 호출마다 1 회 enqueue)
        assert_eq!(audit.total, 5u32, "audit total 5 (3 ok + 2 fail)");
    }
}
