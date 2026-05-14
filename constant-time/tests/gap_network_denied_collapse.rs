//! Phase 6 GAP-01 + GAP-02 — 5 NetworkDenied 콜럐스 카테고리 단일 RAX SyscallError::Denied 회귀 가드
//!
//! # 책임 경계
//! 본 파일은 iso-light-k0 의 5 NetworkDenied 콜럐스 카테고리가 모두
//! 단일 RAX = -4 (SyscallError::Denied) 로 일치함을 host-side 에서 시뮬한다
//! variant 노출 0 (Phase 1 Pitfall 7 + Shared-5 collapse 회귀 가드)
//! Wave 0 은 COMPILE-only RED 스켈레톤 Plan 06-04 + 06-02 GREEN fill-in
//! 직후 #[test] fn 본문이 5 audit_enqueue 호출 지점 검증으로 교체된다
//!
//! # 검증 대상
//!   - closed 빌드 handle_attach BusKind::Network 진입 → matchless `_` arm 거부 (D-01)
//!   - tls-external 빌드 NETWORK_ATTACH_CAP 미보유 호출 → Denied (D-01)
//!   - 5 NetworkDenied 카테고리 모두 RAX = -4 단일 일치 (Pitfall 7 정신)
//!   - 5 호출 지점이 (slot_idx, result) 튜플로 식별 가능
//!
//! # Decision: D-01
//! handle_attach Network arm cfg-split closed/tls-external 양쪽 거부 경로
//!
//! # Decision: D-02
//! NETWORK_ATTACH_CAP one-shot mint + first-caller-wins
//!
//! # Decision: D-04
//! EnrollEvent.result 의 2 코드 5 NetworkDenied 콜럐스 카테고리

#![allow(dead_code)]
#![allow(clippy::all)]

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    /// SyscallError::Denied 의 RAX 잠금 Phase 5 D-11 lock
    /// iso-light-k0 src/syscall.rs SyscallError::Denied = -4 (Phase 1 D-12 + Phase 5 D-11)
    const SYS_DENIED_RAX: i64 = -4;

    /// SyscallError::Ok 의 RAX 잠금
    const SYS_OK_RAX: i64 = 0;

    /// BusKind::Network = 6 Phase 2 BUS-02 lock
    const BUS_KIND_NETWORK: u8 = 6;
    /// BusKind::Software = 0 Phase 2 BUS-02 lock (AUDIT_READ_CAP bus_kind 도용)
    const BUS_KIND_SOFTWARE: u8 = 0;

    // 컴파일-타임 ABI 가드
    const _: () = assert!(SYS_DENIED_RAX == -4);
    const _: () = assert!(SYS_OK_RAX == 0);
    const _: () = assert!(BUS_KIND_NETWORK == 6);
    const _: () = assert!(BUS_KIND_SOFTWARE == 0);

    /// HsmCapability 16 옥텟 ABI 시뮬 iso-light-k0 src/hsm_registry.rs L103-114 mirror
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct HsmCapabilitySim {
        token: u64,
        slot: u8,
        _pad0: u8,
        rights: u16,
        _pad: u8,
        _pad1: [u8; 3],
    }

    const _: () = assert!(size_of::<HsmCapabilitySim>() == 16);

    /// EnrollEvent 12 옥텟 raw layout Phase 5 D-13 lock
    #[repr(C)]
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    struct EnrollEventLocal {
        seq: u32,
        slot_idx: u8,
        result: u8,
        bus_kind: u8,
        _pad: u8,
        pk_hash_prefix: [u8; 4],
    }

    const _: () = assert!(size_of::<EnrollEventLocal>() == 12);

    /// 결정론 cap 생성 helper
    fn cap_sim(token: u64) -> HsmCapabilitySim {
        HsmCapabilitySim {
            token,
            slot: 0xFF,
            _pad0: 0,
            rights: 0,
            _pad: 0,
            _pad1: [0; 3],
        }
    }

    /// 결정론 EnrollEvent helper
    fn enroll(seq: u32, slot: u8, result: u8, bus_kind: u8) -> EnrollEventLocal {
        EnrollEventLocal {
            seq,
            slot_idx: slot,
            result,
            bus_kind,
            _pad: 0,
            pk_hash_prefix: [0u8; 4],
        }
    }

    /// closed 빌드 handle_attach BusKind::Network 진입 → matchless `_` arm = Denied + audit
    ///
    /// # Decision: D-01
    /// closed 빌드 진입은 BusKind::Network arm 자체 cfg-out → matchless `_` arm 거부
    /// audit_enqueue(slot=0xFF, result=2, bus_kind=6, pk_hash_prefix=[0;4]) + Denied
    #[test]
    fn closed_build_attach_audit_emitted() {
        let _expected_event = enroll(0, 0xFF, 2, BUS_KIND_NETWORK);
        let _expected_rax: i64 = SYS_DENIED_RAX;
        todo!("Plan 06-04 GREEN fill-in — closed handle_attach Network audit_enqueue + Denied 회귀 (D-01)")
    }

    /// tls-external 빌드 NETWORK_ATTACH cap 미보유 → audit_enqueue + Denied (D-01)
    #[test]
    fn tls_external_cap_missing_denied() {
        let _caller_cap = cap_sim(0); // token=0 (미보유)
        let _expected_event = enroll(0, 0xFF, 2, BUS_KIND_NETWORK);
        let _expected_rax: i64 = SYS_DENIED_RAX;
        todo!("Plan 06-04 GREEN fill-in — tls-external NETWORK_ATTACH_CAP 미보유 시 Denied + audit 회귀 (D-01)")
    }

    /// 5 NetworkDenied 카테고리 모두 RAX = SYS_DENIED_RAX (-4) 단일 일치 — variant 노출 0
    ///
    /// 5 카테고리 (D-04):
    ///   1. closed-build handle_attach Network (slot=0xFF, bus_kind=6)
    ///   2. tls-external handle_attach cap-less (slot=0xFF, bus_kind=6)
    ///   3. tls-external sys_network_cap_take Taken 재호출 (slot=0xFE, bus_kind=6)
    ///   4. tls-external sys_audit_cap_take Taken 재호출 (slot=0xFD, bus_kind=0)
    ///   5. sys_hsm_status cap-fail (slot=0xFF, bus_kind=0)
    ///
    /// # Decision: D-04 + Pitfall 7
    /// 5 콜럐스 모두 단일 SYS_DENIED_RAX 누설 — lumen RAX 채널 variant 노출 0
    #[test]
    fn variant_collapse_single_rax_denied() {
        let denied_categories: [(u8, u8, u8); 5] = [
            (0xFF, 2, BUS_KIND_NETWORK),   // 1. closed handle_attach Network
            (0xFF, 2, BUS_KIND_NETWORK),   // 2. tls-external cap-less attach
            (0xFE, 2, BUS_KIND_NETWORK),   // 3. NETWORK_CAP_TAKE Taken
            (0xFD, 2, BUS_KIND_SOFTWARE),  // 4. AUDIT_READ take Taken
            (0xFF, 2, BUS_KIND_SOFTWARE),  // 5. sys_hsm_status cap-fail
        ];
        // Wave 0 sanity — 5 카테고리 모두 result=2 잠금
        for (idx, (_slot, result, _bus)) in denied_categories.iter().enumerate() {
            assert_eq!(*result, 2u8, "카테고리 {} result != 2 (D-04 위반)", idx);
        }
        todo!("Plan 06-02 + 06-04 GREEN fill-in — 5 카테고리 모두 RAX = -4 단일 누설 회귀 (Pitfall 7)")
    }

    /// 5 호출 지점이 각각 (slot_idx, result, bus_kind) 튜플로 식별 가능
    ///
    /// audit_enqueue 5 신규 호출 지점:
    ///   1. (0xFF, 2, 6) handle_attach Network 거부
    ///   2. (0xFE, 2, 6) NETWORK_CAP take-taken
    ///   3. (0xFE, 3, 6) NETWORK_CAP take-success
    ///   4. (0xFD, 2, 0) AUDIT_READ take-taken
    ///   5. (0xFD, 3, 0) AUDIT_READ take-success
    ///   추가 (0xFF, 2, 0) sys_hsm_status cap-fail (gap_status_serialize.rs cover)
    ///   추가 (0xFC, 4, 0) gap_self_check fail (gap_self_check.rs cover)
    ///
    /// # Decision: D-04
    /// EnrollEvent.bus_kind 옥텟이 NETWORK_ATTACH (=6) vs AUDIT_READ (=0 도용) 구분
    #[test]
    fn audit_enqueue_five_sites_distinct() {
        let five_sites: [(u8, u8, u8); 5] = [
            (0xFF, 2, BUS_KIND_NETWORK),    // 1. handle_attach Network 거부
            (0xFE, 2, BUS_KIND_NETWORK),    // 2. NETWORK_CAP take-taken
            (0xFE, 3, BUS_KIND_NETWORK),    // 3. NETWORK_CAP take-success
            (0xFD, 2, BUS_KIND_SOFTWARE),   // 4. AUDIT_READ take-taken
            (0xFD, 3, BUS_KIND_SOFTWARE),   // 5. AUDIT_READ take-success
        ];
        // Wave 0 sanity — 5 사이트가 (slot, result, bus) 튜플로 페어와이즈 식별 가능
        for i in 0..5 {
            for j in (i + 1)..5 {
                assert_ne!(
                    five_sites[i], five_sites[j],
                    "사이트 {} 와 {} 가 (slot, result, bus_kind) 동일",
                    i, j
                );
            }
        }
        todo!("Plan 06-02 + 06-04 GREEN fill-in — 5 audit_enqueue 호출 지점 튜플 식별 회귀 (D-04)")
    }
}
