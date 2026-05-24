//! Phase 6 GAP-02 one-shot cap take FSM (Provisioned → Taken) + dual cap symmetry + CT cap compare 회귀 가드
//!
//! # 책임 경계
//! 본 파일은 iso-light-k0 의 `src/air_gap.rs::take_network_cap()` /
//! `take_audit_read_cap()` 의 NetCapState FSM 전이 (Provisioned → Taken)
//! 와 first-caller-wins 의미론을 host-side 에서 시뮬한다 Wave 0 은
//! COMPILE-only RED 스켈레톤 Plan 06-02 GREEN fill-in 직후 #[test] fn
//! 본문이 todo!() 에서 Pattern D 7-Phase 검증 본문으로 교체된다
//!
//! # 검증 대상
//!   - state == Provisioned 시 정상 통과 + 16 B copy + state → Taken + audit_enqueue(0xFE, 3, 6, [0;4])
//!   - state == Taken 재호출 시 Denied + audit_enqueue(0xFE, 2, 6, [0;4]) 1 회 (D-04)
//!   - AUDIT_READ_CAP 양방향 대칭 (slot=0xFD, bus_kind=0 BusKind::Software 도용 — D-06)
//!   - CtEqOps::eq(stored.token, caller.token) 가 bit-위치 독립 분기 (CT cap compare)
//!
//! # Decision: D-02
//! NETWORK_ATTACH_CAP one-shot mint + first-caller-wins
//!
//! # Decision: D-03
//! sys_network_cap_take 16 B 응답 + FSM Provisioned → Taken
//!
//! # Decision: D-04
//! EnrollEvent.result 의 2/3 코드 회귀 (5 콜럐스 + dual take)

#![allow(dead_code)]
#![allow(clippy::all)]

use constant_time::CtEqOps;

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    /// NETWORK_CAP_STATE / AUDIT_CAP_STATE 의 FSM Phase 6 D-03 lock
    #[repr(u8)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum NetCapState {
        Provisioned = 0,
        Taken = 1,
    }

    /// HsmCapability 16 옥텟 ABI 시뮬 iso-light-k0 src/hsm_registry.rs L103-114 mirror
    ///   - rights HsmRights(u16) = 2 B (PLAN.md interfaces L129 의 "4 B" 표기는 stale)
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

    // 컴파일-타임 ABI 가드
    const _: () = assert!(size_of::<HsmCapabilitySim>() == 16);
    const _: () = assert!(size_of::<EnrollEventLocal>() == 12);
    const _: () = assert!(size_of::<NetCapState>() == 1);

    /// 결정론 cap 생성 helper Phase 5 attest_collapse_ct.rs L20-30 mirror
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

    /// state == Provisioned 시 NETWORK_ATTACH_CAP take 정상 통과
    ///
    /// GREEN fill-in 후 Pattern D 7-Phase 순서 검증
    ///   (1) dual-range pointer (2) FSM read (3) staging (4) SMAP-1 write
    ///   (5) state Provisioned → Taken (6) audit_enqueue(0xFE, 3, 6, [0;4]) (7) zeroize
    #[test]
    fn network_cap_take_first_caller_wins() {
        let mut _state = NetCapState::Provisioned;
        let _stored = cap_sim(0xDEADBEEFCAFEBABE);
        let _expected_event = enroll(0, 0xFE, 3, 6);
        todo!(
            "Plan 06-02 GREEN fill-in — take_network_cap Provisioned→Taken + audit result=3 회귀 (D-03)"
        )
    }

    /// state == Taken 재호출 시 Denied + audit_enqueue(0xFE, 2, 6, [0;4]) 1 회 (D-04 콜럐스)
    #[test]
    fn network_cap_take_state_taken_denied() {
        let mut _state = NetCapState::Taken;
        let _stored = cap_sim(0xDEADBEEFCAFEBABE);
        let _expected_event = enroll(0, 0xFE, 2, 6);
        todo!(
            "Plan 06-02 GREEN fill-in — take_network_cap Taken 재호출 시 Denied + audit result=2 회귀 (D-04)"
        )
    }

    /// AUDIT_READ_CAP 대칭 take — slot=0xFD bus_kind=0 BusKind::Software 도용 (D-06)
    #[test]
    fn audit_read_cap_take_first_caller_wins() {
        let mut _state = NetCapState::Provisioned;
        let _stored = cap_sim(0x1234567890ABCDEF);
        // slot=0xFD AUDIT_READ_CAP 식별자 bus_kind=0 BusKind::Software 도용 (D-06)
        let _expected_event = enroll(0, 0xFD, 3, 0);
        todo!(
            "Plan 06-02 GREEN fill-in — take_audit_read_cap Provisioned→Taken + audit result=3 회귀 (D-06)"
        )
    }

    /// AUDIT_READ_CAP 대칭 take-taken — slot=0xFD result=2
    #[test]
    fn audit_read_cap_take_state_taken_denied() {
        let mut _state = NetCapState::Taken;
        let _stored = cap_sim(0x1234567890ABCDEF);
        let _expected_event = enroll(0, 0xFD, 2, 0);
        todo!(
            "Plan 06-02 GREEN fill-in — take_audit_read_cap Taken 재호출 시 Denied + audit result=2 회귀 (D-04 D-06)"
        )
    }

    /// CtEqOps::eq(stored.token, caller.token) 가 token-bit 위치 독립 분기 (CT cap compare)
    ///
    /// Phase 5 attest_collapse_ct.rs 의 CT-eq 회귀 패턴 mirror
    /// GREEN fill-in 시 CtEqOps::eq(...).unwrap_u8() 호출 후 timing-uniform 검증
    #[test]
    fn cap_token_ct_eq_symmetry() {
        let stored = cap_sim(0xDEADBEEFCAFEBABE);
        let same = cap_sim(0xDEADBEEFCAFEBABE);
        let differ_lsb = cap_sim(0xDEADBEEFCAFEBABF); // 1 bit LSB 차이
        let differ_msb = cap_sim(0x5EADBEEFCAFEBABE); // 1 bit MSB 차이

        // Wave 0 sanity — CtEqOps::eq 가 컴파일 시점 결합 가능한지 import 잠금
        let _e1 = CtEqOps::eq(&stored.token, &same.token);
        let _e2 = CtEqOps::eq(&stored.token, &differ_lsb.token);
        let _e3 = CtEqOps::eq(&stored.token, &differ_msb.token);

        todo!("Plan 06-02 GREEN fill-in — CtEqOps::eq token bit-position independent timing 회귀")
    }
}
