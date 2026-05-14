// Phase 3 Plan-03 Wave 0 — sys_hsm_relay dual-cap authenticate CT-AND timing balance
// (Pitfall 1 / D-18)  Host dudect Welch t < 4.5 gate
//
// 검증 대상
//   - handle_relay 의 두 authenticate 호출 결과를 결합할 때 `(src_ok as u8) & (dst_ok as u8)`
//     bitand 가 사용되어야 함 (short-circuit `&&` 금지)
//   - 본 sibling test 는 커널 크레이트에 의존하지 않고 동일한 CT-AND 패턴을 인라인 복제하여
//     "양쪽 valid" 와 "한 쪽 invalid" 두 분포의 timing 평균이 통계적으로 구분 불가능함을 검증

#[cfg(test)]
mod tests {
    use constant_time::{Choice, CtEqOps};
    use std::hint::black_box;

    // Mock HsmCapability  iso-light-k0::hsm_registry::HsmCapability 의 16-byte 레이아웃 미러
    #[derive(Clone, Copy)]
    #[repr(C)]
    struct MockCap {
        token: u64,
        slot: u8,
        _pad0: u8,
        rights: u16,
        _pad: u8,
        _pad1: [u8; 3],
    }
    const _: () = assert!(core::mem::size_of::<MockCap>() == 16);

    // 슬롯 측 진본 정보 (registry 의 slot.token / slot.state / slot.rights 미러)
    #[derive(Clone, Copy)]
    struct MockSlot {
        state_byte: u8, // 1 = Attached
        token: u64,
        rights: u16,
    }

    // authenticate 5-invariant CT-AND 인라인 복제
    //   token_nonzero & state_ok & token_eq & stored_rights_ok & cap_rights_ok
    #[inline(never)]
    fn authenticate_ct(cap: &MockCap, slot: &MockSlot, required: u16) -> bool {
        let token_nonzero: Choice = CtEqOps::ne(&cap.token, &0u64);
        let state_ok: Choice = CtEqOps::eq(&slot.state_byte, &1u8);
        let token_eq: Choice = CtEqOps::eq(&cap.token, &slot.token);
        let stored_masked: u16 = slot.rights & required;
        let stored_rights_ok: Choice = CtEqOps::eq(&stored_masked, &required);
        let cap_masked: u16 = cap.rights & required;
        let cap_rights_ok: Choice = CtEqOps::eq(&cap_masked, &required);
        (token_nonzero & state_ok & token_eq & stored_rights_ok & cap_rights_ok).unwrap_u8() == 1
    }

    // Dual-cap CT-AND simulation  Pitfall 1 회피 검증
    //   bitand `(a as u8) & (b as u8)` 가 사용되며 양쪽 authenticate 가 무조건 실행됨
    #[inline(never)]
    fn relay_authenticate(
        src_cap: &MockCap,
        src_slot: &MockSlot,
        dst_cap: &MockCap,
        dst_slot: &MockSlot,
        src_req: u16,
        dst_req: u16,
    ) -> bool {
        let src_ok = authenticate_ct(src_cap, src_slot, src_req);
        let dst_ok = authenticate_ct(dst_cap, dst_slot, dst_req);
        // Pitfall 1  bitand 사용  short-circuit (&&) 금지
        ((src_ok as u8) & (dst_ok as u8)) == 1
    }

    // RELAY_SRC = 1<<3, RELAY_DST = 1<<4 (Phase 1 D-03 비트 레이아웃)
    const RELAY_SRC: u16 = 1 << 3;
    const RELAY_DST: u16 = 1 << 4;
    const FULL_RIGHTS: u16 = (1 << 0) | (1 << 1) | (1 << 2) | RELAY_SRC | RELAY_DST;

    fn valid_pair() -> (MockCap, MockSlot) {
        let cap = MockCap {
            token: 0xDEAD_BEEF_CAFE_BABE,
            slot: 3,
            _pad0: 0,
            rights: FULL_RIGHTS,
            _pad: 0,
            _pad1: [0; 3],
        };
        let slot = MockSlot {
            state_byte: 1,
            token: 0xDEAD_BEEF_CAFE_BABE,
            rights: FULL_RIGHTS,
        };
        (cap, slot)
    }

    fn invalid_pair() -> (MockCap, MockSlot) {
        // token mismatch (single-invariant 실패)
        let cap = MockCap {
            token: 0x1111_2222_3333_4444,
            slot: 3,
            _pad0: 0,
            rights: FULL_RIGHTS,
            _pad: 0,
            _pad1: [0; 3],
        };
        let slot = MockSlot {
            state_byte: 1,
            token: 0x9999_8888_7777_6666,
            rights: FULL_RIGHTS,
        };
        (cap, slot)
    }

    // ─────── 정합성 회귀 ───────

    #[test]
    fn test_both_valid_accepts() {
        let (src_cap, src_slot) = valid_pair();
        let (dst_cap, dst_slot) = valid_pair();
        assert!(relay_authenticate(
            &src_cap, &src_slot, &dst_cap, &dst_slot, RELAY_SRC, RELAY_DST
        ));
    }

    #[test]
    fn test_src_invalid_denies() {
        let (src_cap, src_slot) = invalid_pair();
        let (dst_cap, dst_slot) = valid_pair();
        assert!(!relay_authenticate(
            &src_cap, &src_slot, &dst_cap, &dst_slot, RELAY_SRC, RELAY_DST
        ));
    }

    #[test]
    fn test_dst_invalid_denies() {
        let (src_cap, src_slot) = valid_pair();
        let (dst_cap, dst_slot) = invalid_pair();
        assert!(!relay_authenticate(
            &src_cap, &src_slot, &dst_cap, &dst_slot, RELAY_SRC, RELAY_DST
        ));
    }

    #[test]
    fn test_both_invalid_denies() {
        let (src_cap, src_slot) = invalid_pair();
        let (dst_cap, dst_slot) = invalid_pair();
        assert!(!relay_authenticate(
            &src_cap, &src_slot, &dst_cap, &dst_slot, RELAY_SRC, RELAY_DST
        ));
    }

    #[test]
    fn test_either_cap_invalid_denies() {
        let (vsrc, vsslot) = valid_pair();
        let (vdst, vdslot) = valid_pair();
        let (isrc, isslot) = invalid_pair();
        let (idst, idslot) = invalid_pair();
        // src 만 invalid
        assert!(!relay_authenticate(
            &isrc, &isslot, &vdst, &vdslot, RELAY_SRC, RELAY_DST
        ));
        // dst 만 invalid
        assert!(!relay_authenticate(
            &vsrc, &vsslot, &idst, &idslot, RELAY_SRC, RELAY_DST
        ));
        // 둘 다 invalid
        assert!(!relay_authenticate(
            &isrc, &isslot, &idst, &idslot, RELAY_SRC, RELAY_DST
        ));
    }

    // ─────── dudect timing harness ───────

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn ticks() -> u64 {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!(
                "lfence",
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nostack, nomem),
            );
        }
        ((hi as u64) << 32) | lo as u64
    }

    #[cfg(all(not(target_arch = "x86_64"), target_arch = "aarch64"))]
    #[inline(always)]
    fn ticks() -> u64 {
        let count: u64;
        unsafe {
            core::arch::asm!(
                "isb",
                "mrs {}, cntvct_el0",
                out(reg) count,
                options(nostack, nomem),
            );
        }
        count
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    #[inline(always)]
    fn ticks() -> u64 {
        use std::time::Instant;
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let start = START.get_or_init(Instant::now);
        start.elapsed().as_nanos() as u64
    }

    fn xsf64(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    #[derive(Default)]
    struct Stats {
        n: u64,
        mean: f64,
        m2: f64,
    }
    impl Stats {
        fn push(&mut self, x: f64) {
            self.n += 1;
            let d1 = x - self.mean;
            self.mean += d1 / self.n as f64;
            self.m2 += d1 * (x - self.mean);
        }
        fn variance(&self) -> f64 {
            if self.n < 2 {
                f64::INFINITY
            } else {
                self.m2 / (self.n - 1) as f64
            }
        }
        fn se(&self) -> f64 {
            (self.variance() / self.n as f64).sqrt()
        }
    }

    fn welch_t(s0: &Stats, s1: &Stats) -> f64 {
        let se = (s0.se().powi(2) + s1.se().powi(2)).sqrt();
        if se == 0.0 || se.is_nan() {
            return 0.0;
        }
        (s0.mean - s1.mean) / se
    }

    // DudeCT parameters (mirror hsm_cap_ct.rs:148-150 verbatim)
    const WARMUP: usize = 50_000;
    const MEASUREMENTS: usize = 1_000_000;
    const T_THRESHOLD: f64 = 4.5;

    fn report(label: &str, s0: &Stats, s1: &Stats) -> bool {
        let t = welch_t(s0, s1).abs();
        let pass = t < T_THRESHOLD;
        println!(
            "  Result {:<60}  |t| = {:>8.3}   (n0={}, n1={})   {}",
            label,
            t,
            s0.n,
            s1.n,
            if pass {
                "PASS"
            } else {
                "FAIL <- timing leak detected!"
            },
        );
        pass
    }

    macro_rules! measure {
        ($f:expr) => {{
            let t0 = ticks();
            let _ = black_box($f);
            let t1 = ticks();
            t1.saturating_sub(t0) as f64
        }};
    }

    // CT timing — 양쪽 valid (accept) vs 한 쪽이라도 invalid (reject) 간 |t| < 4.5 검증
    //
    //   Class 0  src valid + dst valid  (accept 경로  CT-AND 통과)
    //   Class 1  src invalid + dst valid (reject 경로  CT-AND 실패  하지만 양쪽 authenticate 모두 실행)
    //
    // Pitfall 1 회피 (short-circuit 금지) 가 지켜졌다면 두 분포의 timing 평균이 통계적으로 구분 불가능
    #[test]
    #[ignore = "long-running CT bench; run with cargo test --release -- --ignored chan_dual_auth"]
    fn dudect_authenticate_branch_balance() {
        let (vsrc, vsslot) = valid_pair();
        let (vdst, vdslot) = valid_pair();
        let (isrc, isslot) = invalid_pair();

        let mut s = 0xa1b2_c3d4_e5f6_0301_u64;
        let mut stat = [Stats::default(), Stats::default()];

        // 워밍업  class 균등 분포
        for _ in 0..WARMUP {
            let v = xsf64(&mut s);
            let cl = (v & 1) as usize;
            if cl == 0 {
                let _ = black_box(relay_authenticate(
                    black_box(&vsrc),
                    black_box(&vsslot),
                    black_box(&vdst),
                    black_box(&vdslot),
                    black_box(RELAY_SRC),
                    black_box(RELAY_DST),
                ));
            } else {
                let _ = black_box(relay_authenticate(
                    black_box(&isrc),
                    black_box(&isslot),
                    black_box(&vdst),
                    black_box(&vdslot),
                    black_box(RELAY_SRC),
                    black_box(RELAY_DST),
                ));
            }
        }

        // 본 측정 루프  class 0 / class 1 인터리브
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            if cl == 0 {
                stat[cl].push(measure!(relay_authenticate(
                    black_box(&vsrc),
                    black_box(&vsslot),
                    black_box(&vdst),
                    black_box(&vdslot),
                    black_box(RELAY_SRC),
                    black_box(RELAY_DST),
                )));
            } else {
                stat[cl].push(measure!(relay_authenticate(
                    black_box(&isrc),
                    black_box(&isslot),
                    black_box(&vdst),
                    black_box(&vdslot),
                    black_box(RELAY_SRC),
                    black_box(RELAY_DST),
                )));
            }
        }

        assert!(report(
            "relay_authenticate  (both-valid vs src-invalid)",
            &stat[0],
            &stat[1]
        ));
    }
}
