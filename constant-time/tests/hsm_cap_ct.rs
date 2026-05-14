#[cfg(test)]
mod tests {
    use constant_time::{Choice, CtEqOps};
    use std::hint::black_box;

    // Mock HsmCapability — mirrors iso-light-k0::hsm_registry::HsmCapability layout
    // (CONTEXT D-02 — 최소형 12바이트). 본 sibling 테스트는 커널 크레이트에 의존하지 않으므로
    // 타입을 인라인 복제한다(RESEARCH §7 Approach C, line 805).
    #[derive(Clone, Copy, PartialEq, Eq)]
    #[repr(C)]
    struct MockHsmCapability {
        token: u64,
        slot: u8,
        rights: u16,
        _pad: u8,
    }

    // 컴파일-타임 ABI 가드 (2-축):
    //
    // 1) wire-format 논리 크기 = 12 옥텟. CONTEXT D-02 가 "최소형 12바이트" 로 선언한
    //    것은 *논리 필드 합* (token:8 + slot:1 + rights:2 + _pad:1 = 12) 이며, 향후
    //    syscall ABI 인자 검증 (`user_cap_size == 12`) 의 진실 원천.
    const WIRE_LOGICAL_SIZE: usize = 8 /*token*/ + 1 /*slot*/ + 2 /*rights*/ + 1 /*_pad*/;
    const _: () = assert!(WIRE_LOGICAL_SIZE == 12);
    //
    // 2) 메모리 표현 = 16바이트. `#[repr(C)]` + u64 정렬 8 → trailing pad 4 바이트.
    //    Plan 01-02 SUMMARY (STATE.md decision) 가 잠근 ABI 진실. 본 가드는 mock 의
    //    메모리 레이아웃이 커널측 `HsmCapability` 와 정렬·크기 모두 일치함을 강제.
    const _: () = assert!(core::mem::size_of::<MockHsmCapability>() == 16);
    const _: () = assert!(core::mem::align_of::<MockHsmCapability>() == 8);

    // is_valid_for 의 3-predicate AND를 인라인 복제. 분기 없는 CT-AND 그대로 — Pitfall 1 회피.
    #[inline(never)]
    fn check(token: u64, slot_a: u8, slot_b: u8, rights: u16, required: u16) -> bool {
        let t: Choice = CtEqOps::ne(&token, &0u64);
        let s: Choice = CtEqOps::eq(&slot_a, &slot_b);
        let masked: u16 = rights & required;
        let r: Choice = CtEqOps::eq(&masked, &required);
        (t & s & r).unwrap_u8() == 1
    }

    #[test]
    fn accepts_valid_capability() {
        assert!(check(0x1234_5678, 3, 3, 0x07, 0x05));
    }

    #[test]
    fn rejects_zero_token() {
        assert!(!check(0, 3, 3, 0x07, 0x05));
    }

    #[test]
    fn rejects_wrong_slot() {
        assert!(!check(0x1234, 3, 4, 0x07, 0x05));
    }

    #[test]
    fn rejects_missing_rights() {
        assert!(!check(0x1234, 3, 3, 0x01, 0x05));
    }

    //
    // CPU cycle counter (mirrors dudect.rs:38-80 verbatim).
    //
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

    // DudeCT parameters (mirror dudect.rs:151-156 verbatim — fidelity preserved).
    const WARMUP: usize = 50_000;
    const MEASUREMENTS: usize = 1_000_000;
    const T_THRESHOLD: f64 = 4.5;

    fn report(label: &str, s0: &Stats, s1: &Stats) -> bool {
        let t = welch_t(s0, s1).abs();
        let pass = t < T_THRESHOLD;
        println!(
            "  Result {:<50}  |t| = {:>8.3}   (n0={}, n1={})   {}",
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

    // CT timing harness for the 3-predicate AND check.
    //
    //   Class 0 — valid capability (accept branch).
    //   Class 1 — invalid token (reject branch, single-predicate failure).
    //
    // 3-predicate AND이 정상 동작하면 두 클래스의 측정 분포 평균이 통계적으로 구분 불가능해야 한다.
    // |t| < 4.5 (~6σ) → PASS.
    //
    // black_box 입출력 모두 적용 (Pitfall 4 회피, DCE 차단).
    #[test]
    #[ignore = "long-running CT bench; run with cargo test --release -- --ignored hsm_cap_ct"]
    fn is_valid_for_ct_timing() {
        let mut s = 0xa1b2_c3d4_e5f6_0007_u64;
        let mut stat = [Stats::default(), Stats::default()];

        // 캐시·분기 예측기 워밍업 — class 균등 분포로 호출.
        for _ in 0..WARMUP {
            let v = xsf64(&mut s);
            let cl = (v & 1) as usize;
            let token = if cl == 0 { 0x1234_5678 } else { 0u64 };
            black_box(check(
                black_box(token),
                black_box(3),
                black_box(3),
                black_box(0x07),
                black_box(0x05),
            ));
        }

        // 본 측정 루프 — class 0(accept) vs class 1(reject zero-token) 인터리브.
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let token: u64 = if cl == 0 { 0x1234_5678_9abc_def0 } else { 0u64 };
            let slot_a = black_box(3u8);
            let slot_b = black_box(3u8);
            let rights = black_box(0x07u16);
            let required = black_box(0x05u16);
            stat[cl].push(measure!(check(
                black_box(token),
                slot_a,
                slot_b,
                rights,
                required
            )));
        }

        assert!(report(
            "HsmCapability::check  (accept vs reject zero-token)",
            &stat[0],
            &stat[1]
        ));
    }
}
