// Phase 3 Plan-03 Wave 0 — sys_hsm_relay byte_len CtLess::lt / CtEqOps::ne timing
// (CHAN-04)  Host dudect Welch t < 4.5
//
// 검증 대상
//   - handle_write / handle_relay 의 byte_len ∈ (0, CHAN_MAX] 범위 검사가 CT 평면
//   - `CtLess::lt(&len, &(CHAN_MAX+1))` & `CtEqOps::ne(&len, &0)` 두 invariant 의 bitand 결합
//   - len = CHAN_MAX - 1 (통과) 과 len = CHAN_MAX + 1 (overflow 거부) 사이 timing 일치

#[cfg(test)]
mod tests {
    use constant_time::{CtEqOps, CtLess};
    use std::hint::black_box;

    const CHAN_MAX: usize = 4096;

    // handle_write / handle_relay 의 step (1) CT 범위 검사 미러
    #[inline(never)]
    fn check_byte_len(byte_len: usize) -> bool {
        let lt_max: u8 = CtLess::lt(&byte_len, &(CHAN_MAX + 1)).unwrap_u8();
        let nonzero: u8 = CtEqOps::ne(&byte_len, &0usize).unwrap_u8();
        (lt_max & nonzero) == 1
    }

    // ─────── 정합성 회귀 ───────

    #[test]
    fn test_byte_len_bounds() {
        assert!(!check_byte_len(0), "0 은 reject");
        assert!(check_byte_len(1), "1 은 accept");
        assert!(check_byte_len(CHAN_MAX - 1), "CHAN_MAX-1 은 accept");
        assert!(check_byte_len(CHAN_MAX), "CHAN_MAX 은 accept (D-13 4 KiB 정확 등호 허용)");
        assert!(!check_byte_len(CHAN_MAX + 1), "CHAN_MAX+1 은 reject");
        assert!(!check_byte_len(usize::MAX), "usize::MAX 은 reject");
    }

    #[test]
    fn test_byte_len_typical() {
        for &n in &[1usize, 16, 64, 256, 1024, 4095, 4096] {
            assert!(check_byte_len(n), "expected accept for {}", n);
        }
        for &n in &[0usize, 4097, 8192, 65536] {
            assert!(!check_byte_len(n), "expected reject for {}", n);
        }
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

    // CT timing — accept (CHAN_MAX - 1) vs reject (CHAN_MAX + 1)
    //
    //   Class 0  byte_len = CHAN_MAX - 1  (accept 경로)
    //   Class 1  byte_len = CHAN_MAX + 1  (reject 경로, overflow)
    #[test]
    #[ignore = "long-running CT bench; run with cargo test --release -- --ignored chan_length"]
    fn dudect_byte_len_branch_balance() {
        let pass_val: usize = CHAN_MAX - 1;
        let fail_val: usize = CHAN_MAX + 1;

        let mut stat = [Stats::default(), Stats::default()];

        // 워밍업  class 균등 분포
        for i in 0..WARMUP {
            let cl = i & 1;
            let n = if cl == 0 { pass_val } else { fail_val };
            let _ = black_box(check_byte_len(black_box(n)));
        }

        // 본 측정 루프  class 0 / class 1 인터리브
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let n = if cl == 0 { pass_val } else { fail_val };
            stat[cl].push(measure!(check_byte_len(black_box(n))));
        }

        assert!(report(
            "check_byte_len  (CHAN_MAX-1 accept vs CHAN_MAX+1 reject)",
            &stat[0],
            &stat[1]
        ));
    }
}
