//! DudeCT (Leakage Assessment) Tests for Constant-Time Primitives
//!
//! Reference: "Dude, is my code constant time?" (Reparaz, Balasch, Verbauwhede; 2017)
//!            https://eprint.iacr.org/2016/1123
//!
//! # Methodology
//! 다음 두 가지 유형의 입력이 준비됩니다.
//! - Class 0 — one semantic variant of the operation (e.g., "inputs are equal")
//! - Class 1 — the complementary variant (e.g., "inputs are unequal")
//!
//! 각 클래스별로 대상 함수를 둘러싼 CPU 사이클 카운트는 `MEASUREMENTS` 반복에 걸쳐 기록됩니다.
//! 웰포드(Welford)의 온라인 알고리즘은 O(1) 공간에서 평균 및 분산을 유지합니다.
//!
//! Welch's t-test는 두 타이밍 모집단이 서로 다른 평균을 가진 분포에서 추출되었는지 확인합니다.
//! 만약 `|t| < T_THRESHOLD (4.5)` 인 경우, 통계적으로 유의미한 타이밍 누출은 감지되지
//! 않았음을 의미합니다.
//!
//! `constant-time/` 디렉토리에서 다음 명령을 실행하세요.
//! ```bash
//!   $ cargo test -p constant-time --test dudect --release -- --nocapture 2>&1 | grep "Result" > constant-time/dudect.txt
//! ```

#[cfg(test)]
mod tests {
    use constant_time::{Choice, CtEqOps, CtGreeter, CtLess, CtSelOps};
    use std::hint::black_box;

    //
    // CPU cycle counter
    //
    // x86_64: `lfence; rdtsc` pairs provide a consistent serialisation point
    //          that prevents out-of-order instruction reordering across the
    //          measured boundary without requiring the heavier `cpuid` fence.
    //
    // Other:   Falls back to std::time::Instant (lower resolution, acceptable
    //          for a host-side leakage assessment harness).

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
        // aarch64: Use CNTVCT_EL0 (virtual count register) for high-precision timing
        let count: u64;
        unsafe {
            core::arch::asm!(
                "isb",           // Instruction synchronization barrier
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
        // Use Instant for monotonic, high-resolution timing
        // This is more reliable than SystemTime for measuring short durations
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let start = START.get_or_init(Instant::now);
        start.elapsed().as_nanos() as u64
    }

    //
    // Xorshift-64 PRNG
    //
    // Deterministic, non-cryptographic fast PRNG used to generate varied inputs.
    // Each test uses a distinct seed so test results are independent.

    fn xsf64(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }
    fn rnd_u8(s: &mut u64) -> u8 {
        xsf64(s) as u8
    }
    fn rnd_u32(s: &mut u64) -> u32 {
        xsf64(s) as u32
    }
    fn rnd_u64(s: &mut u64) -> u64 {
        xsf64(s)
    }
    fn rnd_i32(s: &mut u64) -> i32 {
        xsf64(s) as i32
    }

    //
    // Welford online statistics
    //
    // Computes running mean and M₂ (sum of squared deviations) in a single pass
    // without storing individual samples.

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
            self.m2 += d1 * (x - self.mean); // Welford update
        }
        fn variance(&self) -> f64 {
            if self.n < 2 {
                f64::INFINITY
            } else {
                self.m2 / (self.n - 1) as f64
            }
        }
        // Standard error of the mean.
        fn se(&self) -> f64 {
            (self.variance() / self.n as f64).sqrt()
        }
    }

    // Welch's t-test
    fn welch_t(s0: &Stats, s1: &Stats) -> f64 {
        let se = (s0.se().powi(2) + s1.se().powi(2)).sqrt();
        if se == 0.0 || se.is_nan() {
            return 0.0;
        }
        (s0.mean - s1.mean) / se
    }

    // DudeCT parameters
    /// Iterations discarded to warm instruction caches and branch predictors.
    const WARMUP: usize = 50_000;
    /// Timing samples collected per test (split evenly: half per class).
    /// Increased from 300k to 1M for better detection of subtle timing leaks.
    const MEASUREMENTS: usize = 1_000_000;
    /// Standard dudect threshold.  |t| ≥ 4.5 → timing leak at ~6σ confidence.
    const T_THRESHOLD: f64 = 4.5;

    fn report(label: &str, s0: &Stats, s1: &Stats) -> bool {
        let t = welch_t(s0, s1).abs();
        let pass = t < T_THRESHOLD;
        println!(
            "  Result {:<50}  |t| = {:>8.3}   (n₀={}, n₁={})   {}",
            label,
            t,
            s0.n,
            s1.n,
            if pass {
                "PASS"
            } else {
                "FAIL ← timing leak detected!"
            },
        );
        pass
    }

    //
    // Test helpers
    //
    // Measure `f(v)` once, return elapsed ticks.
    // The argument and return value go through black_box to prevent DCE/hoisting.
    macro_rules! measure {
        ($f:expr) => {{
            let t0 = ticks();
            let _ = black_box($f);
            let t1 = ticks();
            t1.saturating_sub(t0) as f64
        }};
    }

    //
    // DudeCT tests
    //
    // Choice::from_u8 — CT normalisation of any u8 value to {0, 1}.
    //
    //   Class 0: random u8 input spanning the full 0..=255 range.
    //   Class 1: fixed constant 0 (always maps to Choice(0)).
    //
    //   If the normalisation branches on the value (e.g., `if v != 0`),
    //   class 1 will be systematically faster (always takes the zero branch),
    //   and |t| will exceed the threshold.
    #[test]
    fn dudect_choice_from_u8() {
        let mut s = 0xdead_beef_cafe_0001_u64;
        let mut stat = [Stats::default(), Stats::default()];

        for _ in 0..WARMUP {
            black_box(Choice::from_u8(black_box(rnd_u8(&mut s))));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let v = if cl == 0 { rnd_u8(&mut s) } else { 0u8 };
            stat[cl].push(measure!(Choice::from_u8(black_box(v))));
        }
        assert!(report(
            "Choice::from_u8  (random vs fixed=0)",
            &stat[0],
            &stat[1]
        ));
    }

    //
    // u32::select — conditional select.
    //
    //   Class 0: choice = 0  → select returns the *first* operand.
    //   Class 1: choice = 1  → select returns the *second* operand.
    //
    //   Operands are independently randomised each iteration so that no
    //   information about which path was taken leaks through the value itself.
    #[test]
    fn dudect_select_u32() {
        let mut s = 0x1234_5678_abcd_0002_u64;
        let mut stat = [Stats::default(), Stats::default()];

        for _ in 0..WARMUP {
            let (a, b) = (rnd_u32(&mut s), rnd_u32(&mut s));
            black_box(u32::select(&a, &b, Choice::from_u8(rnd_u8(&mut s) & 1)));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let a = black_box(rnd_u32(&mut s));
            let b = black_box(rnd_u32(&mut s));
            let c = Choice::from_u8(cl as u8);
            stat[cl].push(measure!(u32::select(&a, &b, c)));
        }
        assert!(report(
            "u32::select  (choice=0 vs choice=1)",
            &stat[0],
            &stat[1]
        ));
    }

    // u64::select — same as above but for 64-bit values.
    #[test]
    fn dudect_select_u64() {
        let mut s = 0xfeed_face_dead_0003_u64;
        let mut stat = [Stats::default(), Stats::default()];

        for _ in 0..WARMUP {
            black_box(u64::select(
                &rnd_u64(&mut s),
                &rnd_u64(&mut s),
                Choice::from_u8(rnd_u8(&mut s) & 1),
            ));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let a = black_box(rnd_u64(&mut s));
            let b = black_box(rnd_u64(&mut s));
            let c = Choice::from_u8(cl as u8);
            stat[cl].push(measure!(u64::select(&a, &b, c)));
        }
        assert!(report(
            "u64::select  (choice=0 vs choice=1)",
            &stat[0],
            &stat[1]
        ));
    }

    //
    // CtEqOps::eq<i32> — signed 32-bit equality.
    //
    //   Class 0: a == b  (identical inputs; result is Choice(1)).
    //   Class 1: a != b  (b = a ^ 1; guaranteed different; result is Choice(0)).
    #[test]
    fn dudect_eq_i32() {
        let mut s = 0xaaaa_bbbb_0000_0004_u64;
        let mut stat = [Stats::default(), Stats::default()];

        for _ in 0..WARMUP {
            let a = rnd_i32(&mut s);
            black_box(CtEqOps::eq(&a, &a));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let a = black_box(rnd_i32(&mut s));
            let b = if cl == 0 { a } else { a ^ 1 };
            stat[cl].push(measure!(CtEqOps::eq(&a, &b)));
        }
        assert!(report(
            "CtEqOps::eq<i32>  (a==a vs a!=a^1)",
            &stat[0],
            &stat[1]
        ));
    }

    // CtEqOps::eq<u64> — 64-bit equality.
    #[test]
    fn dudect_eq_u64() {
        let mut s = 0x1111_2222_3333_0005_u64;
        let mut stat = [Stats::default(), Stats::default()];

        for _ in 0..WARMUP {
            let a = rnd_u64(&mut s);
            black_box(CtEqOps::eq(&a, &a));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let a = black_box(rnd_u64(&mut s));
            let b = if cl == 0 { a } else { a ^ 1 };
            stat[cl].push(measure!(CtEqOps::eq(&a, &b)));
        }
        assert!(report(
            "CtEqOps::eq<u64>  (a==a vs a!=a^1)",
            &stat[0],
            &stat[1]
        ));
    }

    //
    // CtGreeter::gt<u64> — unsigned 64-bit greater-than.
    //
    //   Class 0: a > b  — achieved by setting MSB of `a` and clearing it in `b`.
    //   Class 1: a < b  — roles reversed.
    //
    //   The shared low 63 bits are randomised so that operand distributions are
    //   similar across classes (avoiding Hamming-weight correlation artifacts).
    #[test]
    fn dudect_gt_u64() {
        let mut s = 0x9999_8888_7777_0006_u64;
        let mut stat = [Stats::default(), Stats::default()];
        const MSB: u64 = 1u64 << 63;

        for _ in 0..WARMUP {
            let raw = rnd_u64(&mut s);
            let (a, b) = (raw | MSB, raw & !MSB);
            black_box(CtGreeter::gt(&a, &b));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let raw = black_box(rnd_u64(&mut s));
            let (a, b) = if cl == 0 {
                (raw | MSB, raw & !MSB) // a > b (unsigned)
            } else {
                (raw & !MSB, raw | MSB) // a < b
            };
            stat[cl].push(measure!(CtGreeter::gt(&a, &b)));
        }
        assert!(report(
            "CtGreeter::gt<u64>  (a>b vs a<b)",
            &stat[0],
            &stat[1]
        ));
    }

    //
    // CtGreeter::gt<i64> — signed 64-bit greater-than.
    //
    //   Class 0: a > b  — a is non-negative (MSB clear),  b is negative (MSB set).
    //   Class 1: a < b  — roles reversed.
    //
    //   In two's complement, MSB clear ↔ non-negative; MSB set ↔ negative.
    //   Since non-negative > negative for signed comparison, ordering is guaranteed.
    #[test]
    fn dudect_gt_i64() {
        let mut s = 0x5555_4444_3333_0007_u64;
        let mut stat = [Stats::default(), Stats::default()];
        const SIGN: u64 = 1u64 << 63;

        for _ in 0..WARMUP {
            let raw = rnd_u64(&mut s);
            let (a, b) = ((raw & !SIGN) as i64, (raw | SIGN) as i64);
            black_box(CtGreeter::gt(&a, &b));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let raw = black_box(rnd_u64(&mut s));
            let (a, b) = if cl == 0 {
                ((raw & !SIGN) as i64, (raw | SIGN) as i64) // a ≥ 0 > b (signed)
            } else {
                ((raw | SIGN) as i64, (raw & !SIGN) as i64) // a < 0 ≤ b (signed)
            };
            stat[cl].push(measure!(CtGreeter::gt(&a, &b)));
        }
        assert!(report(
            "CtGreeter::gt<i64>  (a>b vs a<b)",
            &stat[0],
            &stat[1]
        ));
    }

    //
    // CtGreeter::gt<u128> — 128-bit unsigned greater-than.
    //
    //   Class 0: a > b  — high 64-bit word of `a` is all-ones; `b` is all-zeros.
    //   Class 1: a < b  — roles reversed.
    //
    //   The low 64-bit word is randomised in both classes.
    #[test]
    fn dudect_gt_u128() {
        let mut s = 0xcafe_babe_f00d_0008_u64;
        let mut stat = [Stats::default(), Stats::default()];

        for _ in 0..WARMUP {
            let lo = rnd_u64(&mut s) as u128;
            let (a, b) = ((u64::MAX as u128) << 64 | lo, lo);
            black_box(CtGreeter::gt(&a, &b));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let lo = black_box(rnd_u64(&mut s)) as u128;
            let (a, b) = if cl == 0 {
                ((u64::MAX as u128) << 64 | lo, lo) // a > b
            } else {
                (lo, (u64::MAX as u128) << 64 | lo) // a < b
            };
            stat[cl].push(measure!(CtGreeter::gt(&a, &b)));
        }
        assert!(report(
            "CtGreeter::gt<u128>  (a>b vs a<b)",
            &stat[0],
            &stat[1]
        ));
    }

    //
    // CtLess::lt<u32> — 32-bit unsigned less-than (derived from gt + eq).
    //
    //   Class 0: a < b.
    //   Class 1: a > b.
    #[test]
    fn dudect_lt_u32() {
        let mut s = 0x3333_2222_1111_0009_u64;
        let mut stat = [Stats::default(), Stats::default()];
        const MSB: u32 = 1u32 << 31;

        for _ in 0..WARMUP {
            let raw = rnd_u32(&mut s);
            black_box(CtLess::lt(&(raw & !MSB), &(raw | MSB)));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let raw = black_box(rnd_u32(&mut s));
            let (a, b) = if cl == 0 {
                (raw & !MSB, raw | MSB) // a < b
            } else {
                (raw | MSB, raw & !MSB) // a > b
            };
            stat[cl].push(measure!(CtLess::lt(&a, &b)));
        }
        assert!(report("CtLess::lt<u32>  (a<b vs a>b)", &stat[0], &stat[1]));
    }
}
