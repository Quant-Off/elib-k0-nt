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

    //
    // 확장 케이스
    //
    // 누락 폭 좁히기 위한 보강. ct_sel32/ct_sel64 가 u8/u16/i32 등 wrapper 를
    // 통해 호출될 때도 CT 가 유지되는지, 그리고 128-bit / signed-128 / Choice
    // 비트연산 / CtSelOps::swap (CWE-316 잔재 소거 포함) 까지 회귀를 검증.

    #[test]
    fn dudect_select_u8() {
        let mut s = 0xa1a1_b2b2_c3c3_0010_u64;
        let mut stat = [Stats::default(), Stats::default()];
        for _ in 0..WARMUP {
            let (a, b) = (rnd_u8(&mut s), rnd_u8(&mut s));
            black_box(u8::select(&a, &b, Choice::from_u8(rnd_u8(&mut s) & 1)));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let a = black_box(rnd_u8(&mut s));
            let b = black_box(rnd_u8(&mut s));
            let c = Choice::from_u8(cl as u8);
            stat[cl].push(measure!(u8::select(&a, &b, c)));
        }
        assert!(report(
            "u8::select  (choice=0 vs choice=1)",
            &stat[0],
            &stat[1]
        ));
    }

    #[test]
    fn dudect_select_u16() {
        let mut s = 0xb2b2_c3c3_d4d4_0011_u64;
        let mut stat = [Stats::default(), Stats::default()];
        for _ in 0..WARMUP {
            let (a, b) = (rnd_u32(&mut s) as u16, rnd_u32(&mut s) as u16);
            black_box(u16::select(&a, &b, Choice::from_u8(rnd_u8(&mut s) & 1)));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let a = black_box(rnd_u32(&mut s) as u16);
            let b = black_box(rnd_u32(&mut s) as u16);
            let c = Choice::from_u8(cl as u8);
            stat[cl].push(measure!(u16::select(&a, &b, c)));
        }
        assert!(report(
            "u16::select  (choice=0 vs choice=1)",
            &stat[0],
            &stat[1]
        ));
    }

    #[test]
    fn dudect_select_u128() {
        let mut s = 0xc3c3_d4d4_e5e5_0012_u64;
        let mut stat = [Stats::default(), Stats::default()];
        for _ in 0..WARMUP {
            let a = ((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128;
            let b = ((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128;
            black_box(u128::select(&a, &b, Choice::from_u8(rnd_u8(&mut s) & 1)));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let a = black_box(((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128);
            let b = black_box(((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128);
            let c = Choice::from_u8(cl as u8);
            stat[cl].push(measure!(u128::select(&a, &b, c)));
        }
        assert!(report(
            "u128::select  (choice=0 vs choice=1)",
            &stat[0],
            &stat[1]
        ));
    }

    #[test]
    fn dudect_eq_u32() {
        let mut s = 0xd4d4_e5e5_f6f6_0013_u64;
        let mut stat = [Stats::default(), Stats::default()];
        for _ in 0..WARMUP {
            let a = rnd_u32(&mut s);
            black_box(CtEqOps::eq(&a, &a));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let a = black_box(rnd_u32(&mut s));
            let b = if cl == 0 { a } else { a ^ 1 };
            stat[cl].push(measure!(CtEqOps::eq(&a, &b)));
        }
        assert!(report(
            "CtEqOps::eq<u32>  (a==a vs a!=a^1)",
            &stat[0],
            &stat[1]
        ));
    }

    #[test]
    fn dudect_eq_u128() {
        let mut s = 0xe5e5_f6f6_0707_0014_u64;
        let mut stat = [Stats::default(), Stats::default()];
        for _ in 0..WARMUP {
            let a = ((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128;
            black_box(CtEqOps::eq(&a, &a));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let a = black_box(((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128);
            let b = if cl == 0 { a } else { a ^ 1 };
            stat[cl].push(measure!(CtEqOps::eq(&a, &b)));
        }
        assert!(report(
            "CtEqOps::eq<u128>  (a==a vs a!=a^1)",
            &stat[0],
            &stat[1]
        ));
    }

    //
    // i128 부호 있는 gt — sign-bit decomposition 경로 (ct_gt_i128) 회귀 가드.
    //
    //   Class 0: a >= 0, b <  0  →  a > b (signed)
    //   Class 1: a <  0, b >= 0  →  a < b (signed)
    #[test]
    fn dudect_gt_i128() {
        let mut s = 0xf6f6_0707_1818_0015_u64;
        let mut stat = [Stats::default(), Stats::default()];
        const SIGN128: u128 = 1u128 << 127;
        for _ in 0..WARMUP {
            let raw = ((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128;
            let (a, b) = ((raw & !SIGN128) as i128, (raw | SIGN128) as i128);
            black_box(CtGreeter::gt(&a, &b));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let raw = black_box(((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128);
            let (a, b) = if cl == 0 {
                ((raw & !SIGN128) as i128, (raw | SIGN128) as i128)
            } else {
                ((raw | SIGN128) as i128, (raw & !SIGN128) as i128)
            };
            stat[cl].push(measure!(CtGreeter::gt(&a, &b)));
        }
        assert!(report(
            "CtGreeter::gt<i128>  (a>b vs a<b)",
            &stat[0],
            &stat[1]
        ));
    }

    //
    // CtSelOps::swap — choice=0 (no-op) vs choice=1 (실제 교환).
    //
    // 두 경로의 timing 차이가 있다면 (예: branch on choice, 또는 잔재 영점화의
    // 길이가 달라짐) |t| 가 임계치를 초과. 추가로 CWE-316 회귀 가드 역할도
    // 동시에 수행 — volatile zero loop 가 선형적으로 size_of::<Self>() 만큼
    // 실행되므로 항상 동일한 cycle 패턴이어야 함.
    #[test]
    fn dudect_swap_u64() {
        let mut s = 0x0707_1818_2929_0016_u64;
        let mut stat = [Stats::default(), Stats::default()];
        for _ in 0..WARMUP {
            let mut a = rnd_u64(&mut s);
            let mut b = rnd_u64(&mut s);
            u64::swap(&mut a, &mut b, Choice::from_u8(rnd_u8(&mut s) & 1));
            black_box(&mut a);
            black_box(&mut b);
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let mut a = black_box(rnd_u64(&mut s));
            let mut b = black_box(rnd_u64(&mut s));
            let c = Choice::from_u8(cl as u8);
            stat[cl].push(measure!({
                u64::swap(&mut a, &mut b, c);
                (a, b)
            }));
        }
        assert!(report(
            "CtSelOps::swap<u64>  (choice=0 vs choice=1)",
            &stat[0],
            &stat[1]
        ));
    }

    #[test]
    fn dudect_swap_u128() {
        let mut s = 0x1818_2929_3a3a_0017_u64;
        let mut stat = [Stats::default(), Stats::default()];
        for _ in 0..WARMUP {
            let mut a = ((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128;
            let mut b = ((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128;
            u128::swap(&mut a, &mut b, Choice::from_u8(rnd_u8(&mut s) & 1));
            black_box(&mut a);
            black_box(&mut b);
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let mut a = black_box(((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128);
            let mut b = black_box(((rnd_u64(&mut s) as u128) << 64) | rnd_u64(&mut s) as u128);
            let c = Choice::from_u8(cl as u8);
            stat[cl].push(measure!({
                u128::swap(&mut a, &mut b, c);
                (a, b)
            }));
        }
        assert!(report(
            "CtSelOps::swap<u128>  (choice=0 vs choice=1)",
            &stat[0],
            &stat[1]
        ));
    }

    //
    // Choice 비트연산 — 모두 단일 ALU op. 그러나 컴파일러가 input 패턴별로
    // 다른 경로를 만들지 않는지 회귀 가드.
    #[test]
    fn dudect_choice_not() {
        let mut s = 0x2929_3a3a_4b4b_0018_u64;
        let mut stat = [Stats::default(), Stats::default()];
        for _ in 0..WARMUP {
            let c = Choice::from_u8(rnd_u8(&mut s) & 1);
            black_box(!c);
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            let c = Choice::from_u8(cl as u8);
            stat[cl].push(measure!(!black_box(c)));
        }
        assert!(report("Choice::not  (c=0 vs c=1)", &stat[0], &stat[1]));
    }

    #[test]
    fn dudect_choice_bitops() {
        let mut s = 0x3a3a_4b4b_5c5c_0019_u64;
        let mut stat = [Stats::default(), Stats::default()];
        for _ in 0..WARMUP {
            let x = Choice::from_u8(rnd_u8(&mut s) & 1);
            let y = Choice::from_u8(rnd_u8(&mut s) & 1);
            black_box((x & y) | (x ^ y));
        }
        for i in 0..MEASUREMENTS {
            let cl = i & 1;
            // 두 클래스 모두 동일 산술량을 수행. 입력만 다름.
            let x = Choice::from_u8(((i >> 1) & 1) as u8);
            let y = Choice::from_u8(cl as u8);
            stat[cl].push(measure!({
                let x = black_box(x);
                let y = black_box(y);
                (x & y) | (x ^ y)
            }));
        }
        assert!(report("Choice::&|^  (mixed inputs)", &stat[0], &stat[1]));
    }
}
