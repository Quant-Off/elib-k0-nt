//! 분기 없는 상수-시간 정수 연산 기능이 구현된 모듈입니다.
//!
//! 비밀 값에 의존하는 분기나 데이터 의존 메모리 접근 없이 값 선택과 동등
//! 비교, 대소 비교를 수행하는 `Choice` 타입과 `CtSelOps`, `CtEqOps`,
//! `CtGtOps`, `CtLess` 트레이트를 제공합니다. 저수준 상수-시간 프리미티브는
//! `internal` 모듈에 있으며 x86_64와 aarch64에서는 인-라인 어셈블리로, 그 외
//! 아키텍처에서는 `black_box` 기반 best-effort fallback으로 동작합니다.
//!
//! # Features
//! - `Choice`: 항상 0 또는 1 값을 갖는 상수-시간 bool이며 비트 연산으로 조합됩니다.
//! - `CtSelOps`: 조건에 따라 두 값 중 하나를 선택하고 대입과 교환을 파생합니다.
//! - `CtEqOps`: 두 값의 동등 여부를 상수-시간에 판정합니다.
//! - `CtGtOps`: 두 값의 대소를 상수-시간에 판정합니다.
//! - `CtLess`: `CtEqOps`와 `CtGtOps`를 만족하는 모든 타입에 자동으로 제공됩니다.
//! - `DitGuard`: AArch64 PSTATE.DIT를 암호 연산 구간 동안 설정하는 옵트-인(opt-in) [RAII](https://doc.rust-lang.org/rust-by-example/scope/raii.html) 가드입니다.
//!
//! # Examples
//! ```rust,ignore
//! let cond = Choice::from_u8(1);
//! let selected = u32::select(&10, &20, cond);
//! let equal = 7u32.ct_eq(&7);
//! let greater = 9u32.ct_gt(&4);
//! ```
#![cfg_attr(not(test), no_std)]

mod dit;
mod internal;
pub mod traits;

pub use dit::{DIT_HW_BACKED, DitGuard};

use crate::private::Sealed;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

//
// Choice
//

/// 항상 0 또는 1 값을 갖는 상수-시간 bool을 나타내는 구조체입니다.
///
/// 비트 연산 `&`, `|`, `^`, `!`이 0 또는 1 불변을 정규화 없이 보존합니다.
///
/// # Security Note
/// 민감한 선택 값이 로그로 흘러 들어가는 사고를 막기 위해 `Debug`를 의도적으로
/// 파생하지 않습니다 (CWE-532).
#[derive(Copy, Clone)]
pub struct Choice(u8);

impl Choice {
    /// 임의의 `u8`을 0 또는 1로 정규화하여 `Choice`를 생성하는 함수입니다.
    ///
    /// 0이 아닌 값은 1로, 0은 0으로 분기 없이 정규화합니다.
    ///
    /// # Arguments
    /// - `v`: 정규화 대상 바이트입니다
    #[must_use]
    #[inline]
    pub fn from_u8(v: u8) -> Self {
        // 상수-시간 정규화로 0이 아니면 1, 0이면 0으로 만듭니다
        // (v | wrapping_neg(v))의 MSB는 v가 0이 아닐 때만 1이므로 7비트 우측 시프트로 추출합니다
        Choice((v | v.wrapping_neg()) >> 7)
    }

    /// 내부 0 또는 1 값을 그대로 반환하는 함수입니다.
    #[must_use]
    #[inline]
    pub const fn unwrap_u8(&self) -> u8 {
        self.0
    }
}

//
// Bits ops - start
//
// 피연산자가 0 또는 1이므로 `&`, `|`, `^`는 정규화 없이 불변을 보존합니다
// `Not`은 1과의 XOR로 분기 없이 0과 1을 뒤집습니다
//

impl BitAnd for Choice {
    type Output = Choice;
    #[inline]
    fn bitand(self, rhs: Choice) -> Choice {
        Choice(self.0 & rhs.0)
    }
}

impl BitAndAssign for Choice {
    #[inline]
    fn bitand_assign(&mut self, rhs: Choice) {
        self.0 &= rhs.0;
    }
}

impl BitOr for Choice {
    type Output = Choice;
    #[inline]
    fn bitor(self, rhs: Choice) -> Choice {
        Choice(self.0 | rhs.0)
    }
}

impl BitOrAssign for Choice {
    #[inline]
    fn bitor_assign(&mut self, rhs: Choice) {
        *self = *self | rhs;
    }
}

impl BitXor for Choice {
    type Output = Choice;
    #[inline]
    fn bitxor(self, rhs: Choice) -> Choice {
        Choice(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for Choice {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Choice) {
        self.0 ^= rhs.0;
    }
}

impl Not for Choice {
    type Output = Choice;
    #[inline]
    fn not(self) -> Choice {
        // 1과의 XOR로 분기나 정규화 없이 0과 1을 뒤집습니다
        Choice(self.0 ^ 1)
    }
}

//
// Bits ops - end
//

//
// Sealed - start
//

mod private {
    pub trait Sealed {}
}

macro_rules! impl_sealed {
    ($($t:ty),+) => {
        $(
            impl private::Sealed for $t {}
        )+
    };
}

impl_sealed!(
    u8, u16, u32, i8, i16, i32, u64, i64, usize, isize, u128, i128
);

impl<T: Sealed, const N: usize> Sealed for [T; N] {}

//
// Sealed - end
//

/// 결정적 값 동등성 테스트 모듈입니다.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::*;
    use zeroize::Secret;

    const U32_SAMPLES: [u32; 8] = [
        0,
        1,
        2,
        0x7FFF_FFFF,
        0x8000_0000,
        0x8000_0001,
        0xFFFF_FFFE,
        0xFFFF_FFFF,
    ];

    const U64_SAMPLES: [u64; 8] = [
        0,
        1,
        2,
        0x7FFF_FFFF_FFFF_FFFF,
        0x8000_0000_0000_0000,
        0x8000_0000_0000_0001,
        0xFFFF_FFFF_FFFF_FFFE,
        0xFFFF_FFFF_FFFF_FFFF,
    ];

    const I64_SAMPLES: [i64; 8] = [i64::MIN, i64::MIN + 1, -1, 0, 1, 2, i64::MAX - 1, i64::MAX];

    const U128_SAMPLES: [u128; 8] = [
        0,
        1,
        u64::MAX as u128,
        (u64::MAX as u128) + 1,
        1u128 << 127,
        (1u128 << 127) | 1,
        u128::MAX - 1,
        u128::MAX,
    ];

    const I128_SAMPLES: [i128; 8] = [
        i128::MIN,
        i128::MIN + 1,
        -1,
        0,
        1,
        i64::MAX as i128,
        i128::MAX - 1,
        i128::MAX,
    ];

    #[test]
    fn choice_from_u8_normalises_to_bit() {
        for v in 0u8..=255 {
            let c = Choice::from_u8(v).unwrap_u8();
            assert!(c == 0 || c == 1, "Choice {{0,1}} 불변 위반: {v} -> {c}");
            assert_eq!(c, (v != 0) as u8, "Choice::from_u8 정규화 불일치: {v}");
        }
    }

    #[test]
    fn choice_bitops_preserve_invariant() {
        for x in 0u8..=1 {
            for y in 0u8..=1 {
                let a = Choice::from_u8(x);
                let b = Choice::from_u8(y);

                let and = (a & b).unwrap_u8();
                let or = (a | b).unwrap_u8();
                let xor = (a ^ b).unwrap_u8();
                let not_a = (!a).unwrap_u8();

                for (name, r) in [("&", and), ("|", or), ("^", xor), ("!", not_a)] {
                    assert!(
                        r == 0 || r == 1,
                        "Choice 비트연산 {name} {{0,1}} 불변 위반: {r}"
                    );
                }

                assert_eq!(and, x & y, "Choice & 값 불일치: {x} & {y}");
                assert_eq!(or, x | y, "Choice | 값 불일치: {x} | {y}");
                assert_eq!(xor, x ^ y, "Choice ^ 값 불일치: {x} ^ {y}");
                assert_eq!(not_a, x ^ 1, "Choice ! 값 불일치: !{x}");

                let mut aa = Choice::from_u8(x);
                aa &= b;
                assert_eq!(aa.unwrap_u8(), x & y, "Choice &= 값 불일치");
                let mut ao = Choice::from_u8(x);
                ao |= b;
                assert_eq!(ao.unwrap_u8(), x | y, "Choice |= 값 불일치");
                let mut ax = Choice::from_u8(x);
                ax ^= b;
                assert_eq!(ax.unwrap_u8(), x ^ y, "Choice ^= 값 불일치");
            }
        }
    }

    #[test]
    fn ct_eq_array_and_secret_delegation() {
        let base = [0x5Au8; 32];
        let same = [0x5Au8; 32];
        assert_eq!(
            base.ct_eq(&same).unwrap_u8(),
            1,
            "[u8; 32] 동일 배열 ct_eq 불일치"
        );

        let mut first_diff = base;
        first_diff[0] ^= 0x80;
        assert_eq!(
            base.ct_eq(&first_diff).unwrap_u8(),
            0,
            "[u8; 32] 첫 원소 차이 미검출"
        );

        let mut last_diff = base;
        last_diff[31] ^= 1;
        assert_eq!(
            base.ct_eq(&last_diff).unwrap_u8(),
            0,
            "[u8; 32] 마지막 원소 차이 미검출"
        );

        let words = [0xDEAD_BEEFu32; 8];
        assert_eq!(
            words.ct_eq(&[0xDEAD_BEEFu32; 8]).unwrap_u8(),
            1,
            "[u32; 8] 동일 배열 ct_eq 불일치"
        );

        let s1 = Secret::new(base);
        let s2 = Secret::new(same);
        let s3 = Secret::new(last_diff);
        assert_eq!(
            s1.ct_eq(&s2).unwrap_u8(),
            1,
            "Secret<[u8; 32]> 동일 키 ct_eq 불일치"
        );
        assert_eq!(
            s1.ct_eq(&s3).unwrap_u8(),
            0,
            "Secret<[u8; 32]> 상이 키 미검출"
        );
        assert_eq!(
            s1.ct_ne(&s3).unwrap_u8(),
            1,
            "Secret<[u8; 32]> ct_ne 파생 불일치"
        );

        let a = Secret::new(0x0123_4567_89AB_CDEFu64);
        let b = Secret::new(0x0123_4567_89AB_CDEFu64);
        assert_eq!(
            a.ct_eq(&b).unwrap_u8(),
            1,
            "Secret<u64> 동일 값 ct_eq 불일치"
        );
    }

    #[test]
    fn ct_eq_value_matches_branchful() {
        // u8 전수 (256 x 256)
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(
                    CtEqOps::ct_eq(&a, &b).unwrap_u8(),
                    (a == b) as u8,
                    "CtEqOps::eq u8 불일치: {a} == {b}"
                );
                assert_eq!(
                    CtEqOps::ct_ne(&a, &b).unwrap_u8(),
                    (a != b) as u8,
                    "CtEqOps::ne u8 불일치: {a} != {b}"
                );
            }
        }
        // u32/u64/u128/i64/i128 경계 샘플
        for &a in &U32_SAMPLES {
            for &b in &U32_SAMPLES {
                assert_eq!(
                    CtEqOps::ct_eq(&a, &b).unwrap_u8(),
                    (a == b) as u8,
                    "eq u32 불일치"
                );
                assert_eq!(
                    CtEqOps::ct_ne(&a, &b).unwrap_u8(),
                    (a != b) as u8,
                    "ne u32 불일치"
                );
            }
        }
        for &a in &U64_SAMPLES {
            for &b in &U64_SAMPLES {
                assert_eq!(
                    CtEqOps::ct_eq(&a, &b).unwrap_u8(),
                    (a == b) as u8,
                    "eq u64 불일치"
                );
            }
        }
        for &a in &U128_SAMPLES {
            for &b in &U128_SAMPLES {
                assert_eq!(
                    CtEqOps::ct_eq(&a, &b).unwrap_u8(),
                    (a == b) as u8,
                    "eq u128 불일치"
                );
            }
        }
        for &a in &I64_SAMPLES {
            for &b in &I64_SAMPLES {
                assert_eq!(
                    CtEqOps::ct_eq(&a, &b).unwrap_u8(),
                    (a == b) as u8,
                    "eq i64 불일치"
                );
            }
        }
        for &a in &I128_SAMPLES {
            for &b in &I128_SAMPLES {
                assert_eq!(
                    CtEqOps::ct_eq(&a, &b).unwrap_u8(),
                    (a == b) as u8,
                    "eq i128 불일치"
                );
            }
        }
    }

    #[test]
    fn ct_select_matches_branchful() {
        // select(a, b, choice)는 choice가 1이면 b, 0이면 a를 반환
        fn check<T: CtSelOps + PartialEq + core::fmt::Debug>(a: T, b: T) {
            let one = Choice::from_u8(1);
            let zero = Choice::from_u8(0);
            assert_eq!(T::select(&a, &b, one), b, "select choice=1 은 b 여야 함");
            assert_eq!(T::select(&a, &b, zero), a, "select choice=0 은 a 여야 함");
        }
        check::<u8>(0x12, 0xED);
        check::<u8>(0, u8::MAX);
        check::<u16>(0x1234, 0xEDCB);
        check::<u32>(0, u32::MAX);
        check::<u32>(0x7FFF_FFFF, 0x8000_0000);
        check::<u64>(0, u64::MAX);
        check::<u64>(0x8000_0000_0000_0000, 0x7FFF_FFFF_FFFF_FFFF);
        check::<u128>(0, u128::MAX);
        check::<u128>(1u128 << 127, (1u128 << 127) | 1);
        check::<i8>(-1, 1);
        check::<i32>(i32::MIN, i32::MAX);
        check::<i64>(i64::MIN, i64::MAX);
        check::<i128>(i128::MIN, i128::MAX);
    }

    #[test]
    fn ct_gt_lt_boundary() {
        // gt는 self가 other보다 큼, lt는 self가 other보다 작음을 분기형과 대조
        for &a in &U32_SAMPLES {
            for &b in &U32_SAMPLES {
                assert_eq!(
                    CtGtOps::ct_gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt u32 불일치: {a} > {b}"
                );
                assert_eq!(
                    CtLess::ct_lt(&a, &b).unwrap_u8(),
                    (a < b) as u8,
                    "lt u32 불일치: {a} < {b}"
                );
            }
        }
        for &a in &U64_SAMPLES {
            for &b in &U64_SAMPLES {
                assert_eq!(
                    CtGtOps::ct_gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt u64 불일치"
                );
                assert_eq!(
                    CtLess::ct_lt(&a, &b).unwrap_u8(),
                    (a < b) as u8,
                    "lt u64 불일치"
                );
            }
        }
        for &a in &I64_SAMPLES {
            for &b in &I64_SAMPLES {
                assert_eq!(
                    CtGtOps::ct_gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt i64 불일치: {a} > {b}"
                );
                assert_eq!(
                    CtLess::ct_lt(&a, &b).unwrap_u8(),
                    (a < b) as u8,
                    "lt i64 불일치: {a} < {b}"
                );
            }
        }
        for &a in &U128_SAMPLES {
            for &b in &U128_SAMPLES {
                assert_eq!(
                    CtGtOps::ct_gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt u128 불일치"
                );
                assert_eq!(
                    CtLess::ct_lt(&a, &b).unwrap_u8(),
                    (a < b) as u8,
                    "lt u128 불일치"
                );
            }
        }
        for &a in &I128_SAMPLES {
            for &b in &I128_SAMPLES {
                assert_eq!(
                    CtGtOps::ct_gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt i128 불일치: {a} > {b}"
                );
                assert_eq!(
                    CtLess::ct_lt(&a, &b).unwrap_u8(),
                    (a < b) as u8,
                    "lt i128 불일치: {a} < {b}"
                );
            }
        }
        // i8 전수 부호경계
        for a in i8::MIN..=i8::MAX {
            for b in i8::MIN..=i8::MAX {
                assert_eq!(
                    CtGtOps::ct_gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt i8 전수 불일치"
                );
                assert_eq!(
                    CtLess::ct_lt(&a, &b).unwrap_u8(),
                    (a < b) as u8,
                    "lt i8 전수 불일치"
                );
            }
        }
    }

    #[test]
    fn ct_sel_swap_value_roundtrip() {
        fn check<T: CtSelOps + PartialEq + core::fmt::Debug>(orig_a: T, orig_b: T) {
            // choice == 1: 교환됨
            let mut a = orig_a;
            let mut b = orig_b;
            T::swap(&mut a, &mut b, Choice::from_u8(1));
            assert_eq!(a, orig_b, "swap choice=1 후 a 는 원래 b 여야 함");
            assert_eq!(b, orig_a, "swap choice=1 후 b 는 원래 a 여야 함");

            // choice == 0: 무변경
            let mut a2 = orig_a;
            let mut b2 = orig_b;
            T::swap(&mut a2, &mut b2, Choice::from_u8(0));
            assert_eq!(a2, orig_a, "swap choice=0 은 a 무변경이어야 함");
            assert_eq!(b2, orig_b, "swap choice=0 은 b 무변경이어야 함");
        }
        check::<u8>(0x12, 0xED);
        check::<u32>(0x7FFF_FFFF, 0x8000_0000);
        check::<u64>(0, u64::MAX);
        check::<u128>(1u128 << 127, (1u128 << 127) | 1);
        check::<i64>(i64::MIN, i64::MAX);

        // assign도 함께 검증합니다 (swap의 기반 연산)
        let mut x: u64 = 0xAAAA_AAAA_AAAA_AAAA;
        let y: u64 = 0x5555_5555_5555_5555;
        x.assign(&y, Choice::from_u8(0));
        assert_eq!(
            x, 0xAAAA_AAAA_AAAA_AAAA,
            "assign choice=0 은 무변경이어야 함"
        );
        x.assign(&y, Choice::from_u8(1));
        assert_eq!(x, y, "assign choice=1 은 other 로 대입되어야 함");
    }
}
