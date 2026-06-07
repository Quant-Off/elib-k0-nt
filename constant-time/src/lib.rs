//! 분기 없는 상수-시간 정수 연산 기능이 구현된 모듈입니다.
//!
//! 비밀 값에 의존하는 분기나 데이터 의존 메모리 접근 없이 값 선택과 동등
//! 비교, 대소 비교를 수행하는 `Choice` 타입과 `CtSelOps`, `CtEqOps`,
//! `CtGreeter`, `CtLess` 트레이트를 제공합니다. 저수준 상수-시간 프리미티브는
//! `internal` 모듈에 있으며 x86_64와 aarch64에서는 인-라인 어셈블리로, 그 외
//! 아키텍처에서는 `black_box` 기반 best-effort fallback으로 동작합니다.
//!
//! # Features
//! - `Choice`: 항상 0 또는 1 값을 갖는 상수-시간 bool이며 비트 연산으로 조합됩니다
//! - `CtSelOps`: 조건에 따라 두 값 중 하나를 선택하고 대입과 교환을 파생합니다
//! - `CtEqOps`: 두 값의 동등 여부를 상수-시간에 판정합니다
//! - `CtGreeter`: 두 값의 대소를 상수-시간에 판정합니다
//! - `CtLess`: `CtEqOps`와 `CtGreeter`를 만족하는 모든 타입에 자동으로 제공됩니다
//!
//! # Examples
//! ```rust,ignore
//! let cond = Choice::from_u8(1);
//! let selected = u32::select(&10, &20, cond);
//! let equal = 7u32.eq(&7);
//! let greater = 9u32.gt(&4);
//! ```
//!
//! # Authors
//! Q. T. Felix
#![cfg_attr(not(test), no_std)]

mod internal;

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};
use internal::*;

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
// 비트 연산
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
// CtSelOps 트레이트 (select, assign, swap)
//
// select(a, b, choice)는 choice가 1이면 *b를, 0이면 *a를 반환하며
// assign과 swap은 select에서 파생됩니다
//
// ct_sel(cond, x, y)가 cond가 0이 아닐 때 x를 반환하므로
// select(a, b, c)는 ct_sel(c.0, *b, *a)와 같습니다
//

/// 조건에 따라 두 값 중 하나를 상수-시간에 선택하는 연산을 정의하는 트레이트입니다.
///
/// `assign`과 `swap`은 `select`에서 파생됩니다.
pub trait CtSelOps: Copy {
    /// `choice`가 1이면 `b`를, 0이면 `a`를 상수-시간에 선택하여 반환하는 함수입니다.
    ///
    /// # Arguments
    /// - `a`: `choice`가 0일 때 선택되는 값입니다
    /// - `b`: `choice`가 1일 때 선택되는 값입니다
    /// - `choice`: 선택 조건입니다
    fn select(a: &Self, b: &Self, choice: Choice) -> Self;

    /// `choice`가 1이면 `other`를 자신에게 상수-시간에 대입하는 함수입니다.
    ///
    /// # Arguments
    /// - `other`: 대입 후보 값입니다
    /// - `choice`: 대입 조건입니다
    #[inline]
    fn assign(&mut self, other: &Self, choice: Choice) {
        *self = Self::select(self, other, choice);
    }

    /// `choice`가 1이면 `a`와 `b`를 상수-시간에 교환하는 함수입니다.
    ///
    /// # Arguments
    /// - `a`: 교환 대상 첫 번째 값입니다
    /// - `b`: 교환 대상 두 번째 값입니다
    /// - `choice`: 교환 조건이며 0이면 두 값을 그대로 둡니다
    ///
    /// # Safety
    /// 임시 변수 `t`는 `Self: Copy + Sized`이며 함수 로컬 스택 슬롯에만
    /// 존재합니다. 각 바이트의 volatile write는 별칭 없는 유일 포인터로
    /// 수행되므로 경합이 없고 `write_volatile`는 죽은 코드 제거 대상이
    /// 아닙니다.
    ///
    /// # Security Note
    /// 임시 변수 `t`는 `*a`의 평문 사본을 일시적으로 보유합니다. 함수 종료 시
    /// `size_of::<Self>()` 바이트 전 영역을 volatile 0으로 덮어쓴 뒤
    /// `compiler_fence(SeqCst)`로 store 재정렬을 차단하여 CWE-316 (cleartext
    /// storage in memory) 잔재를 방지합니다. 추가로 `black_box(&mut t)`가 스택
    /// 슬롯의 escape를 강제하여 최적화기가 임시 변수를 레지스터에만 유지하지
    /// 못하도록 합니다.
    #[inline]
    fn swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let mut t: Self = *a;
        let _ = core::hint::black_box(&mut t);
        a.assign(b, choice);
        b.assign(&t, choice);
        // SAFETY: `t`는 함수 로컬 스택 슬롯의 유일 포인터이며 각 바이트의
        //         volatile write는 별칭과 경합이 없고 죽은 코드 제거 대상이
        //         아닙니다
        let size = core::mem::size_of::<Self>();
        let ptr = core::ptr::from_mut(&mut t).cast::<u8>();
        for i in 0..size {
            unsafe {
                core::ptr::write_volatile(ptr.add(i), 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut t);
    }
}

macro_rules! impl_sel_via32 {
    ($($t:ty),+) => {
        $(
            impl CtSelOps for $t {
                #[inline]
                fn select(a: &Self, b: &Self, choice: Choice) -> Self {
                    ct_sel32(choice.0, *b as u32, *a as u32) as $t
                }
            }
        )+
    };
}

macro_rules! impl_sel_via64 {
    ($($t:ty),+) => {
        $(
            impl CtSelOps for $t {
                #[inline]
                fn select(a: &Self, b: &Self, choice: Choice) -> Self {
                    ct_sel64(choice.0, *b as u64, *a as u64) as $t
                }
            }
        )+
    };
}

impl_sel_via32!(u8, u16, u32, i8, i16, i32);
impl_sel_via64!(u64, i64, usize, isize);

impl CtSelOps for u128 {
    #[inline]
    fn select(a: &Self, b: &Self, choice: Choice) -> Self {
        let hi = ct_sel64(choice.0, (*b >> 64) as u64, (*a >> 64) as u64) as u128;
        let lo = ct_sel64(choice.0, *b as u64, *a as u64) as u128;
        (hi << 64) | lo
    }
}

impl CtSelOps for i128 {
    #[inline]
    fn select(a: &Self, b: &Self, choice: Choice) -> Self {
        u128::select(&(*a as u128), &(*b as u128), choice) as i128
    }
}

//
// CtEqOps 트레이트 (eq, ne)
//
// eq는 self와 other가 같으면 Choice(1)을, 아니면 Choice(0)을 반환하며
// ne는 !eq로 파생됩니다
//
// 동등성은 부호와 무관하며 두 값의 비트 패턴이 같을 때만 같습니다. 부호 있는
// 타입은 비교 전에 부호 확장으로 넓히는데 두 피연산자가 같은 확장을 거치므로
// 결과가 정확합니다
//

/// 두 값의 동등 여부를 상수-시간에 판정하는 연산을 정의하는 트레이트입니다.
pub trait CtEqOps {
    /// 자신과 `other`가 같으면 `Choice(1)`을, 다르면 `Choice(0)`을 반환하는 함수입니다.
    ///
    /// # Arguments
    /// - `other`: 비교 대상 값입니다
    fn eq(&self, other: &Self) -> Choice;

    /// 자신과 `other`가 다르면 `Choice(1)`을, 같으면 `Choice(0)`을 반환하는 함수입니다.
    ///
    /// # Arguments
    /// - `other`: 비교 대상 값입니다
    #[inline]
    fn ne(&self, other: &Self) -> Choice {
        !self.eq(other)
    }
}

macro_rules! impl_eq_via32 {
    ($($t:ty),+) => {
        $(
            impl CtEqOps for $t {
                #[inline]
                fn eq(&self, other: &Self) -> Choice {
                    Choice(ct_eq32(*self as u32, *other as u32))
                }
            }
        )+
    };
}

macro_rules! impl_eq_via64 {
    ($($t:ty),+) => {
        $(
            impl CtEqOps for $t {
                #[inline]
                fn eq(&self, other: &Self) -> Choice {
                    Choice(ct_eq64(*self as u64, *other as u64))
                }
            }
        )+
    };
}

impl_eq_via32!(u8, u16, u32, i8, i16, i32);
impl_eq_via64!(u64, i64, usize, isize);

impl CtEqOps for u128 {
    #[inline]
    fn eq(&self, other: &Self) -> Choice {
        Choice(ct_eq128(*self, *other))
    }
}

impl CtEqOps for i128 {
    #[inline]
    fn eq(&self, other: &Self) -> Choice {
        Choice(ct_eq128(*self as u128, *other as u128))
    }
}

//
// CtGreeter 트레이트 (gt)
//
// gt는 self가 other보다 크면 Choice(1)을, 아니면 Choice(0)을 반환합니다
//
// 부호 없는 타입은 32비트 또는 64비트로 영 확장합니다
// 부호 있는 타입은 i64로 부호 확장하는데 2의 보수 부호 확장이 각 타입 범위
// 안에서 단조이므로 순서가 보존됩니다
//

/// 두 값의 대소를 상수-시간에 판정하는 연산을 정의하는 트레이트입니다.
pub trait CtGreeter {
    /// 자신이 `other`보다 크면 `Choice(1)`을, 아니면 `Choice(0)`을 반환하는 함수입니다.
    ///
    /// # Arguments
    /// - `other`: 비교 대상 값입니다
    fn gt(&self, other: &Self) -> Choice;
}

macro_rules! impl_gt_unsigned_via32 {
    ($($t:ty),+) => {
        $(
            impl CtGreeter for $t {
                #[inline]
                fn gt(&self, other: &Self) -> Choice {
                    Choice(ct_gt_u32(*self as u32, *other as u32))
                }
            }
        )+
    };
}

macro_rules! impl_gt_unsigned_via64 {
    ($($t:ty),+) => {
        $(
            impl CtGreeter for $t {
                #[inline]
                fn gt(&self, other: &Self) -> Choice {
                    Choice(ct_gt_u64(*self as u64, *other as u64))
                }
            }
        )+
    };
}

// 부호 있는 타입은 ct_gt_i64 호출 전에 i64로 부호 확장합니다
// i8 as i64, i16 as i64, i32 as i64는 모두 부호 확장을 수행합니다
// 64비트 플랫폼에서는 isize가 i64와 같으므로 캐스팅에 손실이 없습니다
macro_rules! impl_gt_signed_via64 {
    ($($t:ty),+) => {
        $(
            impl CtGreeter for $t {
                #[inline]
                fn gt(&self, other: &Self) -> Choice {
                    Choice(ct_gt_i64(*self as i64, *other as i64))
                }
            }
        )+
    };
}

impl_gt_unsigned_via32!(u8, u16, u32);
impl_gt_unsigned_via64!(u64, usize);
impl_gt_signed_via64!(i8, i16, i32, i64, isize);

impl CtGreeter for u128 {
    #[inline]
    fn gt(&self, other: &Self) -> Choice {
        Choice(ct_gt_u128(*self, *other))
    }
}

impl CtGreeter for i128 {
    #[inline]
    fn gt(&self, other: &Self) -> Choice {
        Choice(ct_gt_i128(*self, *other))
    }
}

//
// CtLess 트레이트 (lt)
//
// lt는 gt와 eq에서 파생됩니다
// a가 b보다 작은 것은 a가 b보다 크지 않고 a와 b가 같지도 않은 것과 같으며
// 결국 a가 b 이상이 아닌 것과 같습니다
//
// 두 연산 모두 상수-시간이므로 그 조합도 상수-시간입니다
//

/// 두 값의 작음 여부를 상수-시간에 판정하는 연산을 정의하는 트레이트입니다.
///
/// `CtEqOps`와 `CtGreeter`의 결과를 결합하여 기본 구현을 파생합니다.
pub trait CtLess: CtEqOps + CtGreeter {
    /// 자신이 `other`보다 작으면 `Choice(1)`을, 아니면 `Choice(0)`을 반환하는 함수입니다.
    ///
    /// # Arguments
    /// - `other`: 비교 대상 값입니다
    #[inline]
    fn lt(&self, other: &Self) -> Choice {
        !self.gt(other) & !self.eq(other)
    }
}

// 일괄 구현으로 CtEqOps와 CtGreeter를 모두 만족하는 타입은 검증된 상수-시간
// 기본 구현으로 CtLess를 자동으로 얻습니다.
impl<T: CtEqOps + CtGreeter> CtLess for T {}

//
// 계층-1 결정적 값 동등성 테스트 (CTSEC-01, CONTEXT D-03)
//
// 값 동등성만 증명하며 분기 부재는 계층-2 디스어셈블 게이트(check_ct_asm.sh) 소관입니다.
//
#[cfg(test)]
mod tests {
    use super::*;

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
    fn ct_eq_value_matches_branchful() {
        // u8 전수 (256 x 256)
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(
                    CtEqOps::eq(&a, &b).unwrap_u8(),
                    (a == b) as u8,
                    "CtEqOps::eq u8 불일치: {a} == {b}"
                );
                assert_eq!(
                    CtEqOps::ne(&a, &b).unwrap_u8(),
                    (a != b) as u8,
                    "CtEqOps::ne u8 불일치: {a} != {b}"
                );
            }
        }
        // u32/u64/u128/i64/i128 경계 샘플
        for &a in &U32_SAMPLES {
            for &b in &U32_SAMPLES {
                assert_eq!(
                    CtEqOps::eq(&a, &b).unwrap_u8(),
                    (a == b) as u8,
                    "eq u32 불일치"
                );
                assert_eq!(
                    CtEqOps::ne(&a, &b).unwrap_u8(),
                    (a != b) as u8,
                    "ne u32 불일치"
                );
            }
        }
        for &a in &U64_SAMPLES {
            for &b in &U64_SAMPLES {
                assert_eq!(
                    CtEqOps::eq(&a, &b).unwrap_u8(),
                    (a == b) as u8,
                    "eq u64 불일치"
                );
            }
        }
        for &a in &U128_SAMPLES {
            for &b in &U128_SAMPLES {
                assert_eq!(
                    CtEqOps::eq(&a, &b).unwrap_u8(),
                    (a == b) as u8,
                    "eq u128 불일치"
                );
            }
        }
        for &a in &I64_SAMPLES {
            for &b in &I64_SAMPLES {
                assert_eq!(
                    CtEqOps::eq(&a, &b).unwrap_u8(),
                    (a == b) as u8,
                    "eq i64 불일치"
                );
            }
        }
        for &a in &I128_SAMPLES {
            for &b in &I128_SAMPLES {
                assert_eq!(
                    CtEqOps::eq(&a, &b).unwrap_u8(),
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
                    CtGreeter::gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt u32 불일치: {a} > {b}"
                );
                assert_eq!(
                    CtLess::lt(&a, &b).unwrap_u8(),
                    (a < b) as u8,
                    "lt u32 불일치: {a} < {b}"
                );
            }
        }
        for &a in &U64_SAMPLES {
            for &b in &U64_SAMPLES {
                assert_eq!(
                    CtGreeter::gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt u64 불일치"
                );
                assert_eq!(
                    CtLess::lt(&a, &b).unwrap_u8(),
                    (a < b) as u8,
                    "lt u64 불일치"
                );
            }
        }
        for &a in &I64_SAMPLES {
            for &b in &I64_SAMPLES {
                assert_eq!(
                    CtGreeter::gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt i64 불일치: {a} > {b}"
                );
                assert_eq!(
                    CtLess::lt(&a, &b).unwrap_u8(),
                    (a < b) as u8,
                    "lt i64 불일치: {a} < {b}"
                );
            }
        }
        for &a in &U128_SAMPLES {
            for &b in &U128_SAMPLES {
                assert_eq!(
                    CtGreeter::gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt u128 불일치"
                );
                assert_eq!(
                    CtLess::lt(&a, &b).unwrap_u8(),
                    (a < b) as u8,
                    "lt u128 불일치"
                );
            }
        }
        for &a in &I128_SAMPLES {
            for &b in &I128_SAMPLES {
                assert_eq!(
                    CtGreeter::gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt i128 불일치: {a} > {b}"
                );
                assert_eq!(
                    CtLess::lt(&a, &b).unwrap_u8(),
                    (a < b) as u8,
                    "lt i128 불일치: {a} < {b}"
                );
            }
        }
        // i8 전수 부호경계
        for a in i8::MIN..=i8::MAX {
            for b in i8::MIN..=i8::MAX {
                assert_eq!(
                    CtGreeter::gt(&a, &b).unwrap_u8(),
                    (a > b) as u8,
                    "gt i8 전수 불일치"
                );
                assert_eq!(
                    CtLess::lt(&a, &b).unwrap_u8(),
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
