#![cfg_attr(not(test), no_std)]

mod internal;

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};
use internal::*;

//
// Choice
//

/// A constant-time boolean value (0 or 1).
///
/// Debug is intentionally not derived to prevent accidental leakage
/// of sensitive choice values in logs (CWE-532).
#[derive(Copy, Clone)]
pub struct Choice(u8);

impl Choice {
    #[must_use]
    #[inline]
    pub fn from_u8(v: u8) -> Self {
        // CT normalise: nonzero -> 1, zero -> 0.
        // (v | -v) >> 7: MSB of (v | wrapping_neg(v)) is set iff v != 0.
        Choice((v | v.wrapping_neg()) >> 7)
    }

    #[must_use]
    #[inline]
    pub const fn unwrap_u8(&self) -> u8 {
        self.0
    }
}

//
// Bit ops
//
// Operands ∈ {0, 1} so &, |, ^ preserve the invariant without normalisation
// Not uses XOR-with-1: {0->1, 1->0} without branching
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
        // XOR with 1 flips {0->1, 1->0} without branching or normalisation
        Choice(self.0 ^ 1)
    }
}

//
// CtSelOps trait (select, assign, swap)
//
// select(a, b, choice): returns *b when choice == 1, *a when choice == 0
// assign / swap are derived from select
//
// select(a, b, c) == ct_sel*(c.0, *b, *a)
//   because ct_sel*(cond, x, y) returns x when cond != 0
//   c == 1  ->  ct_sel*(1, *b, *a) == *b  ✓
//   c == 0  ->  ct_sel*(0, *b, *a) == *a  ✓
//

pub trait CtSelOps: Copy {
    fn select(a: &Self, b: &Self, choice: Choice) -> Self;

    #[inline]
    fn assign(&mut self, other: &Self, choice: Choice) {
        *self = Self::select(self, other, choice);
    }

    /// `choice == 1` 인 경우 `a` 와 `b` 를 상수시간에 교환하는 함수입니다.
    ///
    /// # Security Note
    /// 임시 변수 `t` 는 `*a` 의 평문 사본을 일시적으로 보유합니다.
    /// 함수 종료 시 `size_of::<Self>()` 바이트 전 영역을 volatile 0으로
    /// 덮어쓴 뒤 `compiler_fence(SeqCst)`로 store reorder를 차단하여
    /// CWE-316 (cleartext storage in memory)잔재를 방지합니다.
    /// 추가로 `black_box(&mut t)`가 stack slot의 escape를 강제하여
    /// 최적화기가 임시 변수를 레지스터 only로 유지하지 못하도록 합니다.
    #[inline]
    fn swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let mut t: Self = *a;
        let _ = core::hint::black_box(&mut t);
        a.assign(b, choice);
        b.assign(&t, choice);
        // SAFETY: `t`는 `Self: Copy + Sized`이며 함수 로컬 스택 슬롯에 존재
        //         각 바이트에 대한 volatile write는 alias 없는 유일 포인터를 통해
        //         수행되므로 race가 없고, write_volatile는 DCE 대상이 아님
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
// CtEqOps trait (eq, ne)
//
// eq returns Choice(1) iff self == other, Choice(0) otherwise
// ne is derived: !eq
//
// Equality is sign-agnostic: two values are equal iff their bit patterns are
// identical. Signed types are widened with sign extension before comparison;
// since both operands go through the same extension the result is correct
//

pub trait CtEqOps {
    fn eq(&self, other: &Self) -> Choice;

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
// CtGreeter trait (gt)
//
// gt returns Choice(1) iff self > other, Choice(0) otherwise
//
// Unsigned types are zero-extended to 32 or 64 bits
// Signed types are sign-extended to i64; this preserves the ordering since
// two's complement sign-extension is monotone within each type's range
//

pub trait CtGreeter {
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

// Signed types: sign-extend to i64 before calling ct_gt_i64
// i8 as i64 / i16 as i64 / i32 as i64 all perform sign extension
// On 64-bit platforms isize == i64, so the cast is lossless
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
// CtLess trait (lt)
//
// lt is derived from gt and eq:
//   a < b  iff  NOT (a > b)  AND  NOT (a == b)
//          iff  NOT (a >= b)
//
// Both operations are CT; their combination is CT
//

pub trait CtLess: CtEqOps + CtGreeter {
    #[inline]
    fn lt(&self, other: &Self) -> Choice {
        !self.gt(other) & !self.eq(other)
    }
}

// Blanket impl: any type that satisfies both CtEqOps and CtGreeter
// automatically gets CtLess with the verified CT default
impl<T: CtEqOps + CtGreeter> CtLess for T {}

//
// Layer-1 deterministic value-equivalence tests (CTSEC-01, CONTEXT D-03)
//
// 값 동등성만 증명 — 분기 부재는 계층-2 디스어셈블 게이트(check_ct_asm.sh) 소관
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
        // select(a, b, choice): choice==1 -> b, choice==0 -> a
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
        // gt: self > other, lt: self < other (분기형과 대조)
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

        // assign 도 함께 검증 (swap 의 기반 연산)
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
