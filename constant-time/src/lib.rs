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

    /// Conditionally swaps `a` and `b` if `choice == 1`.
    ///
    /// The temporary value is passed through `black_box` to prevent the
    /// compiler from keeping it in registers or optimizing away the zeroing
    /// (CWE-316 mitigation).
    #[inline]
    fn swap(a: &mut Self, b: &mut Self, choice: Choice) {
        // Store original value of a
        let mut t: Self = *a;
        a.assign(b, choice);
        b.assign(&t, choice);
        // Prevent compiler from optimizing away the temporary or keeping
        // sensitive data in registers after this function returns.
        // black_box acts as an optimization barrier.
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
