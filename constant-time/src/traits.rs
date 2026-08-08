use crate::Choice;
use crate::internal::*;
use crate::private::Sealed;
use zeroize::{Secret, Zeroable, Zeroize};

//
// CtSelOps - start
//

/// 조건에 따라 두 값 중 하나를 상수-시간에 선택하는 연산을 정의하는 트레이트입니다.
///
/// `assign`과 `swap`은 `select`에서 파생됩니다.
pub trait CtSelOps: Copy + Zeroize + Sealed {
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
    /// # Security Note
    /// 안전성에 관한 논증이 [zeroize] 크레이트로 위임됩니다.
    #[inline]
    fn swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let mut t: Self = *a;
        let _ = core::hint::black_box(&mut t);
        a.assign(b, choice);
        b.assign(&t, choice);
        t.zeroize();
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
// CtSelOps - end
//

//
// CtEqOps - start
//

/// 두 값의 동등 여부를 상수-시간에 판정하는 연산을 정의하는 트레이트입니다.
pub trait CtEqOps: Sealed {
    /// 자신과 `other`가 같으면 `Choice(1)`을, 다르면 `Choice(0)`을 반환하는 함수입니다.
    ///
    /// # Arguments
    /// - `other`: 비교 대상 값입니다
    fn ct_eq(&self, other: &Self) -> Choice;

    /// 자신과 `other`가 다르면 `Choice(1)`을, 같으면 `Choice(0)`을 반환하는 함수입니다.
    ///
    /// # Arguments
    /// - `other`: 비교 대상 값입니다
    #[inline]
    fn ct_ne(&self, other: &Self) -> Choice {
        !self.ct_eq(other)
    }
}

macro_rules! impl_eq_via32 {
    ($($t:ty),+) => {
        $(
            impl CtEqOps for $t {
                #[inline]
                fn ct_eq(&self, other: &Self) -> Choice {
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
                fn ct_eq(&self, other: &Self) -> Choice {
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
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice(ct_eq128(*self, *other))
    }
}

impl CtEqOps for i128 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice(ct_eq128(*self as u128, *other as u128))
    }
}

impl<T: CtEqOps + Zeroable> Sealed for Secret<T> {}

impl<T: CtEqOps, const N: usize> CtEqOps for [T; N] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.iter()
            .zip(other.iter())
            .fold(Choice::from_u8(1), |acc, (a, b)| acc & a.ct_eq(b))
    }
}

impl<T: CtEqOps + Zeroable> CtEqOps for Secret<T> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.expose().ct_eq(other.expose())
    }
}

//
// CtEqOps - end
//

//
// CtGtOps - start
//

/// 두 값의 대소를 상수-시간에 판정하는 연산을 정의하는 트레이트입니다.
pub trait CtGtOps: Sealed {
    /// 자신이 `other`보다 크면 `Choice(1)`을, 아니면 `Choice(0)`을 반환하는 함수입니다.
    ///
    /// # Arguments
    /// - `other`: 비교 대상 값입니다
    fn ct_gt(&self, other: &Self) -> Choice;
}

macro_rules! impl_gt_unsigned_via32 {
    ($($t:ty),+) => {
        $(
            impl CtGtOps for $t {
                #[inline]
                fn ct_gt(&self, other: &Self) -> Choice {
                    Choice(ct_gt_u32(*self as u32, *other as u32))
                }
            }
        )+
    };
}

macro_rules! impl_gt_unsigned_via64 {
    ($($t:ty),+) => {
        $(
            impl CtGtOps for $t {
                #[inline]
                fn ct_gt(&self, other: &Self) -> Choice {
                    Choice(ct_gt_u64(*self as u64, *other as u64))
                }
            }
        )+
    };
}

macro_rules! impl_gt_signed_via64 {
    ($($t:ty),+) => {
        $(
            impl CtGtOps for $t {
                #[inline]
                fn ct_gt(&self, other: &Self) -> Choice {
                    Choice(ct_gt_i64(*self as i64, *other as i64))
                }
            }
        )+
    };
}

impl_gt_unsigned_via32!(u8, u16, u32);
impl_gt_unsigned_via64!(u64, usize);
impl_gt_signed_via64!(i8, i16, i32, i64, isize);

impl CtGtOps for u128 {
    #[inline]
    fn ct_gt(&self, other: &Self) -> Choice {
        Choice(ct_gt_u128(*self, *other))
    }
}

impl CtGtOps for i128 {
    #[inline]
    fn ct_gt(&self, other: &Self) -> Choice {
        Choice(ct_gt_i128(*self, *other))
    }
}

//
// CtGtOps - end
//

//
// CtLess - start
//

/// 두 값의 작음 여부를 상수-시간에 판정하는 연산을 정의하는 트레이트입니다.
///
/// `CtEqOps`와 `CtGtOps`의 결과를 결합하여 기본 구현을 파생합니다.
pub trait CtLess: CtEqOps + CtGtOps {
    /// 자신이 `other`보다 작으면 `Choice(1)`을, 아니면 `Choice(0)`을 반환하는 함수입니다.
    ///
    /// # Arguments
    /// - `other`: 비교 대상 값입니다
    #[inline]
    fn ct_lt(&self, other: &Self) -> Choice {
        // !self.ct_gt(other) & !self.ct_eq(other)
        CtGtOps::ct_gt(other, self)
    }
}

// 일괄 구현으로 CtEqOps와 CtGtOps를 모두 만족하는 타입은 검증된 상수-시간
// 기본 구현으로 CtLess를 자동으로 얻습니다.
impl<T: CtEqOps + CtGtOps> CtLess for T {}

//
// CtLess - end
//
