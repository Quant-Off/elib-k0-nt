//! 아키텍처 독립 128비트 프리미티브를 제공하는 모듈입니다.
//!
//! 아키텍처별 64비트 함수 위에 구성됩니다.

use crate::internal::{ct_eq64, ct_gt_u64};

/// 128비트 두 값이 같으면 1, 다르면 0을 상수-시간에 반환하는 함수입니다.
///
/// 상위 64비트와 하위 64비트를 각각 `ct_eq64`로 비교한 결과를 결합합니다.
///
/// # Arguments
/// - `a`: 비교 대상 첫 번째 128비트 값입니다
/// - `b`: 비교 대상 두 번째 128비트 값입니다
#[must_use]
#[inline]
pub(crate) fn ct_eq128(a: u128, b: u128) -> u8 {
    ct_eq64((a >> 64) as u64, (b >> 64) as u64) & ct_eq64(a as u64, b as u64)
}

/// 부호 없는 128비트 두 값에 대해 a가 b보다 크면 1, 아니면 0을 상수-시간에 반환하는 함수입니다.
///
/// 64비트 프리미티브 위에 구성되며 상위 절반과 하위 절반을 단계적으로 비교합니다.
///
/// # Arguments
/// - `a`: 큰지 비교할 첫 번째 부호 없는 128비트 값입니다
/// - `b`: 기준이 되는 두 번째 부호 없는 128비트 값입니다
#[must_use]
#[inline]
pub(crate) fn ct_gt_u128(a: u128, b: u128) -> u8 {
    let hi_gt = ct_gt_u64((a >> 64) as u64, (b >> 64) as u64);
    let hi_eq = ct_eq64((a >> 64) as u64, (b >> 64) as u64);
    let lo_gt = ct_gt_u64(a as u64, b as u64);
    hi_gt | (hi_eq & lo_gt)
}

/// 부호 있는 128비트 두 값에 대해 a가 b보다 크면 1, 아니면 0을 상수-시간에 반환하는 함수입니다.
///
/// 64비트 프리미티브 위에 구성되며 부호 비트를 분해해 분기 없이 계산합니다.
///
/// # Arguments
/// - `a`: 큰지 비교할 첫 번째 부호 있는 128비트 값입니다
/// - `b`: 기준이 되는 두 번째 부호 있는 128비트 값입니다
#[must_use]
#[inline]
pub(crate) fn ct_gt_i128(a: i128, b: i128) -> u8 {
    let a_u = a as u128;
    let b_u = b as u128;
    let a_msb = (a_u >> 127) as u8;
    let b_msb = (b_u >> 127) as u8;
    let u_gt = ct_gt_u128(a_u, b_u);
    let same_sign = (a_msb ^ b_msb) ^ 1;
    let not_a_msb = a_msb ^ 1;
    (same_sign & u_gt) | (not_a_msb & b_msb)
}
