//
// AArch64 아키텍처에서 사용되는 내부 함수 모듈입니다.
//
// 모든 연산을 64비트로 수행하며 32비트 타입은 호출 전에 영 확장 또는 부호
// 확장합니다.
//

/// 조건이 0이 아니면 a, 0이면 b를 상수-시간에 선택하는 함수입니다.
///
/// 내부적으로 `ct_sel64`에 위임하며 인자를 64비트로 확장한 뒤 결과를 32비트로 줄입니다.
///
/// # Arguments
/// - `cond`: 0이 아니면 a를, 0이면 b를 선택하는 조건 바이트입니다
/// - `a`: 조건이 참일 때 반환되는 값입니다
/// - `b`: 조건이 거짓일 때 반환되는 값입니다
#[must_use]
#[inline]
pub(crate) fn ct_sel32(cond: u8, a: u32, b: u32) -> u32 {
    ct_sel64(cond, a as u64, b as u64) as u32
}

/// 조건이 0이 아니면 a, 0이면 b를 64비트 폭으로 상수-시간에 선택하는 함수입니다.
///
/// # Arguments
/// - `cond`: 0이 아니면 a를, 0이면 b를 선택하는 조건 바이트입니다
/// - `a`: 조건이 참일 때 반환되는 값입니다
/// - `b`: 조건이 거짓일 때 반환되는 값입니다
///
/// # Safety
/// `cmp`와 `csel` 명령만 사용하며 `nomem`으로 메모리에 접근하지 않고
/// `nostack`으로 스택을 사용하지 않습니다. 피연산자는 레지스터 전용이고 비밀
/// 의존 분기가 없으므로 상수-시간 성질이 유지됩니다.
#[must_use]
#[inline]
pub(crate) fn ct_sel64(cond: u8, a: u64, b: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
        "cmp {c:w}, #0",
        "csel {r}, {a}, {b}, ne",
        c = in(reg)  cond as u64,
        a = in(reg)  a,
        b = in(reg)  b,
        r = out(reg) result,
        options(nomem, nostack),
        );
    }
    result
}

/// 두 값이 같으면 1, 다르면 0을 상수-시간에 반환하는 함수입니다.
///
/// 내부적으로 `ct_eq64`에 위임하며 인자를 64비트로 확장한 뒤 비교합니다.
///
/// # Arguments
/// - `a`: 비교 대상 첫 번째 값입니다
/// - `b`: 비교 대상 두 번째 값입니다
#[must_use]
#[inline]
pub(crate) fn ct_eq32(a: u32, b: u32) -> u8 {
    ct_eq64(a as u64, b as u64)
}

/// 두 값이 같으면 1, 다르면 0을 64비트 폭으로 상수-시간에 반환하는 함수입니다.
///
/// # Arguments
/// - `a`: 비교 대상 첫 번째 값입니다
/// - `b`: 비교 대상 두 번째 값입니다
///
/// # Safety
/// `cmp`와 `cset eq` 명령만 사용하며 `nomem`으로 메모리에 접근하지 않고
/// `nostack`으로 스택을 사용하지 않습니다. 피연산자는 레지스터 전용이고 비밀
/// 의존 분기가 없습니다.
#[must_use]
#[inline]
pub(crate) fn ct_eq64(a: u64, b: u64) -> u8 {
    let result: u64;
    unsafe {
        core::arch::asm!(
        "cmp {a}, {b}",
        "cset {r}, eq",
        a = in(reg)  a,
        b = in(reg)  b,
        r = out(reg) result,
        options(nomem, nostack),
        );
    }
    result as u8
}

/// 부호 없는 두 값에 대해 a가 b보다 크면 1, 아니면 0을 상수-시간에 반환하는 함수입니다.
///
/// 내부적으로 `ct_gt_u64`에 위임하며 인자를 64비트로 확장한 뒤 비교합니다.
///
/// # Arguments
/// - `a`: 큰지 비교할 첫 번째 부호 없는 값입니다
/// - `b`: 기준이 되는 두 번째 부호 없는 값입니다
#[must_use]
#[inline]
pub(crate) fn ct_gt_u32(a: u32, b: u32) -> u8 {
    ct_gt_u64(a as u64, b as u64)
}

/// 부호 없는 두 값에 대해 a가 b보다 크면 1, 아니면 0을 64비트 폭으로 상수-시간에 반환하는 함수입니다.
///
/// # Arguments
/// - `a`: 큰지 비교할 첫 번째 부호 없는 값입니다
/// - `b`: 기준이 되는 두 번째 부호 없는 값입니다
///
/// # Safety
/// `cmp`와 `cset hi` 명령만 사용합니다. `cset hi` 는 C가 1이고 Z가 0일 때 1을
/// 기록하므로 a가 b보다 큰 부호 없는 비교 결과를 나타냅니다. `nomem`으로
/// 메모리에 접근하지 않고 `nostack`으로 스택을 사용하지 않으며 피연산자는
/// 레지스터 전용이고 비밀 의존 분기가 없습니다.
#[must_use]
#[inline]
pub(crate) fn ct_gt_u64(a: u64, b: u64) -> u8 {
    let result: u64;
    unsafe {
        core::arch::asm!(
        "cmp {a}, {b}",
        "cset {r}, hi",
        a = in(reg)  a,
        b = in(reg)  b,
        r = out(reg) result,
        options(nomem, nostack),
        );
    }
    result as u8
}

/// 부호 있는 두 값에 대해 a가 b보다 크면 1, 아니면 0을 상수-시간에 반환하는 함수입니다.
///
/// # Arguments
/// - `a`: 큰지 비교할 첫 번째 부호 있는 값입니다
/// - `b`: 기준이 되는 두 번째 부호 있는 값입니다
///
/// # Safety
/// `cmp`와 `cset gt` 명령만 사용합니다. `cset gt` 는 Z가 0이고 N이 V와 같을 때
/// 1을 기록하므로 a가 b보다 큰 부호 있는 비교 결과를 나타냅니다. `nomem`으로
/// 메모리에 접근하지 않고 `nostack`으로 스택을 사용하지 않으며 피연산자는
/// 레지스터 전용이고 비밀 의존 분기가 없습니다.
#[must_use]
#[inline]
pub(crate) fn ct_gt_i64(a: i64, b: i64) -> u8 {
    let result: u64;
    unsafe {
        core::arch::asm!(
        "cmp {a}, {b}",
        "cset {r}, gt",
        a = in(reg)  a,
        b = in(reg)  b,
        r = out(reg) result,
        options(nomem, nostack),
        );
    }
    result as u8
}
