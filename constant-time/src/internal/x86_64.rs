//
// x86_64 아키텍처에서 사용되는 내부 함수 모듈입니다.
//

/// 조건이 0이 아니면 a, 0이면 b를 상수-시간에 선택하는 함수입니다.
///
/// # Arguments
/// - `cond`: 0이 아니면 a를, 0이면 b를 선택하는 조건 바이트입니다
/// - `a`: 조건이 참일 때 반환되는 값입니다
/// - `b`: 조건이 거짓일 때 반환되는 값입니다
///
/// # Safety
/// `test`와 `cmovnz` 명령만 사용하며 `nomem` 옵션으로 메모리에 접근하지 않고
/// `nostack` 옵션으로 스택을 사용하지 않습니다. 피연산자는 레지스터 전용이고
/// 비밀 의존 분기가 없으므로 상수-시간 성질이 유지됩니다.
#[must_use]
#[inline]
pub(crate) fn ct_sel32(cond: u8, a: u32, b: u32) -> u32 {
    let result: u32;
    unsafe {
        core::arch::asm!(
        "test {c:e}, {c:e}",
        "cmovnz {r:e}, {a:e}",
        c = in(reg)    cond as u32,
        a = in(reg)    a,
        r = inout(reg) b => result,
        options(nomem, nostack),
        );
    }
    result
}

/// 조건이 0이 아니면 a, 0이면 b를 64비트 폭으로 상수-시간에 선택하는 함수입니다.
///
/// # Arguments
/// - `cond`: 0이 아니면 a를, 0이면 b를 선택하는 조건 바이트입니다
/// - `a`: 조건이 참일 때 반환되는 값입니다
/// - `b`: 조건이 거짓일 때 반환되는 값입니다
///
/// # Safety
/// `test`와 `cmovnz` 명령만 사용하며 `nomem`으로 메모리에 접근하지 않고
/// `nostack`으로 스택을 사용하지 않습니다. 피연산자는 레지스터 전용이고 비밀
/// 의존 분기가 없습니다.
#[cfg(all(target_arch = "x86_64", not(miri)))]
#[must_use]
#[inline]
pub(crate) fn ct_sel64(cond: u8, a: u64, b: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
        "test {c:e}, {c:e}",
        "cmovnz {r}, {a}",
        c = in(reg)    cond as u32,
        a = in(reg)    a,
        r = inout(reg) b => result,
        options(nomem, nostack),
        );
    }
    result
}

/// 두 값이 같으면 1, 다르면 0을 상수-시간에 반환하는 함수입니다.
///
/// # Arguments
/// - `a`: 비교 대상 첫 번째 값입니다
/// - `b`: 비교 대상 두 번째 값입니다
///
/// # Safety
/// `cmp` 와 `sete` 명령만 사용하며 `nomem`으로 메모리에 접근하지 않고
/// `nostack`으로 스택을 사용하지 않습니다. 피연산자는 레지스터 전용이고 비밀 의존
/// 분기가 없습니다.
#[cfg(all(target_arch = "x86_64", not(miri)))]
#[must_use]
#[inline]
pub(crate) fn ct_eq32(a: u32, b: u32) -> u8 {
    let result: u8;
    unsafe {
        core::arch::asm!(
        "cmp {a:e}, {b:e}",
        "sete {r}",
        a = in(reg)       a,
        b = in(reg)       b,
        r = out(reg_byte) result,
        options(nomem, nostack),
        );
    }
    result
}

/// 두 값이 같으면 1, 다르면 0을 64비트 폭으로 상수-시간에 반환하는 함수입니다.
///
/// # Arguments
/// - `a`: 비교 대상 첫 번째 값입니다
/// - `b`: 비교 대상 두 번째 값입니다
///
/// # Safety
/// `cmp` 와 `sete` 명령만 사용하며 `nomem`으로 메모리에 접근하지 않고
/// `nostack`으로 스택을 사용하지 않습니다. 피연산자는 레지스터 전용이고 비밀 의존
/// 분기가 없습니다.
#[cfg(all(target_arch = "x86_64", not(miri)))]
#[must_use]
#[inline]
pub(crate) fn ct_eq64(a: u64, b: u64) -> u8 {
    let result: u8;
    unsafe {
        core::arch::asm!(
        "cmp {a}, {b}",
        "sete {r}",
        a = in(reg)       a,
        b = in(reg)       b,
        r = out(reg_byte) result,
        options(nomem, nostack),
        );
    }
    result
}

/// 부호 없는 두 값에 대해 a가 b보다 크면 1, 아니면 0을 상수-시간에 반환하는 함수입니다.
///
/// # Arguments
/// - `a`: 큰지 비교할 첫 번째 부호 없는 값입니다
/// - `b`: 기준이 되는 두 번째 부호 없는 값입니다
///
/// # Safety
/// `cmp`와 `seta` 명령만 사용합니다. `seta` 는 CF가 0이고 ZF가 0일 때 1을
/// 기록하므로 a가 b보다 큰 부호 없는 비교 결과를 나타냅니다. `nomem`으로
/// 메모리에 접근하지 않고 `nostack`으로 스택을 사용하지 않으며 피연산자는
/// 레지스터 전용이고 비밀 의존 분기가 없습니다.
#[cfg(all(target_arch = "x86_64", not(miri)))]
#[must_use]
#[inline]
pub(crate) fn ct_gt_u32(a: u32, b: u32) -> u8 {
    let result: u8;
    unsafe {
        core::arch::asm!(
        "cmp {a:e}, {b:e}",
        "seta {r}",
        a = in(reg)       a,
        b = in(reg)       b,
        r = out(reg_byte) result,
        options(nomem, nostack),
        );
    }
    result
}

/// 부호 없는 두 값에 대해 a가 b보다 크면 1, 아니면 0을 64비트 폭으로 상수-시간에 반환하는 함수입니다.
///
/// # Arguments
/// - `a`: 큰지 비교할 첫 번째 부호 없는 값입니다
/// - `b`: 기준이 되는 두 번째 부호 없는 값입니다
///
/// # Safety
/// `cmp` 와 `seta` 명령만 사용합니다. `seta` 는 CF가 0이고 ZF가 0일 때 1을
/// 기록하므로 a가 b보다 큰 부호 없는 비교 결과를 나타냅니다. `nomem`으로
/// 메모리에 접근하지 않고 `nostack`으로 스택을 사용하지 않으며 피연산자는
/// 레지스터 전용이고 비밀 의존 분기가 없습니다.
#[cfg(all(target_arch = "x86_64", not(miri)))]
#[must_use]
#[inline]
pub(crate) fn ct_gt_u64(a: u64, b: u64) -> u8 {
    let result: u8;
    unsafe {
        core::arch::asm!(
        "cmp {a}, {b}",
        "seta {r}",
        a = in(reg)       a,
        b = in(reg)       b,
        r = out(reg_byte) result,
        options(nomem, nostack),
        );
    }
    result
}

/// 부호 있는 두 값에 대해 a가 b보다 크면 1, 아니면 0을 상수-시간에 반환하는 함수입니다.
///
/// 더 작은 부호 있는 타입은 호출자가 i64로 부호 확장한 뒤 전달합니다.
///
/// # Arguments
/// - `a`: 큰지 비교할 첫 번째 부호 있는 값입니다
/// - `b`: 기준이 되는 두 번째 부호 있는 값입니다
///
/// # Safety
/// `cmp` 와 `setg` 명령만 사용합니다. `setg` 는 ZF가 0이고 SF가 OF와 같을 때
/// 1을 기록하므로 a가 b보다 큰 부호 있는 비교 결과를 나타냅니다. `nomem`
/// 으로 메모리에 접근하지 않고 `nostack`으로 스택을 사용하지 않으며 피연산자는
/// 레지스터 전용이고 비밀 의존 분기가 없습니다.
#[cfg(all(target_arch = "x86_64", not(miri)))]
#[must_use]
#[inline]
pub(crate) fn ct_gt_i64(a: i64, b: i64) -> u8 {
    let result: u8;
    unsafe {
        core::arch::asm!(
        "cmp {a}, {b}",
        "setg {r}",
        a = in(reg)       a,
        b = in(reg)       b,
        r = out(reg_byte) result,
        options(nomem, nostack),
        );
    }
    result
}
