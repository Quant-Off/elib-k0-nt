//! x86_64와 aarch64 인-라인 어셈블리 기반 상수-시간 내부 프리미티브가 구현된 모듈입니다.
//!
//! 미지원 아키텍처에서는 `core::hint::black_box`에 의존하는 best-effort
//! fallback을 제공합니다. 모든 함수는 비밀 의존 분기나 데이터 의존 경로
//! 없이 동작하며 반환값은 항상 0 또는 1 범위로 유지됩니다.
//!
//! # Features
//! 다음 계열별 기능을 32비트와 64비트 폭으로 제공합니다.
//!
//! - `ct_sel`: 조건에 따라 한쪽 값 선택, 조건이 0이 아니면 a를, 0이면 b를 반환
//! - `ct_eq`: 동등 여부 판정, 두 값이 같으면 1을, 다르면 0을 반환
//! - `ct_gt`: 대소 판정, a가 b보다 크면 1을, 아니면 0을 반환
//!
//! 부호 있는 비교에서 더 작은 정수 타입은 호출자가 i64 로 부호 확장한 뒤 ct_gt_i64에
//! 전달합니다. 또한 64비트 프리미티브 위에 구성된 아키텍처 독립 128비트 래퍼인
//! `ct_eq128`, `ct_gt_u128`, `ct_gt_i128`을 제공합니다. x86_64와
//! aarch64에서는 인-라인 어셈블리로 하드웨어 수준 상수-시간을 보장하고 그 외
//! 아키텍처에서는 `black_box`로 최적화를 억제하는 fallback으로 동작합니다.
//!
//! # Examples
//! ```rust,ignore
//! let chosen = ct_sel32(1, 0xAAAA_AAAA, 0x5555_5555);
//! let equal = ct_eq64(7, 7);
//! let greater = ct_gt_u32(9, 4);
//! ```
//!
//! # Authors
//! Q. T. Felix

//
// x86_64
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
#[cfg(all(target_arch = "x86_64", not(miri)))]
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

//
// aarch64
// 모든 연산을 64비트로 수행하며 32비트 타입은 호출 전에 영 확장 또는 부호
// 확장합니다
//

/// 조건이 0이 아니면 a, 0이면 b를 상수-시간에 선택하는 함수입니다.
///
/// 내부적으로 `ct_sel64`에 위임하며 인자를 64비트로 확장한 뒤 결과를 32비트로 줄입니다.
///
/// # Arguments
/// - `cond`: 0이 아니면 a를, 0이면 b를 선택하는 조건 바이트입니다
/// - `a`: 조건이 참일 때 반환되는 값입니다
/// - `b`: 조건이 거짓일 때 반환되는 값입니다
#[cfg(all(target_arch = "aarch64", not(miri)))]
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
#[cfg(all(target_arch = "aarch64", not(miri)))]
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
#[cfg(all(target_arch = "aarch64", not(miri)))]
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
#[cfg(all(target_arch = "aarch64", not(miri)))]
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
#[cfg(all(target_arch = "aarch64", not(miri)))]
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
#[cfg(all(target_arch = "aarch64", not(miri)))]
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
#[cfg(all(target_arch = "aarch64", not(miri)))]
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

//
// 위에서 처리하지 않은 모든 아키텍처를 위한 일반 fallback입니다.
//
// 보안 경고: 이 일반 fallback은 best-effort 최적화 배리어인
// `core::hint::black_box`에 의존합니다. 미지원 아키텍처에서는 상수-시간
// 성질이 보장되지 않으므로 보안이 중요한 배포 환경에서는 네이티브 어셈블리
// 구현 추가를 고려하시기 바랍니다.
//
// 하드웨어 수준 상수-시간이 보장되는 아키텍처는 x86_64와 aarch64입니다.
//

#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
const _: () = {
    #[deprecated(
        since = "0.1.0",
        note = "Constant-time guarantees are weaker on this architecture. \
                Only x86_64 and aarch64 have verified CT implementations."
    )]
    const CT_FALLBACK_WARNING: () = ();
    let _ = CT_FALLBACK_WARNING;
};

/// 조건 바이트로부터 상수-시간 비트 마스크를 생성하는 함수입니다.
///
/// 조건이 0이 아니면 모든 비트가 1인 마스크를, 0이면 0 마스크를 반환합니다.
///
/// # Arguments
/// - `cond`: 마스크 생성의 기준이 되는 조건 바이트입니다
///
/// # Security Note
/// 이 fallback 경로는 `core::hint::black_box`에 의존하는 best-effort
/// 구현이므로 상수-시간 성질이 하드웨어 수준으로 보장되지는 않습니다.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[inline(never)]
pub(crate) fn ct_mask(cond: u8) -> u64 {
    let c = core::hint::black_box(cond as u64);
    core::hint::black_box(((c | c.wrapping_neg()) >> 63).wrapping_neg())
}

/// 조건이 0이 아니면 a, 0이면 b를 상수-시간에 선택하는 함수입니다.
///
/// 내부적으로 `ct_sel64`에 위임합니다.
///
/// # Arguments
/// - `cond`: 0이 아니면 a를, 0이면 b를 선택하는 조건 바이트입니다
/// - `a`: 조건이 참일 때 반환되는 값입니다
/// - `b`: 조건이 거짓일 때 반환되는 값입니다
///
/// # Security Note
/// `black_box` 기반 best-effort fallback이므로 상수-시간 성질이 하드웨어
/// 수준으로 보장되지 않습니다.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline]
pub(crate) fn ct_sel32(cond: u8, a: u32, b: u32) -> u32 {
    ct_sel64(cond, a as u64, b as u64) as u32
}

/// 마스크 연산으로 a 또는 b를 64비트 폭으로 상수-시간에 선택하는 함수입니다.
///
/// # Arguments
/// - `cond`: 0이 아니면 a를, 0이면 b를 선택하는 조건 바이트입니다
/// - `a`: 조건이 참일 때 반환되는 값입니다
/// - `b`: 조건이 거짓일 때 반환되는 값입니다
///
/// # Security Note
/// 입력과 중간값을 `core::hint::black_box`로 감싸 최적화를 억제하는
/// best-effort fallback이므로 상수-시간 성질이 하드웨어 수준으로 보장되지
/// 않습니다.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline(never)] // 최적화 기회를 줄이기 위해 인라인을 방지합니다
pub(crate) fn ct_sel64(cond: u8, a: u64, b: u64) -> u64 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let m = ct_mask(cond);
    core::hint::black_box((m & a) | ((!m) & b))
}

/// 두 값이 같으면 1, 다르면 0을 상수-시간에 반환하는 함수입니다.
///
/// 내부적으로 `ct_eq64`에 위임합니다.
///
/// # Arguments
/// - `a`: 비교 대상 첫 번째 값입니다
/// - `b`: 비교 대상 두 번째 값입니다
///
/// # Security Note
/// `black_box` 기반 best-effort fallback이므로 상수-시간 성질이 하드웨어
/// 수준으로 보장되지 않습니다.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline]
pub(crate) fn ct_eq32(a: u32, b: u32) -> u8 {
    ct_eq64(a as u64, b as u64)
}

/// 두 값이 같으면 1, 다르면 0을 64비트 폭으로 상수-시간에 반환하는 함수입니다.
///
/// XOR 결과가 두 값이 같을 때만 0이 되는 성질을 이용합니다. OR 시프트를
/// 연쇄 적용해 모든 비트를 최하위 비트로 모은 뒤 마스크로 결과를 만듭니다.
///
/// # Arguments
/// - `a`: 비교 대상 첫 번째 값입니다
/// - `b`: 비교 대상 두 번째 값입니다
///
/// # Security Note
/// `black_box` 기반 best-effort fallback이므로 상수-시간 성질이 하드웨어
/// 수준으로 보장되지 않습니다.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline(never)] // 최적화 기회를 줄이기 위해 인라인을 방지합니다
pub(crate) fn ct_eq64(a: u64, b: u64) -> u8 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let diff = a ^ b;
    let s = core::hint::black_box(diff | diff.wrapping_shr(32));
    let s = core::hint::black_box(s | s.wrapping_shr(16));
    let s = core::hint::black_box(s | s.wrapping_shr(8));
    // `s as u8`은 `diff`에 비트가 하나라도 설정되어 있으면 0이 아닙니다 (즉 a가 b와 다름)
    let byte = core::hint::black_box(s as u8);
    // `ct_mask`는 `byte`가 0이 아니면 0xFF..FF를, 0이면 0을 만듭니다 (a와 b의 동등 여부)
    let nonzero = ct_mask(byte);
    core::hint::black_box((!nonzero & 1) as u8)
}

/// 부호 없는 두 값에 대해 a가 b보다 크면 1, 아니면 0을 상수-시간에 반환하는 함수입니다.
///
/// b에서 a를 뺄 때 a가 b보다 크면 언더플로가 발생하며 그 빌림이 64비트로
/// 확장된 결과의 비트 32로 전파되는 성질을 이용합니다.
///
/// # Arguments
/// - `a`: 큰지 비교할 첫 번째 부호 없는 값입니다
/// - `b`: 기준이 되는 두 번째 부호 없는 값입니다
///
/// # Security Note
/// `black_box` 기반 best-effort fallback이므로 상수-시간 성질이 하드웨어
/// 수준으로 보장되지 않습니다.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline(never)] // 최적화 기회를 줄이기 위해 인라인을 방지합니다
pub(crate) fn ct_gt_u32(a: u32, b: u32) -> u8 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let diff = (b as u64).wrapping_sub(a as u64);
    core::hint::black_box((diff >> 32) as u8 & 1)
}

/// 부호 없는 두 값에 대해 a가 b보다 크면 1, 아니면 0을 64비트 폭으로 상수-시간에 반환하는 함수입니다.
///
/// 32비트 플랫폼에서 비상수-시간 라이브러리 호출을 피하기 위해 128비트 산술
/// 대신 반워드 비교로 구성합니다.
///
/// # Arguments
/// - `a`: 큰지 비교할 첫 번째 부호 없는 값입니다
/// - `b`: 기준이 되는 두 번째 부호 없는 값입니다
///
/// # Security Note
/// `black_box` 기반 best-effort fallback이므로 상수-시간 성질이 하드웨어
/// 수준으로 보장되지 않습니다.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline]
pub(crate) fn ct_gt_u64(a: u64, b: u64) -> u8 {
    // 32비트 플랫폼에서 비상수-시간 라이브러리 호출로 컴파일될 수 있는
    // 128비트 산술을 피하고 대신 반워드 비교를 사용합니다.
    // a가 b보다 큰 조건은 `a_hi`가 `b_hi`보다 크거나 `a_hi`와 `b_hi`가 같고 `a_lo`가 `b_lo`보다 큰 경우입니다.
    let a_hi = (a >> 32) as u32;
    let a_lo = a as u32;
    let b_hi = (b >> 32) as u32;
    let b_lo = b as u32;

    let hi_gt = ct_gt_u32(a_hi, b_hi);
    let hi_eq = ct_eq32(a_hi, b_hi);
    let lo_gt = ct_gt_u32(a_lo, b_lo);

    core::hint::black_box(hi_gt | (hi_eq & lo_gt))
}

/// 부호 있는 두 값에 대해 a가 b보다 크면 1, 아니면 0을 상수-시간에 반환하는 함수입니다.
///
/// 부호 비트를 분해하여 분기 없이 계산합니다. 같은 부호일 때는 부호 없는
/// 대소 비교 결과를 사용하고 a가 음이 아니면서 b가 음수인 경우를 따로
/// 더합니다.
///
/// # Arguments
/// - `a`: 큰지 비교할 첫 번째 부호 있는 값입니다
/// - `b`: 기준이 되는 두 번째 부호 있는 값입니다
///
/// # Security Note
/// `black_box` 기반 best-effort fallback이므로 상수-시간 성질이 하드웨어
/// 수준으로 보장되지 않습니다.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline(never)] // 최적화 기회를 줄이기 위해 인라인을 방지합니다
pub(crate) fn ct_gt_i64(a: i64, b: i64) -> u8 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let a_u = a as u64;
    let b_u = b as u64;
    let a_msb = core::hint::black_box((a_u >> 63) as u8); // a가 음수면 1입니다
    let b_msb = core::hint::black_box((b_u >> 63) as u8); // b가 음수면 1입니다
    let u_gt = ct_gt_u64(a_u, b_u);
    let same_sign = core::hint::black_box((a_msb ^ b_msb) ^ 1); // 두 부호가 같을 때만 1입니다
    let not_a_msb = core::hint::black_box(a_msb ^ 1); // a가 0 이상일 때만 1입니다
    core::hint::black_box((same_sign & u_gt) | (not_a_msb & b_msb))
}

//
// 아키텍처 독립 128비트 프리미티브입니다.
// 위의 아키텍처별 64비트 함수 위에 구성됩니다.
//

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
    // 상위 절반과 하위 절반이 모두 같아야 합니다
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
    // a가 b보다 큰 조건은 상위 절반이 다르고 `a_hi`가 `b_hi`보다 크거나
    // 상위 절반이 같고 `a_lo`가 `b_lo`보다 큰 경우입니다
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
