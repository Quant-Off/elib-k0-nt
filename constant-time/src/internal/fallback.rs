//
// 다른 아키텍처에 의해 처리되지 않는 모든 아키텍처를 위한 일반 fallback 모듈입니다. 이 모듈은 다음의 보안 게이트를
// 형성합니다.
//
// 이 일반 fallback은 best-effort 최적화 배리어인 `core::hint::black_box`에 의존하므로 하드웨어
// 수준 상수-시간을 보장하지 않습니다. 검증된 인-라인 어셈블리 구현이 있는 x86_64와 aarch64만 지원 타겟으로
// 확정하고, 그 외 아키텍처의 비 miri 빌드는 아래 `compile_error!`로 컴파일 단계에서 거부하여 best-
// effort 경로가 고보안 빌드에 섞이지 않도록 합니다. miri는 인-라인 어셈블리를 실행하지 못하므로 fallback
// 로직 검증을 위해 예외로 둡니다.
//

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
#[must_use]
#[inline(never)]
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
#[must_use]
#[inline(never)]
pub(crate) fn ct_eq64(a: u64, b: u64) -> u8 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let diff = a ^ b;
    let s = core::hint::black_box(diff | diff.wrapping_shr(32));
    let s = core::hint::black_box(s | s.wrapping_shr(16));
    let s = core::hint::black_box(s | s.wrapping_shr(8));
    // `s as u8`은 `diff`에 비트가 하나라도 설정되어 있으면 0이 아님(즉 a가 b와 다름)
    let byte = core::hint::black_box(s as u8);
    // `ct_mask`는 `byte`가 0이 아니면 0xFF..FF를, 0이면 0을 만듦(a와 b의 동등 여부)
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
#[must_use]
#[inline(never)]
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
#[must_use]
#[inline(never)]
pub(crate) fn ct_gt_u64(a: u64, b: u64) -> u8 {
    // 32비트 플랫폼에서 비상수-시간 라이브러리 호출로 컴파일될 수 있는
    // 128비트 산술을 피하고 대신 반워드 비교 사용
    // a가 b보다 큰 조건은 `a_hi`가 `b_hi`보다 크거나 `a_hi`와 `b_hi`가 같고 `a_lo`가 `b_lo`보다 큰 경우임
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
#[must_use]
#[inline(never)] // 최적화 기회를 줄이기 위해 인라인을 방지합니다
pub(crate) fn ct_gt_i64(a: i64, b: i64) -> u8 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let a_u = a as u64;
    let b_u = b as u64;
    let a_msb = core::hint::black_box((a_u >> 63) as u8); // a가 음수면 1
    let b_msb = core::hint::black_box((b_u >> 63) as u8); // b가 음수면 1
    let u_gt = ct_gt_u64(a_u, b_u);
    let same_sign = core::hint::black_box((a_msb ^ b_msb) ^ 1); // 두 부호가 같을 때만 1
    let not_a_msb = core::hint::black_box(a_msb ^ 1); // a가 0 이상일 때만 1
    core::hint::black_box((same_sign & u_gt) | (not_a_msb & b_msb))
}
