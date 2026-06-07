//! x86_64 와 aarch64 inline asm 기반 상수시간 내부 프리미티브가 구현된 모듈입니다.
//!
//! 미지원 아키텍처에서는 `core::hint::black_box` 에 의존하는 best-effort
//! fallback 을 제공합니다. 모든 함수는 비밀 의존 분기나 데이터 의존 경로
//! 없이 동작하며 반환값은 항상 0 또는 1 범위로 유지됩니다.
//!
//! # Features
//! 조건에 따라 한쪽 값을 선택하는 ct_sel 계열, 동등 여부를 판정하는 ct_eq
//! 계열, 대소를 판정하는 ct_gt 계열을 32비트와 64비트 폭으로 제공합니다.
//! ct_sel 계열은 조건이 0 이 아니면 a 를, 0 이면 b 를 반환합니다. ct_eq
//! 계열은 두 값이 같으면 1 을, 다르면 0 을 반환합니다. ct_gt 계열은 a 가
//! b 보다 크면 1 을, 아니면 0 을 반환합니다. 부호 있는 비교에서 더 작은
//! 정수 타입은 호출자가 i64 로 부호 확장한 뒤 ct_gt_i64 에 전달합니다.
//! 또한 64비트 프리미티브 위에 구성된 아키텍처 독립 128비트 래퍼인
//! ct_eq128, ct_gt_u128, ct_gt_i128 을 제공합니다. x86_64 와 aarch64 에서는
//! inline asm 으로 하드웨어 수준 상수시간을 보장하고 그 외 아키텍처에서는
//! black_box 로 최적화를 억제하는 fallback 으로 동작합니다.
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

// seta 는 CF 가 0 이고 ZF 가 0 일 때 a 가 b 보다 큼을 뜻합니다 (부호 없음)
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

// setg 는 ZF 가 0 이고 SF 가 OF 와 같을 때 a 가 b 보다 큼을 뜻합니다 (부호 있음)
// 더 작은 부호 있는 타입은 호출자가 i64 로 부호 확장합니다.
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
// 확장됩니다.
//

#[cfg(all(target_arch = "aarch64", not(miri)))]
#[must_use]
#[inline]
pub(crate) fn ct_sel32(cond: u8, a: u32, b: u32) -> u32 {
    ct_sel64(cond, a as u64, b as u64) as u32
}

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

#[cfg(all(target_arch = "aarch64", not(miri)))]
#[must_use]
#[inline]
pub(crate) fn ct_eq32(a: u32, b: u32) -> u8 {
    ct_eq64(a as u64, b as u64)
}

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

// cset hi 는 C 가 1 이고 Z 가 0 일 때 a 가 b 보다 큼을 뜻합니다 (부호 없음)
#[cfg(all(target_arch = "aarch64", not(miri)))]
#[must_use]
#[inline]
pub(crate) fn ct_gt_u32(a: u32, b: u32) -> u8 {
    ct_gt_u64(a as u64, b as u64)
}

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

// cset gt 는 Z 가 0 이고 N 이 V 와 같을 때 a 가 b 보다 큼을 뜻합니다 (부호 있음)
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
// 위에서 처리하지 않은 모든 아키텍처를 위한 일반 fallback 입니다.
//
// 보안 경고: 이 일반 fallback 은 best-effort 최적화 배리어인
// `core::hint::black_box` 에 의존합니다. 미지원 아키텍처에서는 상수시간
// 성질이 보장되지 않으므로 보안이 중요한 배포 환경에서는 네이티브 어셈블리
// 구현 추가를 고려하시기 바랍니다.
//
// 하드웨어 수준 상수시간이 보장되는 아키텍처는 x86_64 와 aarch64 입니다.
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

#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[inline(never)]
pub(crate) fn ct_mask(cond: u8) -> u64 {
    let c = core::hint::black_box(cond as u64);
    core::hint::black_box(((c | c.wrapping_neg()) >> 63).wrapping_neg())
}

#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline]
pub(crate) fn ct_sel32(cond: u8, a: u32, b: u32) -> u32 {
    ct_sel64(cond, a as u64, b as u64) as u32
}

#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline(never)] // Prevent inlining to reduce optimization opportunities
pub(crate) fn ct_sel64(cond: u8, a: u64, b: u64) -> u64 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let m = ct_mask(cond);
    core::hint::black_box((m & a) | ((!m) & b))
}

#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline]
pub(crate) fn ct_eq32(a: u32, b: u32) -> u8 {
    ct_eq64(a as u64, b as u64)
}

// XOR 결과는 두 값이 같을 때만 0 이 되며 OR 시프트를 연쇄 적용해 모든
// 비트를 최하위 비트로 모읍니다.
// 두 값이 같으면 1, 아니면 0 을 반환합니다.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline(never)] // Prevent inlining to reduce optimization opportunities
pub(crate) fn ct_eq64(a: u64, b: u64) -> u8 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let diff = a ^ b;
    let s = core::hint::black_box(diff | diff.wrapping_shr(32));
    let s = core::hint::black_box(s | s.wrapping_shr(16));
    let s = core::hint::black_box(s | s.wrapping_shr(8));
    // s as u8 은 diff 에 비트가 하나라도 설정되어 있으면 0 이 아닙니다 (즉 a 가 b 와 다름)
    let byte = core::hint::black_box(s as u8);
    // ct_mask 는 byte 가 0 이 아니면 0xFF..FF 를, 0 이면 0 을 만듭니다 (a 와 b 의 동등 여부)
    let nonzero = ct_mask(byte);
    core::hint::black_box((!nonzero & 1) as u8)
}

// 빌림 검출 방식입니다. b 에서 a 를 빼면 a 가 b 보다 클 때 언더플로가 발생합니다 (부호 없음).
// 그 빌림은 64비트로 확장된 결과의 비트 32 로 전파됩니다.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline(never)] // Prevent inlining to reduce optimization opportunities
pub(crate) fn ct_gt_u32(a: u32, b: u32) -> u8 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let diff = (b as u64).wrapping_sub(a as u64);
    core::hint::black_box((diff >> 32) as u8 & 1)
}

#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline]
pub(crate) fn ct_gt_u64(a: u64, b: u64) -> u8 {
    // 32비트 플랫폼에서 비상수시간 라이브러리 호출로 컴파일될 수 있는
    // 128비트 산술을 피하고 대신 반워드 비교를 사용합니다.
    // a 가 b 보다 큰 조건은 a_hi 가 b_hi 보다 크거나 a_hi 와 b_hi 가 같고 a_lo 가 b_lo 보다 큰 경우입니다.
    let a_hi = (a >> 32) as u32;
    let a_lo = a as u32;
    let b_hi = (b >> 32) as u32;
    let b_lo = b as u32;

    let hi_gt = ct_gt_u32(a_hi, b_hi);
    let hi_eq = ct_eq32(a_hi, b_hi);
    let lo_gt = ct_gt_u32(a_lo, b_lo);

    core::hint::black_box(hi_gt | (hi_eq & lo_gt))
}

// 부호 비트 분해를 이용한 부호 있는 대소 비교입니다 (분기 없음).
// a 가 b 보다 큰 조건 (부호 있음)은 다음과 같습니다.
//   같은 부호이면서 부호 없는 비교로 a 가 b 보다 큰 경우 (2의 보수 같은 부호 비교)
//   또는 a 가 음이 아니면서 b 가 음수인 경우입니다.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[must_use]
#[inline(never)] // Prevent inlining to reduce optimization opportunities
pub(crate) fn ct_gt_i64(a: i64, b: i64) -> u8 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let a_u = a as u64;
    let b_u = b as u64;
    let a_msb = core::hint::black_box((a_u >> 63) as u8); // 1 if a < 0
    let b_msb = core::hint::black_box((b_u >> 63) as u8); // 1 if b < 0
    let u_gt = ct_gt_u64(a_u, b_u);
    let same_sign = core::hint::black_box((a_msb ^ b_msb) ^ 1); // 1 iff signs are equal
    let not_a_msb = core::hint::black_box(a_msb ^ 1); // 1 iff a >= 0
    core::hint::black_box((same_sign & u_gt) | (not_a_msb & b_msb))
}

//
// 아키텍처 독립 128비트 프리미티브입니다.
// 위의 아키텍처별 64비트 함수 위에 구성됩니다.
//

#[must_use]
#[inline]
pub(crate) fn ct_eq128(a: u128, b: u128) -> u8 {
    // 상위 절반과 하위 절반이 모두 같아야 합니다
    ct_eq64((a >> 64) as u64, (b >> 64) as u64) & ct_eq64(a as u64, b as u64)
}

#[must_use]
#[inline]
pub(crate) fn ct_gt_u128(a: u128, b: u128) -> u8 {
    // a 가 b 보다 큰 조건은 상위 절반이 다르고 a_hi 가 b_hi 보다 크거나
    // 상위 절반이 같고 a_lo 가 b_lo 보다 큰 경우입니다
    let hi_gt = ct_gt_u64((a >> 64) as u64, (b >> 64) as u64);
    let hi_eq = ct_eq64((a >> 64) as u64, (b >> 64) as u64);
    let lo_gt = ct_gt_u64(a as u64, b as u64);
    hi_gt | (hi_eq & lo_gt)
}

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
