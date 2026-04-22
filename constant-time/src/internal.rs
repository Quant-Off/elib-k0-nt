//
// Internal CT primitives — all return values strictly in {0, 1}.
// No branches, no data-dependent paths.
//
// ct_sel32 / ct_sel64 : returns `a` if `cond != 0`, else `b`.
// ct_eq32  / ct_eq64  : 1 iff a == b, else 0.
// ct_gt_u32 / ct_gt_u64 : 1 iff a > b (unsigned), else 0.
// ct_gt_i64             : 1 iff a > b (signed),   else 0.
//   — smaller signed types (i8/i16/i32/i64/isize) are sign-extended
//     to i64 before calling ct_gt_i64.
// ct_eq128 / ct_gt_u128 / ct_gt_i128 : architecture-independent 128-bit
//   wrappers built on top of the 64-bit primitives above.
//

//
// x86_64
//

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
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

// seta: CF=0 AND ZF=0  ->  a > b (unsigned)
#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
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

// setg: ZF=0 AND SF=OF  ->  a > b (signed)
// Smaller signed types are sign-extended to i64 by the caller.
#[cfg(target_arch = "x86_64")]
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
// aarch64  —  64-bit operations throughout; 32-bit types are zero- or
//             sign-extended before the call.
//

#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub(crate) fn ct_sel32(cond: u8, a: u32, b: u32) -> u32 {
    ct_sel64(cond, a as u64, b as u64) as u32
}

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub(crate) fn ct_eq32(a: u32, b: u32) -> u8 {
    ct_eq64(a as u64, b as u64)
}

#[cfg(target_arch = "aarch64")]
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

// cset hi: C=1 AND Z=0  ->  a > b (unsigned)
#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub(crate) fn ct_gt_u32(a: u32, b: u32) -> u8 {
    ct_gt_u64(a as u64, b as u64)
}

#[cfg(target_arch = "aarch64")]
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

// cset gt: Z=0 AND N=V  ->  a > b (signed)
#[cfg(target_arch = "aarch64")]
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
// Generic fallback (any architecture not handled above)
//
// SECURITY WARNING: The generic fallback relies on `core::hint::black_box`
// which is a best-effort optimization barrier. Constant-time properties
// are NOT guaranteed on unsupported architectures. Consider adding native
// assembly implementations for security-critical deployments.
//
// Supported architectures with hardware CT guarantees: x86_64, aarch64
//

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const _: () = {
    #[deprecated(
        since = "0.1.0",
        note = "Constant-time guarantees are weaker on this architecture. \
                Only x86_64 and aarch64 have verified CT implementations."
    )]
    const CT_FALLBACK_WARNING: () = ();
    let _ = CT_FALLBACK_WARNING;
};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(never)]
pub(crate) fn ct_mask(cond: u8) -> u64 {
    let c = core::hint::black_box(cond as u64);
    core::hint::black_box(((c | c.wrapping_neg()) >> 63).wrapping_neg())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline]
pub(crate) fn ct_sel32(cond: u8, a: u32, b: u32) -> u32 {
    ct_sel64(cond, a as u64, b as u64) as u32
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline(never)] // Prevent inlining to reduce optimization opportunities
pub(crate) fn ct_sel64(cond: u8, a: u64, b: u64) -> u64 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let m = ct_mask(cond);
    core::hint::black_box((m & a) | ((!m) & b))
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline]
pub(crate) fn ct_eq32(a: u32, b: u32) -> u8 {
    ct_eq64(a as u64, b as u64)
}

// XOR -> 0 iff equal; fold all bits into the LSB via cascading OR-shifts.
// Result is 1 if a == b, else 0.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline(never)] // Prevent inlining to reduce optimization opportunities
pub(crate) fn ct_eq64(a: u64, b: u64) -> u8 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let diff = a ^ b;
    let s = core::hint::black_box(diff | diff.wrapping_shr(32));
    let s = core::hint::black_box(s | s.wrapping_shr(16));
    let s = core::hint::black_box(s | s.wrapping_shr(8));
    // s as u8 is nonzero iff any bit in diff is set (i.e., a != b)
    let byte = core::hint::black_box(s as u8);
    // ct_mask: 0xFF..FF if byte != 0 (a != b), 0 if byte == 0 (a == b)
    let nonzero = ct_mask(byte);
    core::hint::black_box((!nonzero & 1) as u8)
}

// Borrow detection: b - a underflows iff a > b (unsigned).
// The borrow propagates into bit 32 of the widened 64-bit result.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline(never)] // Prevent inlining to reduce optimization opportunities
pub(crate) fn ct_gt_u32(a: u32, b: u32) -> u8 {
    let a = core::hint::black_box(a);
    let b = core::hint::black_box(b);
    let diff = (b as u64).wrapping_sub(a as u64);
    core::hint::black_box((diff >> 32) as u8 & 1)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline]
pub(crate) fn ct_gt_u64(a: u64, b: u64) -> u8 {
    // Avoid 128-bit arithmetic which may compile to non-CT library calls
    // on 32-bit platforms. Use half-word comparison instead:
    //   a > b iff (a_hi > b_hi) OR (a_hi == b_hi AND a_lo > b_lo)
    let a_hi = (a >> 32) as u32;
    let a_lo = a as u32;
    let b_hi = (b >> 32) as u32;
    let b_lo = b as u32;

    let hi_gt = ct_gt_u32(a_hi, b_hi);
    let hi_eq = ct_eq32(a_hi, b_hi);
    let lo_gt = ct_gt_u32(a_lo, b_lo);

    core::hint::black_box(hi_gt | (hi_eq & lo_gt))
}

// Signed gt via sign-bit decomposition (no branches):
//   a > b (signed) iff
//     (same_sign AND a >_unsigned b)   — two's complement same-sign comparison
//     OR (a is non-negative AND b is negative)
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
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
// Architecture-independent 128-bit primitives
// Built from the arch-specific 64-bit functions above.
//

#[must_use]
#[inline]
pub(crate) fn ct_eq128(a: u128, b: u128) -> u8 {
    // Both halves must be equal
    ct_eq64((a >> 64) as u64, (b >> 64) as u64) & ct_eq64(a as u64, b as u64)
}

#[must_use]
#[inline]
pub(crate) fn ct_gt_u128(a: u128, b: u128) -> u8 {
    // a > b iff the high halves differ and a_hi > b_hi
    // or the high halves are equal and a_lo > b_lo
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
