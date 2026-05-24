//! 상수시간 회귀 방어용 어셈블리 probe 바이너리입니다.
//!
//! # Features
//! `scripts/check_ct_asm.sh` 스크립트를 통해 사용 가능합니다.
//!
//! 각 probe는 `#[unsafe(no_mangle)] extern "C"` + `#[inline(never)]`로 standalone 심볼을
//! 강제 방출하여, release 빌드 산출물의 어셈블리에서 조건분기 명령(x86_64 `jcc`, aarch64
//! `b.cc/cbnz/cbz/tbnz/tbz`)부재를 grep 으로 검증 가능하게 합니다. swap probe는 추가로
//! volatile zero store가 살아남는지(CWE-316 회귀 방지)도 함께 검사하도록 설계됩니다.
//!
//! main 함수는 DCE 방지용 호출만 수행합니다.

use constant_time::{Choice, CtEqOps, CtGreeter, CtLess, CtSelOps};

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_choice_from_u8(v: u8) -> u8 {
    Choice::from_u8(v).unwrap_u8()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_sel_u8(c: u8, a: u8, b: u8) -> u8 {
    u8::select(&a, &b, Choice::from_u8(c))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_sel_u16(c: u8, a: u16, b: u16) -> u16 {
    u16::select(&a, &b, Choice::from_u8(c))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_sel_u32(c: u8, a: u32, b: u32) -> u32 {
    u32::select(&a, &b, Choice::from_u8(c))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_sel_u64(c: u8, a: u64, b: u64) -> u64 {
    u64::select(&a, &b, Choice::from_u8(c))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_sel_u128(c: u8, a: u128, b: u128) -> u128 {
    u128::select(&a, &b, Choice::from_u8(c))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_eq_u32(a: u32, b: u32) -> u8 {
    CtEqOps::eq(&a, &b).unwrap_u8()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_eq_u64(a: u64, b: u64) -> u8 {
    CtEqOps::eq(&a, &b).unwrap_u8()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_eq_u128(a: u128, b: u128) -> u8 {
    CtEqOps::eq(&a, &b).unwrap_u8()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_gt_u32(a: u32, b: u32) -> u8 {
    CtGreeter::gt(&a, &b).unwrap_u8()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_gt_u64(a: u64, b: u64) -> u8 {
    CtGreeter::gt(&a, &b).unwrap_u8()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_gt_i64(a: i64, b: i64) -> u8 {
    CtGreeter::gt(&a, &b).unwrap_u8()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_gt_u128(a: u128, b: u128) -> u8 {
    CtGreeter::gt(&a, &b).unwrap_u8()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_gt_i128(a: i128, b: i128) -> u8 {
    CtGreeter::gt(&a, &b).unwrap_u8()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_lt_u32(a: u32, b: u32) -> u8 {
    CtLess::lt(&a, &b).unwrap_u8()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_swap_u64(a: &mut u64, b: &mut u64, c: u8) {
    u64::swap(a, b, Choice::from_u8(c))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_swap_u128(a: &mut u128, b: &mut u128, c: u8) {
    u128::swap(a, b, Choice::from_u8(c))
}

fn main() {
    use core::hint::black_box;
    black_box(probe_choice_from_u8(black_box(0x5a)));
    black_box(probe_sel_u8(black_box(1), black_box(1), black_box(2)));
    black_box(probe_sel_u16(black_box(1), black_box(1), black_box(2)));
    black_box(probe_sel_u32(black_box(1), black_box(1), black_box(2)));
    black_box(probe_sel_u64(black_box(1), black_box(1), black_box(2)));
    black_box(probe_sel_u128(black_box(1), black_box(1), black_box(2)));
    black_box(probe_eq_u32(black_box(1), black_box(1)));
    black_box(probe_eq_u64(black_box(1), black_box(1)));
    black_box(probe_eq_u128(black_box(1), black_box(1)));
    black_box(probe_gt_u32(black_box(2), black_box(1)));
    black_box(probe_gt_u64(black_box(2), black_box(1)));
    black_box(probe_gt_i64(black_box(2), black_box(-1)));
    black_box(probe_gt_u128(black_box(2), black_box(1)));
    black_box(probe_gt_i128(black_box(2), black_box(-1)));
    black_box(probe_lt_u32(black_box(1), black_box(2)));
    let (mut a, mut b) = (1u64, 2u64);
    probe_swap_u64(&mut a, &mut b, 1);
    black_box((a, b));
    let (mut a, mut b) = (1u128, 2u128);
    probe_swap_u128(&mut a, &mut b, 1);
    black_box((a, b));
}
