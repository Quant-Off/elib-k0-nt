//! IR Taint Checker의 부정(negative) 테스트용 probe입니다.
//!
//! 의도적으로 비밀 의존 분기를 포함한 함수인 `scripts/check_ct_ir.py`
//! 가 이를 FAIL로 정확히 보고해야 검사기 자체의 정확성이 입증됩니다.

// 비밀 의존 루프 trip count
// LLVM이 branchless로 elide할 수 없는 패턴
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn negative_secret_loop_count(c: u32, data: &mut u32) {
    // c 가 비밀, 그러나 loop 종료조건이 c 에 의존 -> br i1 condition tainted
    for _ in 0..c {
        *data = data.wrapping_add(1);
        // black_box 으로 LLVM 의 trip-count constant fold 차단
        core::hint::black_box(&mut *data);
    }
}

// 비밀 의존 분기
// match-on-secret으로 jump table 강제
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn negative_secret_match(c: u8, data: &mut u32) {
    // c 의 lower 4 bit 가 분기 결정
    // LLVM이 switch instruction 으로 유지
    match c & 0x0F {
        0 => *data = core::hint::black_box(*data).wrapping_add(1),
        1 => *data = core::hint::black_box(*data).wrapping_add(2),
        2 => *data = core::hint::black_box(*data).wrapping_add(4),
        3 => *data = core::hint::black_box(*data).wrapping_add(8),
        4 => *data = core::hint::black_box(*data).wrapping_add(16),
        5 => *data = core::hint::black_box(*data).wrapping_add(32),
        6 => *data = core::hint::black_box(*data).wrapping_add(64),
        7 => *data = core::hint::black_box(*data).wrapping_add(128),
        _ => *data = core::hint::black_box(*data).wrapping_add(256),
    }
}

fn main() {
    use core::hint::black_box;
    let mut x = 0u32;
    negative_secret_loop_count(black_box(3), &mut x);
    negative_secret_match(black_box(5), &mut x);
    black_box(x);
}
