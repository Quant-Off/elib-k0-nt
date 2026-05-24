//! Valgrind ctgrind 검증의 self-check 용 부정(negative) probe입니다.
//!
//! 의도적으로 비밀 의존 분기 / 인덱스를 포함하여, Valgrind가 이를
//! "Conditional jump or move depends on uninitialised value(s)" 또는
//! "Use of uninitialised value of size N"으로 보고하는지 확인합니다
//!
//! 보고 = ctgrind 검증기 정확성 PASS

unsafe extern "C" {
    fn malloc(size: usize) -> *mut u8;
}

// LLVM이 read 와 후속 사용을 DCE 하지 않도록 #[inline(never)]
// 와 black_box 다중 적용함 release 빌드에서도 secret의존 분기가 보존되어
// Valgrind가 uninit 추적을 통해 보고할 수 있도록 함
#[inline(never)]
unsafe fn secret_dep_branch(secret: u32) -> u32 {
    let secret = core::hint::black_box(secret);
    // 비밀 의존 loop trip count: branchless 변환 불가
    let trips = core::hint::black_box(secret & 0x0F);
    let mut acc: u32 = 0;
    for _ in 0..trips {
        acc = core::hint::black_box(acc).wrapping_add(1);
    }
    core::hint::black_box(acc)
}

fn main() {
    unsafe {
        let p = malloc(4) as *mut u32;
        // *p 는 uninit (malloc) -> secret이 비밀로 추적됨
        let secret: u32 = core::ptr::read_volatile(p);
        let r = secret_dep_branch(secret);
        // 결과를 stdout으로 추출하여 DCE 차단
        std::process::exit(r as i32 & 0x1);
    }
}
