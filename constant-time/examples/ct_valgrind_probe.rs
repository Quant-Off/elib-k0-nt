//! Valgrind memcheck 기반 ctgrind 검증 probe입니다.
//!
//! Valgrind memcheck은 `malloc`으로 할당된 메모리를 자동으로 'undefined'
//! 로 추적합니다. 본 probe는 malloc으로 얻은 uninit 비트 위에서 CT
//! primitive를 호출하여 함수 내부에 비밀 의존 분기 / 메모리 인덱싱이
//! 발생하면 Valgrind가 "Conditional jump or move depends on uninitialised
//! value(s)" 또는 "Use of uninitialised value of size N" 로 결정론적으로
//! 보고하도록 합니다.
//!
//! client-request 매크로(VALGRIND_MAKE_MEM_UNDEFINED) 방식보다 단순하며
//! Rust inline asm 시멘틱과의 충돌이 없습니다. 실제 CT 검증력은 동일합니다.
//! (Valgrind 의 uninit 추적은 호출 그래프 전반에 cross-function 으로 적용)
//!
//! 호스트 한정: Linux x86_64 (또는 macOS/Apple Silicon의 linux/amd64
//! Docker 컨테이너)

use constant_time::{Choice, CtEqOps, CtGreeter, CtSelOps};

unsafe extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn free(ptr: *mut u8);
}

/// malloc으로 size 바이트 할당
///
/// Valgrind가 자동으로 undefined로 추적
unsafe fn alloc_secret<T>() -> *mut T {
    let p = unsafe { malloc(size_of::<T>()) };
    assert!(!p.is_null(), "malloc 실패");
    p as *mut T
}

unsafe fn drop_secret<T>(p: *mut T) {
    unsafe { free(p as *mut u8) };
}

fn main() {
    unsafe {
        // ct_eq32: 양 operand가 uninit
        let pa: *mut u32 = alloc_secret();
        let pb: *mut u32 = alloc_secret();
        let _ = core::hint::black_box(CtEqOps::eq(&*pa, &*pb));
        drop_secret(pa);
        drop_secret(pb);

        // ct_eq64
        let pa: *mut u64 = alloc_secret();
        let pb: *mut u64 = alloc_secret();
        let _ = core::hint::black_box(CtEqOps::eq(&*pa, &*pb));
        drop_secret(pa);
        drop_secret(pb);

        // ct_eq128
        let pa: *mut u128 = alloc_secret();
        let pb: *mut u128 = alloc_secret();
        let _ = core::hint::black_box(CtEqOps::eq(&*pa, &*pb));
        drop_secret(pa);
        drop_secret(pb);

        // ct_gt_u64
        let pa: *mut u64 = alloc_secret();
        let pb: *mut u64 = alloc_secret();
        let _ = core::hint::black_box(CtGreeter::gt(&*pa, &*pb));
        drop_secret(pa);
        drop_secret(pb);

        // ct_gt_i64
        let pa: *mut i64 = alloc_secret();
        let pb: *mut i64 = alloc_secret();
        let _ = core::hint::black_box(CtGreeter::gt(&*pa, &*pb));
        drop_secret(pa);
        drop_secret(pb);

        // ct_gt_u128 / i128
        let pa: *mut u128 = alloc_secret();
        let pb: *mut u128 = alloc_secret();
        let _ = core::hint::black_box(CtGreeter::gt(&*pa, &*pb));
        drop_secret(pa);
        drop_secret(pb);

        // ct_sel32: choice 도 uninit (가장 치명적임, choice가 분기에 사용되면 즉시 보고)
        let pc: *mut u8 = alloc_secret();
        let pa: *mut u32 = alloc_secret();
        let pb: *mut u32 = alloc_secret();
        let _ = core::hint::black_box(u32::select(&*pa, &*pb, Choice::from_u8(*pc)));
        drop_secret(pc);
        drop_secret(pa);
        drop_secret(pb);

        // ct_sel64 (동일)
        let pc: *mut u8 = alloc_secret();
        let pa: *mut u64 = alloc_secret();
        let pb: *mut u64 = alloc_secret();
        let _ = core::hint::black_box(u64::select(&*pa, &*pb, Choice::from_u8(*pc)));
        drop_secret(pc);
        drop_secret(pa);
        drop_secret(pb);

        // ct_sel128
        let pc: *mut u8 = alloc_secret();
        let pa: *mut u128 = alloc_secret();
        let pb: *mut u128 = alloc_secret();
        let _ = core::hint::black_box(u128::select(&*pa, &*pb, Choice::from_u8(*pc)));
        drop_secret(pc);
        drop_secret(pa);
        drop_secret(pb);

        // swap: choice와 양 mut operand 모두 uninit
        let pc: *mut u8 = alloc_secret();
        let pa: *mut u64 = alloc_secret();
        let pb: *mut u64 = alloc_secret();
        u64::swap(&mut *pa, &mut *pb, Choice::from_u8(*pc));
        let _ = core::hint::black_box((*pa, *pb));
        drop_secret(pc);
        drop_secret(pa);
        drop_secret(pb);
    }

    eprintln!(
        "ctgrind probe 완료. Valgrind 출력에 'Conditional jump' 또는 'uninitialised value' 가 없으면 PASS"
    );
}
