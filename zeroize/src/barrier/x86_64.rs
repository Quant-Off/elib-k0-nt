//! x86_64 아키텍처용 최적화 배리어입니다.
//!
//! `mfence` 명령어와 인라인 어셈블리를 활용하여
//! 메모리 연산의 순서와 가시성을 보장합니다.
//!
//! # Authors
//! Q. T. Felix

use core::arch::asm;

/// CPU 메모리 배리어를 수행합니다.
///
/// `mfence` 명령어를 사용하여 모든 이전 메모리 연산이
/// 완료된 후에야 이후 연산이 시작되도록 보장합니다.
#[inline(always)]
pub fn memory_barrier() {
    unsafe {
        asm!("mfence", options(nostack, preserves_flags));
    }
}

/// 컴파일러 배리어를 수행합니다.
///
/// 빈 인라인 어셈블리로 컴파일러가 이 지점을 기준으로
/// 메모리 연산을 재배치하지 못하도록 합니다.
#[inline(always)]
pub fn compiler_barrier() {
    unsafe {
        asm!("", options(nostack, preserves_flags));
    }
}

/// 원자적 컴파일러 펜스를 수행합니다.
///
/// `SeqCst` 순서로 컴파일러 펜스를 설정하여
/// 모든 메모리 연산의 순서를 보장합니다.
#[inline(always)]
pub fn atomic_compiler_fence() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// 값을 최적화에서 숨깁니다.
///
/// 값의 주소를 레지스터에 강제 로드하고 휘발성 읽기를 수행하여
/// 컴파일러가 해당 값에 대한 연산을 최적화하지 못하도록 합니다.
///
/// # Arguments
/// - `value`: 최적화에서 숨길 값
#[inline(never)]
pub fn black_box<T>(value: T) -> T {
    unsafe {
        asm!(
            "",
            in("rax") &value,
            options(nostack, preserves_flags)
        );
        core::ptr::read_volatile(&value as *const T)
    }
}
