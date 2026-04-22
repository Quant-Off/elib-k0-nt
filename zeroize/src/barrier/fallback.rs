//! 범용 아키텍처용 최적화 배리어입니다.
//!
//! x86_64, aarch64 외의 아키텍처에서 사용되며,
//! `core::sync::atomic` 기반의 배리어를 제공합니다.
//!
//! # Authors
//! Q. T. Felix

/// CPU 메모리 배리어를 수행합니다.
///
/// `SeqCst` 순서의 원자적 펜스를 사용하여
/// 모든 이전 메모리 연산이 완료된 후에야 이후 연산이 시작되도록 보장합니다.
#[inline(always)]
pub fn memory_barrier() {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// 컴파일러 배리어를 수행합니다.
///
/// `SeqCst` 순서의 컴파일러 펜스를 사용하여
/// 컴파일러가 이 지점을 기준으로 메모리 연산을 재배치하지 못하도록 합니다.
#[inline(always)]
pub fn compiler_barrier() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
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
/// 휘발성 읽기를 수행하여 컴파일러가 해당 값에 대한
/// 연산을 최적화하지 못하도록 합니다.
///
/// # Arguments
/// - `value`: 최적화에서 숨길 값
#[inline(never)]
pub fn black_box<T>(value: T) -> T {
    let ptr = &value as *const T;
    unsafe { core::ptr::read_volatile(ptr) }
}
