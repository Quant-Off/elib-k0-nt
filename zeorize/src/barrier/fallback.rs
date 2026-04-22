#[inline(always)]
pub fn memory_barrier() {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline(always)]
pub fn compiler_barrier() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline(always)]
pub fn atomic_compiler_fence() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline(never)]
pub fn black_box<T>(value: T) -> T {
    let ptr = &value as *const T;
    unsafe { core::ptr::read_volatile(ptr) }
}
