use core::arch::asm;

#[inline(always)]
pub fn memory_barrier() {
    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn compiler_barrier() {
    unsafe {
        asm!("", options(nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn atomic_compiler_fence() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline(never)]
pub fn black_box<T>(value: T) -> T {
    unsafe {
        asm!(
            "",
            in("x0") &value,
            options(nostack, preserves_flags)
        );
        core::ptr::read_volatile(&value as *const T)
    }
}
