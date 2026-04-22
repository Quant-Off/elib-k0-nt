use crate::barrier::{atomic_compiler_fence, compiler_barrier, memory_barrier};
use core::ptr;

/// # Safety
/// `dest`는 유효하고 정렬된 포인터여야 함
#[inline(always)]
pub unsafe fn volatile_write<T: Copy>(dest: *mut T, value: T) {
    compiler_barrier();
    unsafe {
        ptr::write_volatile(dest, value);
    }
    compiler_barrier();
}

/// # Safety
/// `dest`는 `count` 바이트 이상의 유효한 메모리를 가리켜야 함
#[inline(always)]
pub unsafe fn volatile_set(dest: *mut u8, value: u8, count: usize) {
    compiler_barrier();

    for i in 0..count {
        unsafe {
            ptr::write_volatile(dest.add(i), value);
        }
    }

    compiler_barrier();
    atomic_compiler_fence();
    memory_barrier();
}

/// # Safety
/// `dest`는 `count` 바이트 이상의 유효한 메모리를 가리켜야 함
#[inline(always)]
pub unsafe fn secure_zero(dest: *mut u8, count: usize) {
    unsafe {
        volatile_set(dest, 0, count);
    }
}
