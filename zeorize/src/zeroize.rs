use crate::barrier::{atomic_compiler_fence, black_box, compiler_barrier, memory_barrier};
use crate::volatile::volatile_write;
use core::{mem, ptr};

pub trait Zeroize {
    fn zeroize(&mut self);
}

impl Zeroize for u8 {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut u8, 0) };
    }
}

impl Zeroize for u16 {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut u16, 0) };
    }
}

impl Zeroize for u32 {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut u32, 0) };
    }
}

impl Zeroize for u64 {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut u64, 0) };
    }
}

impl Zeroize for u128 {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut u128, 0) };
    }
}

impl Zeroize for usize {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut usize, 0) };
    }
}

impl Zeroize for i8 {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut i8, 0) };
    }
}

impl Zeroize for i16 {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut i16, 0) };
    }
}

impl Zeroize for i32 {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut i32, 0) };
    }
}

impl Zeroize for i64 {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut i64, 0) };
    }
}

impl Zeroize for i128 {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut i128, 0) };
    }
}

impl Zeroize for isize {
    #[inline(always)]
    fn zeroize(&mut self) {
        unsafe { volatile_write(self as *mut isize, 0) };
    }
}

impl<T: Zeroize, const N: usize> Zeroize for [T; N] {
    #[inline(always)]
    fn zeroize(&mut self) {
        for elem in self.iter_mut() {
            elem.zeroize();
        }
        atomic_compiler_fence();
        memory_barrier();
    }
}

impl<T: Zeroize> Zeroize for &mut [T] {
    #[inline(always)]
    fn zeroize(&mut self) {
        for elem in self.iter_mut() {
            elem.zeroize();
        }
        atomic_compiler_fence();
        memory_barrier();
    }
}

pub fn zeroize_flat<T>(value: &mut T) {
    compiler_barrier();

    let size = mem::size_of::<T>();
    let ptr = value as *mut T as *mut u8;

    for i in 0..size {
        unsafe {
            ptr::write_volatile(ptr.add(i), 0);
        }
    }

    compiler_barrier();
    atomic_compiler_fence();
    memory_barrier();

    black_box(ptr);
}
