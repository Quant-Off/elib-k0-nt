//! 데이터 소거 트레이트 모듈입니다.
//!
//! `Zeroize` 트레이트를 통해 다양한 타입에 대한
//! 안전한 메모리 소거 기능을 제공합니다.
//!
//! # Features
//! - 기본 정수 타입 (u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize)
//! - 고정 크기 배열 `[T; N]`
//! - 가변 슬라이스 `&mut [T]`
//! - `zeroize_flat`: 임의 타입의 메모리를 바이트 단위로 소거
//!
//! # Examples
//! ```rust,ignore
//! use zeorize::Zeroize;
//!
//! let mut key: [u8; 32] = [0xAB; 32];
//! key.zeroize();
//! assert!(key.iter().all(|&b| b == 0));
//! ```
//!
//! # Authors
//! Q. T. Felix

use crate::barrier::{atomic_compiler_fence, black_box, compiler_barrier, memory_barrier};
use crate::volatile::volatile_write;
use core::{mem, ptr};

/// 데이터를 안전하게 0으로 소거하는 트레이트입니다.
///
/// 이 트레이트를 구현한 타입은 `zeroize()` 메서드를 통해
/// 메모리를 안전하게 소거할 수 있습니다.
///
/// # Security Note
/// 구현은 휘발성 쓰기와 배리어를 사용하여
/// 컴파일러 최적화로 인한 소거 생략을 방지합니다.
pub trait Zeroize {
    /// 데이터를 0으로 소거합니다.
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

/// 임의 타입의 메모리를 바이트 단위로 소거합니다.
///
/// 타입의 크기만큼 모든 바이트를 0으로 설정하며,
/// 휘발성 쓰기와 배리어를 통해 소거의 완료를 보장합니다.
///
/// # Arguments
/// - `value`: 소거할 값의 가변 참조
///
/// # Security Note
/// 이 함수는 `Zeroize` 트레이트를 구현하지 않은 타입에도
/// 사용할 수 있으나, 내부에 포인터가 있는 타입의 경우
/// 포인터가 가리키는 데이터는 소거되지 않습니다.
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
