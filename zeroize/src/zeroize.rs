//! 데이터 소거 트레이트 모듈입니다.
//!
//! `Zeroize` 트레이트를 통해 다양한 타입에 대한
//! 안전한 메모리 소거 기능을 제공합니다.
//!
//! # Features
//! - 기본 정수 타입 (u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize)
//! - 고정 크기 배열 `[T; N]`
//! - 가변 슬라이스 `&mut [T]`
//! - `Zeroable`: all-zero 비트 패턴이 유효한 타입 표시 마커
//! - `zeroize_flat`: `Zeroable` 타입의 메모리를 바이트 단위로 소거
//!
//! # Examples
//! ```rust,ignore
//! use zeroize::Zeroize;
//!
//! let mut key: [u8; 32] = [0xAB; 32];
//! key.zeroize();
//! assert!(key.iter().all(|&b| b == 0));
//! ```

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

/// all-zero 바이트 패턴이 유효한 값인 타입을 표시하는 마커 트레이트입니다.
///
/// `Secret<T>`의 `Drop`과 `zeroize_flat`은 타입 구조를 무시하고 메모리를
/// 바이트 단위로 0으로 덮어쓰므로, 이 트레이트가 구현된 타입에만 허용됩니다.
///
/// # Safety
/// 모든 바이트가 0인 비트 패턴이 해당 타입의 유효한 값이어야 하며,
/// 타입이 소유권 있는 간접 참조(힙 포인터 등)를 포함하지 않아야 합니다.
/// `NonZeroU32`처럼 0이 invalid value인 타입이나 `Box`처럼 널이 될 수 없는
/// 포인터 타입에 구현하면 소거 시점에 UB가 발생합니다.
pub unsafe trait Zeroable {}

unsafe impl Zeroable for u8 {}
unsafe impl Zeroable for u16 {}
unsafe impl Zeroable for u32 {}
unsafe impl Zeroable for u64 {}
unsafe impl Zeroable for u128 {}
unsafe impl Zeroable for usize {}
unsafe impl Zeroable for i8 {}
unsafe impl Zeroable for i16 {}
unsafe impl Zeroable for i32 {}
unsafe impl Zeroable for i64 {}
unsafe impl Zeroable for i128 {}
unsafe impl Zeroable for isize {}
unsafe impl<T: Zeroable, const N: usize> Zeroable for [T; N] {}

/// 타입의 메모리를 바이트 단위로 소거합니다.
///
/// 타입의 크기만큼 모든 바이트를 0으로 설정하며,
/// 휘발성 쓰기와 배리어를 통해 소거의 완료를 보장합니다.
///
/// # Arguments
/// - `value`: 소거할 값의 가변 참조
///
/// # Security Note
/// `T: Zeroable` 바운드가 all-zero 가 invalid value 인 타입 (`NonZeroU32`,
/// `Box` 등) 의 소거를 컴파일타임에 차단하여 validity invariant 위반과
/// use-after-free 를 방지합니다.
pub fn zeroize_flat<T: Zeroable>(value: &mut T) {
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
