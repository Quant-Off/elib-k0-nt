//! 비밀 데이터 래퍼 모듈입니다.
//!
//! `Secret<T>`는 민감한 데이터를 감싸고, 스코프 종료 시
//! 자동으로 메모리를 소거하는 래퍼 타입입니다.
//!
//! # Features
//! - 스코프 종료 시 자동 소거 (`Drop` 구현)
//! - `Deref`/`DerefMut`를 통한 내부 데이터 접근
//! - `into_inner`로 데이터 추출 시에도 원본 메모리 소거
//! - `Clone` 미구현으로 암시적 복제 방지
//!
//! # Examples
//! ```rust,ignore
//! use zeroize::Secret;
//!
//! fn process_key() {
//!     let key = Secret::new([0u8; 32]);
//!     // key.expose()로 내부 데이터 접근
//!     let data = key.expose();
//!     // ...
//! } // 함수 종료 시 key 자동 소거
//! ```
//!
//! # Security Note
//! - `Clone`을 구현하지 않아 암시적 복제를 방지합니다
//! - `into_inner` 호출 시 원본 메모리도 소거됩니다
//! - `Debug` 미구현으로 로깅 시 데이터 노출을 방지합니다
//!
//! # Authors
//! Q. T. Felix

use crate::barrier::{atomic_compiler_fence, black_box, compiler_barrier, memory_barrier};
use crate::zeroize::Zeroize;
use core::ops::{Deref, DerefMut};
use core::{mem, ptr};

/// 스코프 종료 시 자동 소거되는 비밀 데이터 래퍼입니다.
///
/// 내부 데이터는 `Drop` 시 휘발성 쓰기와 배리어를 통해
/// 안전하게 0으로 소거됩니다.
pub struct Secret<T> {
    inner: T,
}

impl<T> Secret<T> {
    /// 새로운 `Secret`을 생성합니다.
    ///
    /// # Arguments
    /// - `value`: 보호할 값
    #[inline]
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// 내부 데이터에 대한 불변 참조를 반환합니다.
    ///
    /// # Security Note
    /// 반환된 참조를 통해 데이터가 복사되지 않도록 주의하세요.
    #[inline]
    pub fn expose(&self) -> &T {
        &self.inner
    }

    /// 내부 데이터에 대한 가변 참조를 반환합니다.
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// 내부 데이터를 추출하고 원본 메모리를 소거합니다.
    ///
    /// 데이터를 복사한 후 원본 메모리를 안전하게 소거하고,
    /// `Drop`을 우회하여 복사본을 반환합니다.
    ///
    /// # Security Note
    /// 반환된 값은 더 이상 `Secret`의 보호를 받지 않습니다.
    /// 사용 후 직접 소거해야 합니다.
    #[inline]
    pub fn into_inner(mut self) -> T {
        let inner = unsafe { ptr::read(&self.inner) };

        compiler_barrier();
        let size = mem::size_of::<T>();
        let p = &mut self.inner as *mut T as *mut u8;
        for i in 0..size {
            unsafe {
                ptr::write_volatile(p.add(i), 0);
            }
        }
        compiler_barrier();
        atomic_compiler_fence();
        memory_barrier();
        black_box(p);

        mem::forget(self);
        inner
    }
}

impl<T> Deref for Secret<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.expose()
    }
}

impl<T> DerefMut for Secret<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.expose_mut()
    }
}

impl<T> Drop for Secret<T> {
    #[inline]
    fn drop(&mut self) {
        compiler_barrier();

        let size = mem::size_of::<T>();
        let p = &mut self.inner as *mut T as *mut u8;

        for i in 0..size {
            unsafe {
                ptr::write_volatile(p.add(i), 0);
            }
        }

        compiler_barrier();
        atomic_compiler_fence();
        memory_barrier();

        black_box(p);
    }
}

impl<T: Zeroize> Zeroize for Secret<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Default> Default for Secret<T> {
    #[inline]
    fn default() -> Self {
        Self::new(T::default())
    }
}
