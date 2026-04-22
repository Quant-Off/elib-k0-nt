use crate::barrier::{atomic_compiler_fence, black_box, compiler_barrier, memory_barrier};
use crate::zeroize::Zeroize;
use core::ops::{Deref, DerefMut};
use core::{mem, ptr};

pub struct Secret<T> {
    inner: T,
}

impl<T> Secret<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    #[inline]
    pub fn expose(&self) -> &T {
        &self.inner
    }

    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.inner
    }

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
