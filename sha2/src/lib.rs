#![no_std]

mod sha2_256;
mod sha2_512;

use core::sync::atomic::{Ordering, compiler_fence};
use zeroize::volatile::volatile_write;
use zeroize::{Secret, Zeroize};

pub trait SHA2: Sized {
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Digest;
}

//
// Digest
// Fixed-size container for the output of a SHA-2 hash
// Zeroizes itself on drop so digest material does not linger in memory
//

pub struct Digest {
    bytes: Secret<[u8; 64]>,
    len: usize, // 28/32 (SHA-256 family) or 48/64 (SHA-512 family)
}

impl Digest {
    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Zeroize for Digest {
    #[inline(always)]
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

//
// SHA256State
// Internal mutable state shared by SHA-256 and SHA-224
// Zeroizes all sensitive fields on drop
//

pub(crate) struct SHA256State {
    pub(crate) state: Secret<[u32; 8]>,
    pub(crate) buffer: Secret<[u8; 64]>,
    pub(crate) buffer_len: usize,
    pub(crate) total_len: u64,
    pub(crate) is_224: bool,
}

impl Zeroize for SHA256State {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
    }
}

impl Drop for SHA256State {
    fn drop(&mut self) {
        unsafe {
            volatile_write(&mut self.total_len, 0);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

//
// SHA512State
// Internal mutable state shared by SHA-384 and SHA-512
// Zeroizes all sensitive fields on drop
//

pub(crate) struct SHA512State {
    pub(crate) state: Secret<[u64; 8]>,
    pub(crate) buffer: Secret<[u8; 128]>,
    pub(crate) buffer_len: usize,
    pub(crate) total_len: u64,
    pub(crate) is_384: bool,
}

impl Zeroize for SHA512State {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
    }
}

impl Drop for SHA512State {
    fn drop(&mut self) {
        unsafe {
            volatile_write(&mut self.total_len, 0);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

//
// Public hash types
//

pub struct SHA224(SHA256State);
pub struct SHA256(SHA256State);

impl SHA2 for SHA224 {
    #[inline]
    fn new() -> Self {
        SHA224(SHA256State::new(true))
    }
    #[inline]
    fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    #[inline]
    fn finalize(self) -> Digest {
        self.0.finalize()
    }
}

impl SHA2 for SHA256 {
    #[inline]
    fn new() -> Self {
        SHA256(SHA256State::new(false))
    }
    #[inline]
    fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    #[inline]
    fn finalize(self) -> Digest {
        self.0.finalize()
    }
}

pub struct SHA384(SHA512State);
pub struct SHA512(SHA512State);

impl SHA2 for SHA384 {
    #[inline]
    fn new() -> Self {
        SHA384(SHA512State::new(true))
    }
    #[inline]
    fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    #[inline]
    fn finalize(self) -> Digest {
        self.0.finalize()
    }
}

impl SHA2 for SHA512 {
    #[inline]
    fn new() -> Self {
        SHA512(SHA512State::new(false))
    }
    #[inline]
    fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    #[inline]
    fn finalize(self) -> Digest {
        self.0.finalize()
    }
}
