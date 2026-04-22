#![no_std]
#![allow(non_camel_case_types)]

mod keccak;

use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

//
// Traits
//

pub trait SHA3: Sized {
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Digest;
}

pub trait XOF: Sized {
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize_into(self, out: &mut [u8]);
}

//
// Digest
//

pub struct Digest {
    bytes: [u8; 64],
    len: usize, // 28 / 32 / 48 / 64
}

impl Digest {
    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Drop for Digest {
    fn drop(&mut self) {
        for b in &mut self.bytes {
            unsafe {
                write_volatile(b, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

//
// KeccakState
// Internal sponge state shared by all SHA-3 and SHAKE variants.
// The largest rate is SHAKE128: 1344 bits = 168 bytes.
//

pub(crate) const MAX_RATE_BYTES: usize = 168;

pub(crate) struct KeccakState {
    pub(crate) state: [u64; 25],
    pub(crate) buffer: [u8; MAX_RATE_BYTES],
    pub(crate) buffer_len: usize,
    pub(crate) rate_bytes: usize,
    pub(crate) domain: u8,
}

impl Drop for KeccakState {
    fn drop(&mut self) {
        for s in &mut self.state {
            unsafe {
                write_volatile(s, 0);
            }
        }
        for b in &mut self.buffer {
            unsafe {
                write_volatile(b, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

//
// Public hash types
//

pub struct SHA3_224(KeccakState);
pub struct SHA3_256(KeccakState);

// SHA3-224  rate = 1600 − 448 = 1152 bits = 144 bytes, output = 28 bytes
impl SHA3 for SHA3_224 {
    #[inline]
    fn new() -> Self {
        SHA3_224(KeccakState::new(1152, 0x06))
    }
    #[inline]
    fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    #[inline]
    fn finalize(self) -> Digest {
        self.0.finalize_fixed(28)
    }
}

// SHA3-256  rate = 1600 − 512 = 1088 bits = 136 bytes, output = 32 bytes
impl SHA3 for SHA3_256 {
    #[inline]
    fn new() -> Self {
        SHA3_256(KeccakState::new(1088, 0x06))
    }
    #[inline]
    fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    #[inline]
    fn finalize(self) -> Digest {
        self.0.finalize_fixed(32)
    }
}

pub struct SHA3_384(KeccakState);
pub struct SHA3_512(KeccakState);

// SHA3-384  rate = 1600 − 768 = 832 bits = 104 bytes, output = 48 bytes
impl SHA3 for SHA3_384 {
    #[inline]
    fn new() -> Self {
        SHA3_384(KeccakState::new(832, 0x06))
    }
    #[inline]
    fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    #[inline]
    fn finalize(self) -> Digest {
        self.0.finalize_fixed(48)
    }
}

// SHA3-512  rate = 1600 − 1024 = 576 bits = 72 bytes, output = 64 bytes
impl SHA3 for SHA3_512 {
    #[inline]
    fn new() -> Self {
        SHA3_512(KeccakState::new(576, 0x06))
    }
    #[inline]
    fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    #[inline]
    fn finalize(self) -> Digest {
        self.0.finalize_fixed(64)
    }
}

pub struct SHAKE128(KeccakState);
pub struct SHAKE256(KeccakState);

// SHAKE128  rate = 1600 − 256 = 1344 bits = 168 bytes
// Security level: 128 bits (capacity = 256 bits)
impl XOF for SHAKE128 {
    #[inline]
    fn new() -> Self {
        SHAKE128(KeccakState::new(1344, 0x1f))
    }
    #[inline]
    fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    #[inline]
    fn finalize_into(self, out: &mut [u8]) {
        self.0.finalize_xof(out);
    }
}

// SHAKE256  rate = 1600 − 512 = 1088 bits = 136 bytes
// Security level: 256 bits (capacity = 512 bits)
impl XOF for SHAKE256 {
    #[inline]
    fn new() -> Self {
        SHAKE256(KeccakState::new(1088, 0x1f))
    }
    #[inline]
    fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    #[inline]
    fn finalize_into(self, out: &mut [u8]) {
        self.0.finalize_xof(out);
    }
}
