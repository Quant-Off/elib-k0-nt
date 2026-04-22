//! BLAKE2b 및 BLAKE3 암호 해시 함수 모듈입니다.
//!
//! BLAKE2b는 RFC 7693을 준수하며, BLAKE3는 공식 명세를 따릅니다.
//! 민감 데이터는 `SecureBuffer`에 보관하며, Drop 시 내부 상태를
//! `write_volatile`로 강제 소거합니다.
//!
//! 상수-시간 비교는 `constant-time` 크레이트를 통해 수행됩니다.
//! aarch64, x86_64, 베어메탈에서 동일하게 작동합니다.
//!
//! ---
//!
//! `blake2b` 해시는 `blake2`의 변형 중 하나로, 64비트 플랫폼(최신 서버,
//! PC)에 최적화되어 있으며, 최대 512비트의 다이제스트를 생성합니다. 추 후
//! 다중 코어를 활용하기 위한 병렬 처리를 지원하는 `blake2bp`, `blake2sp`
//! 를 지원할 예정입니다.
//!
//! `blake3` 해시는 2020년에 발표된 최신 버전으로, 내부적으로 머클
//! 트리(Merkle Tree) 구조를 채택하여 SIMD 명령어와 다중 스레딩을 통한
//! 극단적인 병렬 처리가 가능합니다. 이는 `blake2b`보다도 압도적으로 빠르며,
//! 단일 알고리즘으로 기존의 다양한 변형(다이제스트 크기 변경, 키 파생 등)을
//! 모두 커버하도록 설계되었습니다.
//!
//! # Examples
//! ```rust,ignore
//! use blake::{Blake2b, Blake3, blake2b_long};
//!
//! // blake2b
//! let mut h = Blake2b::new(32);
//! h.update(b"hello world");
//! let digest = h.finalize().unwrap();
//! assert_eq!(digest.as_slice().len(), 32);
//!
//! // blake3
//! let mut h = Blake3::new();
//! h.update(b"hello world");
//! let digest = h.finalize().unwrap();
//! assert_eq!(digest.as_slice().len(), 32);
//!
//! let out = blake2b_long(b"input", 80).unwrap();
//! assert_eq!(out.as_slice().len(), 80);
//! ```
//!
//! # Authors
//! Q. T. Felix

#![cfg_attr(not(test), no_std)]

mod blake2b;
mod blake3;

use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

pub use blake2b::Blake2b;
pub use blake3::{Blake3, OUT_LEN as BLAKE3_OUT_LEN};

pub use constant_time::{Choice, CtEqOps};

/// 해시 연산 중 발생할 수 있는 에러 타입입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashError {
    /// 출력 길이가 유효하지 않음 (0 또는 최대 크기 초과)
    InvalidOutputLength,
    /// 버퍼 할당 실패 (no_std 환경에서 최대 크기 초과)
    AllocationFailed,
}

/// blake2b_long이 지원하는 최대 출력 크기입니다.
/// Argon2id에서 사용되는 최대 크기(1024바이트)를 고려하여 설정합니다.
pub const MAX_OUTPUT_LEN: usize = 1024;

/// 가변 길이 보안 버퍼입니다.
///
/// no_std 환경에서 힙 할당 없이 고정 크기 배열을 사용합니다.
/// Drop 시 `write_volatile`로 데이터를 강제 소거합니다.
pub struct SecureBuffer {
    data: [u8; MAX_OUTPUT_LEN],
    len: usize,
}

impl SecureBuffer {
    /// 지정된 크기의 새 버퍼를 생성합니다.
    ///
    /// # Errors
    /// `len > MAX_OUTPUT_LEN`이면 `Err(HashError::AllocationFailed)` 반환.
    #[inline]
    pub fn new_owned(len: usize) -> Result<Self, HashError> {
        if len > MAX_OUTPUT_LEN {
            return Err(HashError::AllocationFailed);
        }
        Ok(Self {
            data: [0u8; MAX_OUTPUT_LEN],
            len,
        })
    }

    /// 버퍼의 유효 데이터를 슬라이스로 반환합니다.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// 버퍼의 유효 데이터를 가변 슬라이스로 반환합니다.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        for b in &mut self.data[..self.len] {
            unsafe { write_volatile(b, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// 상수-시간 바이트 슬라이스 비교입니다.
///
/// 두 슬라이스가 동일한 길이와 내용을 가지면 `Choice(1)` 반환.
/// 길이가 다르면 `Choice(0)` 반환 (상수 시간).
#[inline]
pub fn ct_eq_slice(a: &[u8], b: &[u8]) -> Choice {
    // 길이 비교도 상수-시간으로 수행
    let len_eq = CtEqOps::eq(&a.len(), &b.len());

    // 두 슬라이스 중 작은 길이만큼 비교
    let min_len = if a.len() < b.len() { a.len() } else { b.len() };

    let mut result = Choice::from_u8(1);
    for i in 0..min_len {
        result &= CtEqOps::eq(&a[i], &b[i]);
    }

    // 길이가 다르면 결과는 무조건 false
    result & len_eq
}

impl CtEqOps for SecureBuffer {
    #[inline]
    fn eq(&self, other: &Self) -> Choice {
        ct_eq_slice(self.as_slice(), other.as_slice())
    }
}

/// RFC 9106 Section 3.2에서 정의된 가변 출력 BLAKE2b 함수입니다 (H').
///
/// Argon2id 블록 초기화 및 최종 태그 생성에 사용됩니다.
///
/// # Security Note
/// `out_len > 64`일 때 중간 다이제스트를 체인으로 연결합니다.
/// 각 단계의 중간값은 SecureBuffer에 보관됩니다.
///
/// # Errors
/// `out_len == 0` 또는 SecureBuffer 할당 실패 시 `Err`.
pub fn blake2b_long(input: &[u8], out_len: usize) -> Result<SecureBuffer, HashError> {
    if out_len == 0 {
        return Err(HashError::InvalidOutputLength);
    }

    let len_prefix = (out_len as u32).to_le_bytes();

    if out_len <= 64 {
        let mut h = Blake2b::new(out_len);
        h.update(&len_prefix);
        h.update(input);
        return h.finalize();
    }

    // out_len > 64
    // r = ceil(out_len/32) - 2  (number of full-64-byte intermediate hashes)
    // last_len = out_len - 32*r  (final hash length, always 33..=64)
    let r = out_len.div_ceil(32).saturating_sub(2);
    let last_len = out_len - 32 * r;

    let mut out = SecureBuffer::new_owned(out_len)?;
    let out_slice = out.as_mut_slice();

    // A_1 = BLAKE2b-64(LE32(out_len) || input)
    let mut h = Blake2b::new(64);
    h.update(&len_prefix);
    h.update(input);
    let mut prev = h.finalize()?;

    out_slice[..32].copy_from_slice(&prev.as_slice()[..32]);
    let mut written = 32usize;

    // A_2 .. A_r  (r-1 iterations, each 64 bytes, take first 32)
    for _ in 1..r {
        let mut h = Blake2b::new(64);
        h.update(prev.as_slice());
        let a = h.finalize()?;
        out_slice[written..written + 32].copy_from_slice(&a.as_slice()[..32]);
        written += 32;
        prev = a;
    }

    // A_{r+1} = BLAKE2b-last_len(A_r), write all last_len bytes
    let mut h = Blake2b::new(last_len);
    h.update(prev.as_slice());
    let a = h.finalize()?;
    out_slice[written..out_len].copy_from_slice(a.as_slice());

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // BLAKE2b RFC 7693 테스트 벡터
    #[test]
    fn blake2b_empty() {
        let h = Blake2b::new(64);
        let digest = h.finalize().unwrap();
        let expected = [
            0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03, 0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52,
            0xd2, 0x72, 0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61, 0x8a, 0x86, 0xe2, 0x17,
            0xf7, 0x1f, 0x54, 0x19, 0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53, 0x13, 0x89,
            0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b, 0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
            0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce,
        ];
        assert_eq!(digest.as_slice(), &expected);
    }

    #[test]
    fn blake2b_abc() {
        let mut h = Blake2b::new(64);
        h.update(b"abc");
        let digest = h.finalize().unwrap();
        let expected = [
            0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d, 0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12,
            0xf6, 0xe9, 0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7, 0x4b, 0x12, 0xbb, 0x6f,
            0xdb, 0xff, 0xa2, 0xd1, 0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d, 0xc2, 0x52,
            0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95, 0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
            0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23,
        ];
        assert_eq!(digest.as_slice(), &expected);
    }

    // BLAKE3 테스트 벡터
    #[test]
    fn blake3_empty() {
        let h = Blake3::new();
        let digest = h.finalize().unwrap();
        let expected = [
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
            0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
            0xe4, 0x1f, 0x32, 0x62,
        ];
        assert_eq!(digest.as_slice(), &expected);
    }

    #[test]
    fn blake3_hello() {
        let mut h = Blake3::new();
        h.update(b"hello");
        let digest = h.finalize().unwrap();
        let expected = [
            0xea, 0x8f, 0x16, 0x3d, 0xb3, 0x86, 0x82, 0x92, 0x5e, 0x44, 0x91, 0xc5, 0xe5, 0x8d,
            0x4b, 0xb3, 0x50, 0x6e, 0xf8, 0xc1, 0x4e, 0xb7, 0x8a, 0x86, 0xe9, 0x08, 0xc5, 0x62,
            0x4a, 0x67, 0x20, 0x0f,
        ];
        assert_eq!(digest.as_slice(), &expected);
    }

    // blake2b_long 테스트
    #[test]
    fn blake2b_long_80() {
        let out = blake2b_long(b"test", 80).unwrap();
        assert_eq!(out.as_slice().len(), 80);
    }

    // 상수-시간 비교 테스트
    #[test]
    fn ct_eq_slice_same() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        assert_eq!(ct_eq_slice(&a, &b).unwrap_u8(), 1);
    }

    #[test]
    fn ct_eq_slice_different() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert_eq!(ct_eq_slice(&a, &b).unwrap_u8(), 0);
    }

    #[test]
    fn ct_eq_slice_different_len() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];
        assert_eq!(ct_eq_slice(&a, &b).unwrap_u8(), 0);
    }

    #[test]
    fn secure_buffer_ct_eq() {
        let mut buf1 = SecureBuffer::new_owned(4).unwrap();
        buf1.as_mut_slice().copy_from_slice(&[1, 2, 3, 4]);

        let mut buf2 = SecureBuffer::new_owned(4).unwrap();
        buf2.as_mut_slice().copy_from_slice(&[1, 2, 3, 4]);

        assert_eq!(CtEqOps::eq(&buf1, &buf2).unwrap_u8(), 1);

        buf2.as_mut_slice()[3] = 5;
        assert_eq!(CtEqOps::eq(&buf1, &buf2).unwrap_u8(), 0);
    }
}
