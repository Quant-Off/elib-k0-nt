//! BLAKE2b 및 BLAKE3 암호 해시 함수 모듈입니다.
//!
//! BLAKE2b는 RFC 7693을 준수하며, BLAKE3는 공식 명세를 따릅니다.
//! 민감 데이터는 [SecureBuffer]에 보관하며, Drop 시 내부 상태를
//! [ptr::write_volatile]로 강제 소거합니다.
//!
//! 상수-시간 비교는 플랫폼(환경)에 상관없이 `constant-time` 
//! 크레이트를 통해 정상적으로 수행됩니다.
//!
//! ---
//!
//! `blake2b`해시는 `blake2`의 변형 중 하나로, 64비트 플랫폼(최신
//! 서버)에 최적화되어 있으며, 최대 512비트의 다이제스트를 생성합니다. 추 후
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

use zeroize::{Secret, Zeroize};

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
/// 내부 데이터는 `Secret`으로 보호되어 Drop 시 전체 영역이 소거됩니다.
pub struct SecureBuffer {
    data: Secret<[u8; MAX_OUTPUT_LEN]>,
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
            data: Secret::new([0u8; MAX_OUTPUT_LEN]),
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

impl Zeroize for SecureBuffer {
    #[inline]
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.len.zeroize();
    }
}

impl Drop for SecureBuffer {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// 상수시간 바이트 슬라이스 비교 함수입니다.
///
/// 두 슬라이스가 동일한 길이와 내용을 가지면 `Choice(1)` 을, 내용이 다르거나
/// 길이가 다르면 `Choice(0)` 을 반환합니다.
///
/// # Security Note
/// 본 함수의 상수시간 보장은 두 슬라이스의 길이가 공개임을 가정합니다.
/// (FIPS / SP 표준상 MAC 태그, 해시 다이제스트, 키 등 비교 대상의 길이는
/// 공개 파라미터로 정의됨. 가변 비밀 평문의 동등성 비교에는 적합하지 않음.)
/// 동일 길이 입력에 대해서는 입력 내용과 무관하게 동일 사이클을 소비합니다.
/// 길이 불일치 시 짧은 쪽까지 비교 후 길이비교 결과로 0으로 마스킹되어
/// 최종 결과가 `Choice(0)`이 되며, 어떤 분기 결과도 호출자에게 직접 누설
/// 되지 않습니다.
pub fn ct_eq_slice(a: &[u8], b: &[u8]) -> Choice {
    let len_eq = CtEqOps::eq(&a.len(), &b.len());
    // 두 슬라이스 길이는 공개 가정
    // `min` 산출의 비교가 공개 데이터 분기
    let min_len = a.len().min(b.len());

    let mut result = Choice::from_u8(1);
    for i in 0..min_len {
        result &= CtEqOps::eq(&a[i], &b[i]);
    }

    // 길이가 다르면 len_eq == 0 으로 최종 결과 마스킹
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
    use core::mem::MaybeUninit;

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

    /// 길이 0 (빈 입력) keyed-hash 가 BLAKE3 공식 reference vector 와 byte-identity 인지 검증.
    /// 단일 블록 root 경로 (compress 1 회, push_cv/pop_cv 미운동) 의 최소 케이스.
    #[test]
    fn blake3_keyed_kat_len_0() {
        let key: [u8; 32] = *b"whats the Elvish word for friend";
        let input: [u8; 0] = [];
        let expected: [u8; 32] = [
            0x92, 0xb2, 0xb7, 0x56, 0x04, 0xed, 0x3c, 0x76, 0x1f, 0x9d, 0x6f, 0x62, 0x39, 0x2c,
            0x8a, 0x92, 0x27, 0xad, 0x0e, 0xa3, 0xf0, 0x95, 0x73, 0xe7, 0x83, 0xf1, 0x49, 0x8a,
            0x4e, 0xd6, 0x0d, 0x26,
        ];
        let mut h = Blake3::new_keyed(&key);
        h.update(&input);
        let digest = h.finalize().unwrap();
        assert_eq!(digest.as_slice(), &expected);
    }

    /// 길이 1 keyed-hash 가 BLAKE3 공식 reference vector 와 byte-identity 인지 검증.
    /// 단일 블록 root 경로 (block_len = 1, compress 1 회).
    #[test]
    fn blake3_keyed_kat_len_1() {
        let key: [u8; 32] = *b"whats the Elvish word for friend";
        let input: [u8; 1] = [0u8]; // (0 % 251) as u8 == 0
        let expected: [u8; 32] = [
            0x6d, 0x78, 0x78, 0xdf, 0xff, 0x2f, 0x48, 0x56, 0x35, 0xd3, 0x90, 0x13, 0x27, 0x8a,
            0xe1, 0x4f, 0x14, 0x54, 0xb8, 0xc0, 0xa3, 0xa2, 0xd3, 0x4b, 0xc1, 0xab, 0x38, 0x22,
            0x8a, 0x80, 0xc9, 0x5b,
        ];
        let mut h = Blake3::new_keyed(&key);
        h.update(&input);
        let digest = h.finalize().unwrap();
        assert_eq!(digest.as_slice(), &expected);
    }

    /// 길이 64 keyed-hash 가 BLAKE3 공식 reference vector 와 byte-identity 인지 검증.
    /// ChunkState::update 의 첫 block-boundary compress (L185 first_8_words(compress(...))) 운동.
    #[test]
    fn blake3_keyed_kat_len_64() {
        let key: [u8; 32] = *b"whats the Elvish word for friend";
        let mut input = [0u8; 64];
        for (i, b) in input.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let expected: [u8; 32] = [
            0xba, 0x8c, 0xed, 0x36, 0xf3, 0x27, 0x70, 0x0d, 0x21, 0x3f, 0x12, 0x0b, 0x1a, 0x20,
            0x7a, 0x3b, 0x8c, 0x04, 0x33, 0x05, 0x28, 0x58, 0x6f, 0x41, 0x4d, 0x09, 0xf2, 0xf7,
            0xd9, 0xcc, 0xb7, 0xe6,
        ];
        let mut h = Blake3::new_keyed(&key);
        h.update(&input);
        let digest = h.finalize().unwrap();
        assert_eq!(digest.as_slice(), &expected);
    }

    /// 길이 1024 keyed-hash 가 BLAKE3 공식 reference vector 와 byte-identity 인지 검증.
    /// 정확히 한 chunk 분량 (CHUNK_LEN = 1024) — chunk-boundary 진입 직전 root 마무리 경로.
    #[test]
    fn blake3_keyed_kat_len_1024() {
        let key: [u8; 32] = *b"whats the Elvish word for friend";
        let mut input = [0u8; 1024];
        for (i, b) in input.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let expected: [u8; 32] = [
            0x75, 0xc4, 0x6f, 0x6f, 0x3d, 0x9e, 0xb4, 0xf5, 0x5e, 0xca, 0xae, 0xe4, 0x80, 0xdb,
            0x73, 0x2e, 0x6c, 0x21, 0x05, 0x54, 0x6f, 0x1e, 0x67, 0x50, 0x03, 0x68, 0x7c, 0x31,
            0x71, 0x9c, 0x7b, 0xa4,
        ];
        let mut h = Blake3::new_keyed(&key);
        h.update(&input);
        let digest = h.finalize().unwrap();
        assert_eq!(digest.as_slice(), &expected);
    }

    /// 길이 1025 keyed-hash 가 BLAKE3 공식 reference vector 와 byte-identity 인지 검증.
    /// multi-chunk 진입점 — push_cv / pop_cv / parent_cv / merge_cv_stack 가 처음 운동되는 길이.
    #[test]
    fn blake3_keyed_kat_len_1025() {
        let key: [u8; 32] = *b"whats the Elvish word for friend";
        let mut input = [0u8; 1025];
        for (i, b) in input.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let expected: [u8; 32] = [
            0x35, 0x7d, 0xc5, 0x5d, 0xe0, 0xc7, 0xe3, 0x82, 0xc9, 0x00, 0xfd, 0x6e, 0x32, 0x0a,
            0xcc, 0x04, 0x14, 0x6b, 0xe0, 0x1d, 0xb6, 0xa8, 0xce, 0x72, 0x10, 0xb7, 0x18, 0x9b,
            0xd6, 0x64, 0xea, 0x69,
        ];
        let mut h = Blake3::new_keyed(&key);
        h.update(&input);
        let digest = h.finalize().unwrap();
        assert_eq!(digest.as_slice(), &expected);
    }

    /// 길이 8192 keyed-hash 가 BLAKE3 공식 reference vector 와 byte-identity 인지 검증.
    /// 8 chunk 이진 머지 — merge_cv_stack 의 ≥ 3 단계 cascade 가 처음 운동되는 길이.
    #[test]
    fn blake3_keyed_kat_len_8192() {
        let key: [u8; 32] = *b"whats the Elvish word for friend";
        let mut input = [0u8; 8192];
        for (i, b) in input.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let expected: [u8; 32] = [
            0xdc, 0x96, 0x37, 0xc8, 0x84, 0x5a, 0x77, 0x0b, 0x4c, 0xbf, 0x76, 0xb8, 0xda, 0xec,
            0x0e, 0xeb, 0xf7, 0xdc, 0x2e, 0xac, 0x11, 0x49, 0x85, 0x17, 0xf0, 0x8d, 0x44, 0xc8,
            0xfc, 0x00, 0xd5, 0x8a,
        ];
        let mut h = Blake3::new_keyed(&key);
        h.update(&input);
        let digest = h.finalize().unwrap();
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

    /// Blake2b 인스턴스가 update 후 nonempty 상태에서 Drop 시
    /// h / t / buf / buf_len / hash_len 전체가 0으로 소거되는지 검증
    /// blake3의 zeroize_on_drop 회귀 가드와 일관성을 맞추기 위한 추가 케이스
    #[test]
    #[cfg_attr(miri, ignore)] // padding byte scan 은 MIRI typed read 모델 외 stable 에서만 실행
    fn test_blake2b_zeroize_on_drop() {
        let mut storage: MaybeUninit<Blake2b> = MaybeUninit::uninit();
        // addr_of! 는 borrow tag 를 생성하지 않으므로 후속 &mut 작업 후에도
        // raw pointer 가 유효하게 유지 (Stacked Borrows 회피)
        let ptr = core::ptr::addr_of!(storage) as *const u8;
        let byte_len = size_of::<Blake2b>();

        unsafe {
            storage.write(Blake2b::new(64));
            (*storage.as_mut_ptr()).update(b"non-empty regression-guard input");

            let pre = core::slice::from_raw_parts(ptr, byte_len);
            assert!(
                pre.iter().any(|&b| b != 0),
                "Blake2b 가 비어 있음 new/update 가 동작하지 않음"
            );

            storage.assume_init_drop();

            let post = core::slice::from_raw_parts(ptr, byte_len);
            assert!(
                post.iter().all(|&b| b == 0),
                "Blake2b 인스턴스가 Drop 후 소거되지 않음"
            );
        }
    }

    /// keyed Blake3 인스턴스가 update 후 비-empty 상태에서 Drop 시
    /// key_words / cv_stack / chunk_state.{chaining_value, buf} / flags / cv_stack_len
    /// 모두 0 으로 소거되는지 검증.
    /// 회귀 가드 — 향후 plain [u32; 8] 또는 plain int 필드 재도입 시 본 테스트가 실패해야 함.
    #[test]
    #[cfg_attr(miri, ignore)] // padding byte scan 은 MIRI typed read 모델 외 stable 에서만 실행
    fn test_blake3_keyed_zeroize_on_drop() {
        let key = [0xA5u8; 32];
        let mut storage: MaybeUninit<Blake3> = MaybeUninit::uninit();
        let ptr = core::ptr::addr_of!(storage) as *const u8;
        let byte_len = core::mem::size_of::<Blake3>();

        unsafe {
            storage.write(Blake3::new_keyed(&key));
            // non-empty update — 내부 chaining_value 와 buf 에 비-제로 데이터를 채움
            (*storage.as_mut_ptr()).update(b"non-empty regression-guard input");

            // Blake3 전체 byte-extent 위에서 raw-pointer 스캔
            let pre = core::slice::from_raw_parts(ptr, byte_len);
            assert!(
                pre.iter().any(|&b| b != 0),
                "Blake3 가 비어 있음 — new_keyed/update 가 동작하지 않음"
            );

            storage.assume_init_drop();

            let post = core::slice::from_raw_parts(ptr, byte_len);
            assert!(
                post.iter().all(|&b| b == 0),
                "Blake3 keyed 인스턴스가 Drop 후 소거되지 않음"
            );
        }
    }

    /// unkeyed Blake3 인스턴스도 동일하게 검증 — 회귀 범위가 keyed 모드 전용이 아닌
    /// 전체 path 임을 명시.
    #[test]
    #[cfg_attr(miri, ignore)] // padding byte scan 은 MIRI typed read 모델 외 stable 에서만 실행
    fn test_blake3_unkeyed_zeroize_on_drop() {
        let mut storage: MaybeUninit<Blake3> = MaybeUninit::uninit();
        let ptr = core::ptr::addr_of!(storage) as *const u8;
        let byte_len = core::mem::size_of::<Blake3>();

        unsafe {
            storage.write(Blake3::new());
            (*storage.as_mut_ptr()).update(b"non-empty regression-guard input");

            let pre = core::slice::from_raw_parts(ptr, byte_len);
            assert!(
                pre.iter().any(|&b| b != 0),
                "Blake3 가 비어 있음 — new/update 가 동작하지 않음"
            );

            storage.assume_init_drop();

            let post = core::slice::from_raw_parts(ptr, byte_len);
            assert!(
                post.iter().all(|&b| b == 0),
                "Blake3 unkeyed 인스턴스가 Drop 후 소거되지 않음"
            );
        }
    }
}
