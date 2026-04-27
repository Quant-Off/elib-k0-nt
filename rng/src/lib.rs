#![cfg_attr(not(test), no_std)]

mod hash_drbg;
pub mod os_entropy;

use zeroize::Zeroize;

/// DRBG 연산 중 발생할 수 있는 오류에 대한 열거형입니다.
///
/// 모든 DRBG 구현에서 공유됩니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrbgError {
    /// 엔트로피 입력이 최소 보안 강도 요구사항(security_strength bytes) 미달
    EntropyTooShort,
    /// 엔트로피 입력 또는 Nonce가 최대 허용 길이(2^35 bits = 2^32 bytes) 초과
    EntropyTooLong,
    /// additional_input 또는 personalization_string이 최대 허용 길이(2^35 bits = 2^32 bytes) 초과
    InputTooLong,
    /// Nonce가 최소 길이(security_strength / 2 bytes) 미달
    NonceTooShort,
    /// 잘못된 인수 (예: no_of_bits 오버플로우)
    InvalidArgument,
    /// 재시드 간격(2^48) 초과 — 즉시 reseed() 호출 필요
    ReseedRequired,
    /// SecureBuffer 메모리 할당 실패 또는 OS mlock 실패
    AllocationFailed,
    /// 내부 해시 연산 실패
    InternalHashError,
    /// 요청한 출력 크기가 최대 허용치(65536 bytes = 2^19 bits) 초과
    RequestTooLarge,
    /// OS 엔트로피 소스 접근 실패
    ///
    /// 발생 원인:
    /// - 지원되지 않는 플랫폼: `os_entropy::extract_os_entropy` cfg 조건 미충족
    /// - VM 환경: 엔트로피 풀 초기화 미완료 (부팅 직후)
    OsEntropyFailed,
}

pub use hash_drbg::{HashDRBGSHA224, HashDRBGSHA256, HashDRBGSHA384, HashDRBGSHA512};

/// DRBG 내부 상태를 위한 최대 버퍼 크기입니다.
/// SHA-512 기반 Hash_DRBG의 seedlen = 111바이트
const MAX_SECURE_BUFFER_LEN: usize = 128;

/// 보안 버퍼입니다.
///
/// DRBG 내부 상태(V, C) 또는 OS 엔트로피 시드를 저장합니다.
/// Drop 또는 명시적 zeroize 호출 시 zeroize 크레이트의 휘발성 쓰기 + 배리어를
/// 통해 전체 backing storage 가 소거됩니다.
pub(crate) struct SecureBuffer {
    data: [u8; MAX_SECURE_BUFFER_LEN],
    len: usize,
}

impl SecureBuffer {
    #[inline]
    pub fn new_owned(len: usize) -> Result<Self, DrbgError> {
        if len > MAX_SECURE_BUFFER_LEN {
            return Err(DrbgError::AllocationFailed);
        }
        Ok(Self {
            data: [0u8; MAX_SECURE_BUFFER_LEN],
            len,
        })
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

impl Zeroize for SecureBuffer {
    #[inline]
    fn zeroize(&mut self) {
        // 활성 영역만이 아니라 backing storage 전체를 소거하여
        // 과거 더 큰 len 으로 사용된 적이 있는 잔존 바이트도 함께 제거.
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    /// SecureBuffer Drop 후 backing storage 전체가 0 으로 소거됨을 확인.
    #[test]
    fn test_secure_buffer_zeroize_on_drop() {
        let mut storage: MaybeUninit<SecureBuffer> = MaybeUninit::uninit();

        unsafe {
            let mut buf = SecureBuffer::new_owned(55).expect("new_owned");
            // 활성 영역을 인식 가능한 패턴으로 채움
            for b in buf.as_mut_slice().iter_mut() {
                *b = 0xA5;
            }
            // 활성 영역 외에도 잔존 데이터가 있다고 가정하고 강제 주입
            // (data 직접 접근은 pub(crate) 이므로 이 test 모듈에서 가능)
            buf.data[55..].fill(0x5A);
            buf.len = 55;

            storage.write(buf);
            let data_ptr = (&raw const (*storage.as_ptr()).data) as *const u8;
            let len_ptr = &raw const (*storage.as_ptr()).len;

            let pre = core::slice::from_raw_parts(data_ptr, MAX_SECURE_BUFFER_LEN);
            assert!(
                pre[..55].iter().all(|&b| b == 0xA5),
                "활성 영역 패턴 미반영"
            );
            assert!(
                pre[55..].iter().all(|&b| b == 0x5A),
                "비활성 영역 패턴 미반영"
            );
            assert_eq!(core::ptr::read(len_ptr), 55);

            storage.assume_init_drop();

            let post = core::slice::from_raw_parts(data_ptr, MAX_SECURE_BUFFER_LEN);
            assert!(
                post.iter().all(|&b| b == 0),
                "SecureBuffer data 미소거: {:?}",
                post
            );
            assert_eq!(core::ptr::read(len_ptr), 0, "SecureBuffer len 미소거");
        }
    }

    /// SecureBuffer::zeroize 명시 호출이 backing storage 전체를 소거함을 확인.
    #[test]
    fn test_secure_buffer_explicit_zeroize() {
        let mut buf = SecureBuffer::new_owned(64).expect("new_owned");
        for b in buf.as_mut_slice().iter_mut() {
            *b = 0xFF;
        }
        buf.data[64..].fill(0xEE);

        buf.zeroize();

        assert!(buf.data.iter().all(|&b| b == 0), "zeroize 후 data 미소거");
        assert_eq!(buf.len, 0, "zeroize 후 len 미소거");
    }
}
