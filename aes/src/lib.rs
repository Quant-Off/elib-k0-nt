//! AES-256 블록 암호 및 운용 모드가 구현된 모듈입니다.
//!
//! FIPS 197 (AES) 및 NIST SP 800-38A/D 표준을 준수하며,
//! constant-time 연산을 통해 타이밍 공격을 방지합니다.
//!
//! # Features
//! - AES-256 블록 암호 (FIPS 197)
//! - CBC 모드 (NIST SP 800-38A)
//! - CTR 모드 (NIST SP 800-38A)
//! - GCM 모드 (NIST SP 800-38D)
//!
//! # Examples
//! ```rust
//! use aes::{AES256, AES256GCM, KEY_SIZE, GCM_NONCE_SIZE, GCM_TAG_SIZE};
//!
//! let key = [0u8; KEY_SIZE];
//! let nonce = [0u8; GCM_NONCE_SIZE];
//! let plaintext = b"Hello, World!!!!";
//!
//! let gcm = AES256GCM::new(&key);
//! let mut ciphertext = [0u8; 16];
//! let mut tag = [0u8; GCM_TAG_SIZE];
//! gcm.encrypt(&nonce, &[], plaintext, &mut ciphertext, &mut tag);
//! ```
//!
//! # Security Note
//! 모든 키 및 라운드 키는 Drop 시 강제 소거됩니다.
//!
//! # Authors
//! Q. T. Felix

#![cfg_attr(not(test), no_std)]

mod block;
mod cbc;
mod ctr;
mod gcm;
mod ghash;
mod key;
mod sbox;

pub use cbc::{AES256CBC, CBC_IV_SIZE};
pub use ctr::{AES256CTR, CTR_IV_SIZE, CTR_NONCE_SIZE};
pub use gcm::{AES256GCM, GCM_NONCE_SIZE, GCM_TAG_SIZE};
pub use ghash::GHash;

use block::{decrypt_block, encrypt_block};
use key::expand_key;
use zeroize::Secret;

const NB: usize = 4;
const NR: usize = 14;

pub const KEY_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 16;

/// AES-256 블록 암호 구조체입니다.
///
/// 라운드 키는 `Secret` 으로 보호되어 Drop 시 자동 소거됩니다.
pub struct AES256 {
    round_keys: Secret<[u32; NB * (NR + 1)]>,
}

impl AES256 {
    /// 256비트 키로 AES-256 인스턴스를 생성합니다.
    ///
    /// # Arguments
    /// - `key`: 32바이트 암호화 키
    #[must_use]
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self {
            round_keys: Secret::new(expand_key(key)),
        }
    }

    /// 16바이트 블록을 암호화합니다.
    ///
    /// # Arguments
    /// - `block`: 16바이트 평문 블록
    #[must_use]
    pub fn encrypt(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        encrypt_block(block, self.round_keys.expose())
    }

    /// 16바이트 블록을 복호화합니다.
    ///
    /// # Arguments
    /// - `block`: 16바이트 암호문 블록
    #[must_use]
    pub fn decrypt(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        decrypt_block(block, self.round_keys.expose())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    /// AES256 의 round_keys 는 expand_key 결과로 키 정보를 포함.
    /// Drop 후 round_keys 메모리가 0 으로 소거되는지 검증.
    #[test]
    fn test_aes256_zeroize_on_drop() {
        let key = [0xA5u8; KEY_SIZE];
        let mut storage: MaybeUninit<AES256> = MaybeUninit::uninit();

        unsafe {
            storage.write(AES256::new(&key));
            // Secret<[u32; 60]> 의 inner 위치에 round_keys 저장
            let ptr = storage.assume_init_ref().round_keys.expose().as_ptr() as *const u8;
            let byte_len = core::mem::size_of::<[u32; NB * (NR + 1)]>();

            let pre = core::slice::from_raw_parts(ptr, byte_len);
            assert!(
                pre.iter().any(|&b| b != 0),
                "round_keys 가 비어 있음 — expand_key 가 동작하지 않음"
            );

            storage.assume_init_drop();

            let post = core::slice::from_raw_parts(ptr, byte_len);
            assert!(
                post.iter().all(|&b| b == 0),
                "AES256 round_keys 가 Drop 후 소거되지 않음"
            );
        }
    }

    #[test]
    fn fips197_c3_test_vector() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected_ciphertext: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];

        let cipher = AES256::new(&key);
        let ciphertext = cipher.encrypt(&plaintext);
        assert_eq!(ciphertext, expected_ciphertext);

        let decrypted = cipher.decrypt(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key: [u8; 32] = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
        ];
        let plaintext: [u8; 16] = [
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x00,
            0x00, 0x00,
        ];

        let cipher = AES256::new(&key);
        let ciphertext = cipher.encrypt(&plaintext);
        let decrypted = cipher.decrypt(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }
}
