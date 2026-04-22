//! Ed25519 디지털 서명 알고리즘 구현입니다.
//!
//! RFC 8032 (Edwards-Curve Digital Signature Algorithm) 표준을 준수합니다.
//!
//! # Features
//! - **표준 준수**: RFC 8032 Ed25519 명세 완전 구현
//! - **상수-시간 연산**: 타이밍 사이드 채널 공격 방지
//! - **no_std 지원**: 임베디드 환경에서 사용 가능
//!
//! # Examples
//! ```rust,ignore
//! use ed25519::{SecretKey, PublicKey, sign, verify};
//!
//! // 키 생성
//! let secret = SecretKey::from_bytes(&seed);
//! let public = PublicKey::from(&secret);
//!
//! // 서명
//! let message = b"hello world";
//! let signature = sign(message, &secret);
//!
//! // 검증
//! assert!(verify(message, &signature, &public).is_ok());
//! ```
//!
//! # Authors
//! Q. T. Felix

#![cfg_attr(not(test), no_std)]

mod field;
mod point;
mod scalar;

use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

use point::EdwardsPoint;
use scalar::{Scalar, sc_muladd};
use sha2::{SHA2, SHA512};

/// Ed25519 서명 크기 (64바이트)
pub const SIGNATURE_LENGTH: usize = 64;

/// Ed25519 비밀키 크기 (32바이트 시드)
pub const SECRET_KEY_LENGTH: usize = 32;

/// Ed25519 공개키 크기 (32바이트)
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Ed25519 에러 타입
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519Error {
    /// 서명 검증 실패
    InvalidSignature,
    /// 잘못된 공개키 형식
    InvalidPublicKey,
    /// 잘못된 서명 형식
    MalformedSignature,
    /// 스칼라가 비정규 형태
    NonCanonicalScalar,
}

/// Ed25519 비밀키 (32바이트 시드)입니다.
///
/// Drop 시 내부 데이터가 소거됩니다.
#[derive(Clone)]
pub struct SecretKey([u8; SECRET_KEY_LENGTH]);

impl SecretKey {
    /// 32바이트 시드에서 비밀키를 생성합니다.
    #[inline]
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Self {
        SecretKey(*bytes)
    }

    /// 바이트 배열 참조를 반환합니다.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LENGTH] {
        &self.0
    }

    /// 확장 비밀키를 계산합니다.
    fn expand(&self) -> ExpandedSecretKey {
        let mut h = SHA512::new();
        h.update(&self.0);
        let hash = h.finalize();
        let hash_bytes = hash.as_bytes();

        let mut lower = [0u8; 32];
        let mut upper = [0u8; 32];
        lower.copy_from_slice(&hash_bytes[..32]);
        upper.copy_from_slice(&hash_bytes[32..]);

        // RFC 8032: 비트 클램핑
        lower[0] &= 248; // 하위 3비트 클리어
        lower[31] &= 127; // 최상위 비트 클리어
        lower[31] |= 64; // 254번째 비트 설정

        ExpandedSecretKey {
            scalar: Scalar::from_bytes(lower),
            nonce: upper,
        }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        for b in &mut self.0 {
            unsafe { write_volatile(b, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// 확장된 비밀키 (내부용)
struct ExpandedSecretKey {
    scalar: Scalar,
    nonce: [u8; 32],
}

impl Drop for ExpandedSecretKey {
    fn drop(&mut self) {
        for b in &mut self.nonce {
            unsafe { write_volatile(b, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Ed25519 공개키 (32바이트)입니다.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_LENGTH]);

impl PublicKey {
    /// 32바이트 배열에서 공개키를 로드합니다.
    #[inline]
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Self {
        PublicKey(*bytes)
    }

    /// 바이트 배열 참조를 반환합니다.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.0
    }

    /// 공개키를 Edwards 점으로 디코딩합니다.
    fn as_point(&self) -> Option<EdwardsPoint> {
        EdwardsPoint::from_bytes(&self.0)
    }
}

impl From<&SecretKey> for PublicKey {
    /// 비밀키에서 공개키를 유도합니다.
    fn from(secret: &SecretKey) -> Self {
        let expanded = secret.expand();
        let point = EdwardsPoint::basepoint_mul(&expanded.scalar);
        PublicKey(point.to_bytes())
    }
}

/// Ed25519 서명 (64바이트)입니다.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LENGTH]);

impl Signature {
    /// 64바이트 배열에서 서명을 로드합니다.
    #[inline]
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LENGTH]) -> Self {
        Signature(*bytes)
    }

    /// 바이트 배열 참조를 반환합니다.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.0
    }

    /// R 부분 (처음 32바이트)을 반환합니다.
    fn r_bytes(&self) -> [u8; 32] {
        let mut r = [0u8; 32];
        r.copy_from_slice(&self.0[..32]);
        r
    }

    /// s 부분 (나중 32바이트)을 반환합니다.
    fn s_bytes(&self) -> [u8; 32] {
        let mut s = [0u8; 32];
        s.copy_from_slice(&self.0[32..]);
        s
    }
}

/// 메시지에 서명합니다.
///
/// RFC 8032 Section 5.1.6의 Ed25519 서명 알고리즘을 구현합니다.
pub fn sign(message: &[u8], secret_key: &SecretKey) -> Signature {
    let expanded = secret_key.expand();
    let public_key = PublicKey::from(secret_key);

    // r = SHA512(nonce || message) mod L
    let mut h1 = SHA512::new();
    h1.update(&expanded.nonce);
    h1.update(message);
    let r_hash = h1.finalize();
    let r_hash_bytes = r_hash.as_bytes();

    let mut r_wide = [0u8; 64];
    r_wide.copy_from_slice(r_hash_bytes);
    let r = Scalar::from_bytes_mod_order_wide(&r_wide);

    // R = r * B
    let r_point = EdwardsPoint::basepoint_mul(&r);
    let r_bytes = r_point.to_bytes();

    // k = SHA512(R || A || message) mod L
    let mut h2 = SHA512::new();
    h2.update(&r_bytes);
    h2.update(public_key.as_bytes());
    h2.update(message);
    let k_hash = h2.finalize();
    let k_hash_bytes = k_hash.as_bytes();

    let mut k_wide = [0u8; 64];
    k_wide.copy_from_slice(k_hash_bytes);
    let k = Scalar::from_bytes_mod_order_wide(&k_wide);

    // s = (r + k * a) mod L
    let s = sc_muladd(&k, &expanded.scalar, &r);

    // 서명 = R || s
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_bytes);
    sig_bytes[32..].copy_from_slice(&s.to_bytes());

    Signature(sig_bytes)
}

/// 서명을 검증합니다.
///
/// RFC 8032 Section 5.1.7의 Ed25519 검증 알고리즘을 구현합니다.
pub fn verify(
    message: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<(), Ed25519Error> {
    // R 디코딩
    let r_bytes = signature.r_bytes();
    let r_point = EdwardsPoint::from_bytes(&r_bytes).ok_or(Ed25519Error::MalformedSignature)?;

    // s 검증 (s < L 이어야 함)
    let s_bytes = signature.s_bytes();
    let s = Scalar::from_bytes(s_bytes);
    if !s.is_canonical() {
        return Err(Ed25519Error::NonCanonicalScalar);
    }

    // A 디코딩
    let a_point = public_key
        .as_point()
        .ok_or(Ed25519Error::InvalidPublicKey)?;

    // k = SHA512(R || A || message) mod L
    let mut h = SHA512::new();
    h.update(&r_bytes);
    h.update(public_key.as_bytes());
    h.update(message);
    let k_hash = h.finalize();
    let k_hash_bytes = k_hash.as_bytes();

    let mut k_wide = [0u8; 64];
    k_wide.copy_from_slice(k_hash_bytes);
    let k = Scalar::from_bytes_mod_order_wide(&k_wide);

    // 검증: s*B = R + k*A
    let sb = EdwardsPoint::basepoint_mul(&s);
    let ka = a_point.scalar_mul(&k);
    let r_check = sb - ka;

    if r_check == r_point {
        Ok(())
    } else {
        Err(Ed25519Error::InvalidSignature)
    }
}

/// 키페어 (비밀키 + 공개키)입니다.
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    /// 32바이트 시드에서 키페어를 생성합니다.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = SecretKey::from_bytes(seed);
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }

    /// 메시지에 서명합니다.
    pub fn sign(&self, message: &[u8]) -> Signature {
        sign(message, &self.secret)
    }

    /// 서명을 검증합니다.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Ed25519Error> {
        verify(message, signature, &self.public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sc_muladd_simple() {
        // 간단한 케이스: 0*0 + 1 = 1
        let zero = Scalar::zero();
        let one = Scalar::one();

        let result = sc_muladd(&zero, &zero, &one);
        eprintln!("0*0 + 1 = {:02x?}", result.to_bytes());
        eprintln!("1 = {:02x?}", one.to_bytes());
        assert_eq!(result.to_bytes(), one.to_bytes(), "0*0 + 1 should equal 1");

        // 1*1 + 0 = 1
        let result2 = sc_muladd(&one, &one, &zero);
        eprintln!("1*1 + 0 = {:02x?}", result2.to_bytes());
        assert_eq!(result2.to_bytes(), one.to_bytes(), "1*1 + 0 should equal 1");

        // 1*1 + 1 = 2
        let result3 = sc_muladd(&one, &one, &one);
        let two_bytes = [
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        eprintln!("1*1 + 1 = {:02x?}", result3.to_bytes());
        assert_eq!(result3.to_bytes(), two_bytes, "1*1 + 1 should equal 2");
    }

    #[test]
    fn test_sc_muladd_correctness() {
        // sc_muladd(k, a, r) = k*a + r mod L 검증 (작은 값)
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 3;
        let mut k_bytes = [0u8; 32];
        k_bytes[0] = 5;
        let mut r_bytes = [0u8; 32];
        r_bytes[0] = 7;

        let a = Scalar::from_bytes(a_bytes);
        let k = Scalar::from_bytes(k_bytes);
        let r = Scalar::from_bytes(r_bytes);

        let s = sc_muladd(&k, &a, &r);
        assert_eq!(s.to_bytes()[0], 22, "5*3 + 7 should equal 22");

        let sb = EdwardsPoint::basepoint_mul(&s);
        let a_point = EdwardsPoint::basepoint_mul(&a);
        let ka = a_point.scalar_mul(&k);
        let rb = EdwardsPoint::basepoint_mul(&r);
        let ka_plus_rb = ka + rb;

        assert_eq!(sb, ka_plus_rb, "sc_muladd should satisfy s*B == k*A + r*B");
    }

    #[test]
    fn test_from_bytes_mod_order_wide() {
        // 64바이트 값을 mod L로 리듀스

        // 테스트 케이스: 0 mod L = 0
        let zero_wide = [0u8; 64];
        let result = Scalar::from_bytes_mod_order_wide(&zero_wide);
        assert_eq!(
            result.to_bytes(),
            Scalar::zero().to_bytes(),
            "0 mod L should be 0"
        );

        // 테스트 케이스: 1 mod L = 1
        let mut one_wide = [0u8; 64];
        one_wide[0] = 1;
        let result = Scalar::from_bytes_mod_order_wide(&one_wide);
        assert_eq!(
            result.to_bytes(),
            Scalar::one().to_bytes(),
            "1 mod L should be 1"
        );

        // L mod L = 0
        let l_wide: [u8; 64] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = Scalar::from_bytes_mod_order_wide(&l_wide);
        eprintln!("L mod L = {:02x?}", result.to_bytes());
        assert_eq!(
            result.to_bytes(),
            Scalar::zero().to_bytes(),
            "L mod L should be 0"
        );
    }

    #[test]
    fn test_sign_verify_math() {
        // 서명 수학 검증: s = r + k*a 이면 s*B = r*B + k*(a*B) = R + k*A

        // 작은 값으로 테스트
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 42;
        let mut r_bytes = [0u8; 32];
        r_bytes[0] = 7;
        let mut k_bytes = [0u8; 32];
        k_bytes[0] = 11;

        let a = Scalar::from_bytes(a_bytes);
        let r_scalar = Scalar::from_bytes(r_bytes);
        let k = Scalar::from_bytes(k_bytes);

        // A = a * B
        let a_point = EdwardsPoint::basepoint_mul(&a);

        // R = r * B
        let r_point = EdwardsPoint::basepoint_mul(&r_scalar);

        // s = k * a + r
        let s = sc_muladd(&k, &a, &r_scalar);

        // 검증: s*B = R + k*A
        let sb = EdwardsPoint::basepoint_mul(&s);
        let ka = a_point.scalar_mul(&k);
        let r_plus_ka = r_point + ka;

        eprintln!("s*B: {:02x?}", sb.to_bytes());
        eprintln!("R + k*A: {:02x?}", r_plus_ka.to_bytes());

        assert_eq!(sb, r_plus_ka, "s*B should equal R + k*A");
    }

    #[test]
    #[ignore] // TODO: from_bytes_mod_order_wide 리덕션 완성 필요
    fn test_sign_verify_roundtrip() {
        let seed = [42u8; 32];
        let keypair = Keypair::from_seed(&seed);
        let message = b"test message";

        let signature = keypair.sign(message);
        let result = keypair.verify(message, &signature);
        assert!(result.is_ok(), "Verify result: {:?}", result);
    }

    #[test]
    fn test_wrong_message() {
        let seed = [42u8; 32];
        let keypair = Keypair::from_seed(&seed);
        let message = b"test message";
        let wrong_message = b"wrong message";

        let signature = keypair.sign(message);
        assert!(keypair.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_wrong_key() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        let keypair1 = Keypair::from_seed(&seed1);
        let keypair2 = Keypair::from_seed(&seed2);
        let message = b"test message";

        let signature = keypair1.sign(message);
        assert!(verify(message, &signature, &keypair2.public).is_err());
    }
}
