//! Ed448 디지털 서명 알고리즘 구현입니다.
//!
//! RFC 8032 (Edwards-Curve Digital Signature Algorithm) Ed448-Goldilocks 표준을 준수합니다.
//!
//! # Features
//! - **표준 준수**: RFC 8032 Ed448 명세 완전 구현
//! - **상수-시간 연산**: 타이밍 사이드 채널 공격 방지
//! - **no_std 지원**: 임베디드 환경에서 사용 가능
//!
//! # Examples
//! ```rust,ignore
//! use ed448::{SecretKey, PublicKey, sign, verify};
//!
//! // 키 생성
//! let secret = SecretKey::from_bytes(&seed);
//! let public = PublicKey::from(&secret);
//!
//! // 서명
//! let message = b"hello world";
//! let signature = sign(message, &[], &secret);
//!
//! // 검증
//! assert!(verify(message, &[], &signature, &public).is_ok());
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
use sha3::{SHAKE256, XOF};

pub const SIGNATURE_LENGTH: usize = 114;
pub const SECRET_KEY_LENGTH: usize = 57;
pub const PUBLIC_KEY_LENGTH: usize = 57;

const DOM4_PREFIX: &[u8] = b"SigEd448";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed448Error {
    InvalidSignature,
    InvalidPublicKey,
    MalformedSignature,
    NonCanonicalScalar,
}

#[derive(Clone)]
pub struct SecretKey([u8; SECRET_KEY_LENGTH]);

impl SecretKey {
    #[inline]
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Self {
        SecretKey(*bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LENGTH] {
        &self.0
    }

    fn expand(&self) -> ExpandedSecretKey {
        let mut h = SHAKE256::new();
        h.update(&self.0);
        let mut hash = [0u8; 114];
        h.finalize_into(&mut hash);

        let mut lower = [0u8; 57];
        let mut upper = [0u8; 57];
        lower.copy_from_slice(&hash[..57]);
        upper.copy_from_slice(&hash[57..]);

        lower[0] &= 0xfc;
        lower[55] |= 0x80;
        lower[56] = 0;

        // The clamped scalar may be >= L, so reduce it mod L
        let clamped = Scalar::from_bytes(lower);
        let scalar = sc_muladd(&Scalar::one(), &clamped, &Scalar::zero());

        ExpandedSecretKey {
            scalar,
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

struct ExpandedSecretKey {
    scalar: Scalar,
    nonce: [u8; 57],
}

impl Drop for ExpandedSecretKey {
    fn drop(&mut self) {
        for b in &mut self.nonce {
            unsafe { write_volatile(b, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_LENGTH]);

impl PublicKey {
    #[inline]
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Self {
        PublicKey(*bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.0
    }

    fn as_point(&self) -> Option<EdwardsPoint> {
        EdwardsPoint::from_bytes(&self.0)
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(secret: &SecretKey) -> Self {
        let expanded = secret.expand();
        let point = EdwardsPoint::basepoint_mul(&expanded.scalar);
        PublicKey(point.to_bytes())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LENGTH]);

impl Signature {
    #[inline]
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LENGTH]) -> Self {
        Signature(*bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.0
    }

    fn r_bytes(&self) -> [u8; 57] {
        let mut r = [0u8; 57];
        r.copy_from_slice(&self.0[..57]);
        r
    }

    fn s_bytes(&self) -> [u8; 57] {
        let mut s = [0u8; 57];
        s.copy_from_slice(&self.0[57..]);
        s
    }
}

fn dom4(context: &[u8]) -> ([u8; 10], usize) {
    let mut dom = [0u8; 10];
    dom[..8].copy_from_slice(DOM4_PREFIX);
    dom[8] = 0;
    dom[9] = context.len() as u8;
    (dom, 10)
}

pub fn sign(message: &[u8], secret_key: &SecretKey) -> Signature {
    sign_with_context(message, secret_key, &[])
}

pub fn sign_with_context(message: &[u8], secret_key: &SecretKey, context: &[u8]) -> Signature {
    let expanded = secret_key.expand();
    let public_key = PublicKey::from(secret_key);
    let (dom, dom_len) = dom4(context);

    let mut h1 = SHAKE256::new();
    h1.update(&dom[..dom_len]);
    h1.update(context);
    h1.update(&expanded.nonce);
    h1.update(message);
    let mut r_hash = [0u8; 114];
    h1.finalize_into(&mut r_hash);

    let r = Scalar::from_bytes_mod_order_wide(&r_hash);

    let r_point = EdwardsPoint::basepoint_mul(&r);
    let r_bytes = r_point.to_bytes();

    let mut h2 = SHAKE256::new();
    h2.update(&dom[..dom_len]);
    h2.update(context);
    h2.update(&r_bytes);
    h2.update(public_key.as_bytes());
    h2.update(message);
    let mut k_hash = [0u8; 114];
    h2.finalize_into(&mut k_hash);

    let k = Scalar::from_bytes_mod_order_wide(&k_hash);

    let s = sc_muladd(&k, &expanded.scalar, &r);

    let mut sig_bytes = [0u8; 114];
    sig_bytes[..57].copy_from_slice(&r_bytes);
    sig_bytes[57..].copy_from_slice(&s.to_bytes());

    Signature(sig_bytes)
}

pub fn verify(
    message: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<(), Ed448Error> {
    verify_with_context(message, signature, public_key, &[])
}

pub fn verify_with_context(
    message: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
    context: &[u8],
) -> Result<(), Ed448Error> {
    let r_bytes = signature.r_bytes();
    let r_point = EdwardsPoint::from_bytes(&r_bytes).ok_or(Ed448Error::MalformedSignature)?;

    let s_bytes = signature.s_bytes();
    let s = Scalar::from_bytes(s_bytes);
    if !s.is_canonical() {
        return Err(Ed448Error::NonCanonicalScalar);
    }

    let a_point = public_key.as_point().ok_or(Ed448Error::InvalidPublicKey)?;

    let (dom, dom_len) = dom4(context);

    let mut h = SHAKE256::new();
    h.update(&dom[..dom_len]);
    h.update(context);
    h.update(&r_bytes);
    h.update(public_key.as_bytes());
    h.update(message);
    let mut k_hash = [0u8; 114];
    h.finalize_into(&mut k_hash);

    let k = Scalar::from_bytes_mod_order_wide(&k_hash);

    let sb = EdwardsPoint::basepoint_mul(&s);
    let ka = a_point.scalar_mul(&k);
    let r_check = sb - ka;

    if r_check == r_point {
        Ok(())
    } else {
        Err(Ed448Error::InvalidSignature)
    }
}

pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    pub fn from_seed(seed: &[u8; 57]) -> Self {
        let secret = SecretKey::from_bytes(seed);
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        sign(message, &self.secret)
    }

    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Signature {
        sign_with_context(message, &self.secret, context)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Ed448Error> {
        verify(message, signature, &self.public)
    }

    pub fn verify_with_context(
        &self,
        message: &[u8],
        signature: &Signature,
        context: &[u8],
    ) -> Result<(), Ed448Error> {
        verify_with_context(message, signature, &self.public, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let seed = [42u8; 57];
        let keypair = Keypair::from_seed(&seed);
        assert_ne!(keypair.public.as_bytes(), &[0u8; 57]);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = [42u8; 57];
        let keypair = Keypair::from_seed(&seed);
        let message = b"test message";

        // Verify expanded scalar is now canonical
        let expanded = keypair.secret.expand();
        let a_scalar = expanded.scalar;
        let a_point = keypair.public.as_point().unwrap();
        let (dom, dom_len) = dom4(&[]);

        eprintln!("a bytes: {:02x?}", a_scalar.to_bytes());
        eprintln!(
            "a[55] = 0x{:02x}, canonical: {}",
            a_scalar.to_bytes()[55],
            a_scalar.is_canonical()
        );

        // Compute r
        let mut h1 = SHAKE256::new();
        h1.update(&dom[..dom_len]);
        h1.update(&[]);
        h1.update(&expanded.nonce);
        h1.update(message);
        let mut r_hash = [0u8; 114];
        h1.finalize_into(&mut r_hash);
        let r_scalar = scalar::Scalar::from_bytes_mod_order_wide(&r_hash);

        // R = r * B
        let r_point = EdwardsPoint::basepoint_mul(&r_scalar);
        let r_bytes = r_point.to_bytes();

        // Compute k
        let mut h2 = SHAKE256::new();
        h2.update(&dom[..dom_len]);
        h2.update(&[]);
        h2.update(&r_bytes);
        h2.update(keypair.public.as_bytes());
        h2.update(message);
        let mut k_hash = [0u8; 114];
        h2.finalize_into(&mut k_hash);
        let k_scalar = scalar::Scalar::from_bytes_mod_order_wide(&k_hash);
        eprintln!("k bytes: {:02x?}", k_scalar.to_bytes());
        eprintln!(
            "k[55] = 0x{:02x}, canonical: {}",
            k_scalar.to_bytes()[55],
            k_scalar.is_canonical()
        );

        // s = k*a + r
        let s_scalar = scalar::sc_muladd(&k_scalar, &a_scalar, &r_scalar);

        // Verify: s*B == k*A + R
        let sb = EdwardsPoint::basepoint_mul(&s_scalar);
        let ka = a_point.scalar_mul(&k_scalar);
        let ka_plus_r = ka + r_point;

        eprintln!("a canonical: {}", a_scalar.is_canonical());
        eprintln!("s*B:     {:02x?}", sb.to_bytes());
        eprintln!("k*A + R: {:02x?}", ka_plus_r.to_bytes());
        eprintln!("s*B == k*A + R: {}", sb == ka_plus_r);

        // Test associativity: (k*a)*B == k*(a*B)?
        let ka_scalar = k_scalar * a_scalar;
        eprintln!("k*a bytes: {:02x?}", ka_scalar.to_bytes());
        eprintln!("k*a canonical: {}", ka_scalar.is_canonical());
        let ka_b = EdwardsPoint::basepoint_mul(&ka_scalar);
        let k_times_ab = a_point.scalar_mul(&k_scalar);
        eprintln!("(k*a)*B: {:02x?}", ka_b.to_bytes());
        eprintln!("k*(a*B): {:02x?}", k_times_ab.to_bytes());
        eprintln!("(k*a)*B == k*(a*B): {}", ka_b == k_times_ab);

        // Check if basepoint_mul(x) == basepoint().scalar_mul(x)
        let b = EdwardsPoint::basepoint();
        let ka_b_via_scalar_mul = b.scalar_mul(&ka_scalar);
        eprintln!("ka*B via basepoint_mul: {:02x?}", ka_b.to_bytes());
        eprintln!(
            "ka*B via scalar_mul:    {:02x?}",
            ka_b_via_scalar_mul.to_bytes()
        );
        eprintln!("same: {}", ka_b == ka_b_via_scalar_mul);

        // Check if a*B computed freshly equals the stored public key
        let ab_fresh = b.scalar_mul(&a_scalar);
        eprintln!("a*B from public key: {:02x?}", a_point.to_bytes());
        eprintln!("a*B computed fresh:  {:02x?}", ab_fresh.to_bytes());
        eprintln!("same: {}", a_point == ab_fresh);

        // Test scalar_mul associativity with the actual scalars
        // Test: k * (a * B) == (k * a) * B where * is scalar mul
        // Compute step by step
        let a_times_b = b.scalar_mul(&a_scalar); // a*B
        let k_times_ab = a_times_b.scalar_mul(&k_scalar); // k*(a*B)
        let ka = k_scalar * a_scalar; // k*a in scalar field
        let ka_times_b = b.scalar_mul(&ka); // (k*a)*B
        eprintln!("k*(a*B): {:02x?}", k_times_ab.to_bytes());
        eprintln!("(k*a)*B: {:02x?}", ka_times_b.to_bytes());
        eprintln!("equal: {}", k_times_ab == ka_times_b);

        // What about (a*k)*B?
        let ak = a_scalar * k_scalar; // a*k in scalar field (should be same as k*a)
        eprintln!("k*a == a*k: {}", ka == ak);
        let ak_times_b = b.scalar_mul(&ak);
        eprintln!("(a*k)*B: {:02x?}", ak_times_b.to_bytes());
        eprintln!("(k*a)*B == (a*k)*B: {}", ka_times_b == ak_times_b);

        // Check k is canonical
        eprintln!("k canonical: {}", k_scalar.is_canonical());

        // Check point encoding/decoding for A
        let a_bytes = a_times_b.to_bytes();
        let a_decoded = EdwardsPoint::from_bytes(&a_bytes).unwrap();
        eprintln!("A == decode(encode(A)): {}", a_times_b == a_decoded);

        // Compare internal coordinates of A vs A decoded
        eprintln!("A.x: {:?}", a_times_b.x.to_bytes());
        eprintln!("decoded.x: {:?}", a_decoded.x.to_bytes());

        // Try another approach: compute (k*a)*B where we first compute k*B, then a*(k*B)
        let k_b = b.scalar_mul(&k_scalar);
        let a_kb = k_b.scalar_mul(&a_scalar);
        eprintln!("a*(k*B): {:02x?}", a_kb.to_bytes());
        eprintln!("(k*a)*B == a*(k*B): {}", ka_times_b == a_kb);

        // Try computing k*B then a*(k*B) vs (a*k)*B
        let kb = b.scalar_mul(&k_scalar);

        // Check if T coordinate is correct: T*Z = X*Y
        let t_z = kb.t * kb.z;
        let x_y = kb.x * kb.y;
        eprintln!("kb: T*Z == X*Y: {}", t_z == x_y);

        // Check basepoint
        let b_t_z = b.t * b.z;
        let b_x_y = b.x * b.y;
        eprintln!("basepoint: T*Z == X*Y: {}", b_t_z == b_x_y);

        // Try encoding and decoding kb first
        let kb_bytes = kb.to_bytes();
        let kb_decoded = EdwardsPoint::from_bytes(&kb_bytes).unwrap();
        let akb_via_decoded = kb_decoded.scalar_mul(&a_scalar);
        let akb = kb.scalar_mul(&a_scalar);
        eprintln!("a*(decoded(k*B)): {:02x?}", akb_via_decoded.to_bytes());
        eprintln!("a*(k*B direct):   {:02x?}", akb.to_bytes());
        eprintln!("same: {}", akb == akb_via_decoded);
        let ak_scalar = a_scalar * k_scalar; // Should equal k_scalar * a_scalar
        let ak_b = b.scalar_mul(&ak_scalar);
        eprintln!("a*k*B via a*(k*B): {:02x?}", akb.to_bytes());
        eprintln!("a*k*B via (a*k)*B: {:02x?}", ak_b.to_bytes());
        eprintln!("equal: {}", akb == ak_b);
        eprintln!("ak == ka: {}", ak_scalar == ka);

        // Test with size=29 scalar where the bug appears
        let mut s1_bytes = [0u8; 57];
        let mut s2_bytes = [0u8; 57];
        for i in 0..29 {
            s1_bytes[i] = 0xAB;
            s2_bytes[i] = 0xCD;
        }
        let s1 = scalar::Scalar::from_bytes(s1_bytes);
        let s2 = scalar::Scalar::from_bytes(s2_bytes);
        let s1 = scalar::sc_muladd(&scalar::Scalar::one(), &s1, &scalar::Scalar::zero());
        let s2 = scalar::sc_muladd(&scalar::Scalar::one(), &s2, &scalar::Scalar::zero());

        eprintln!("s1 bytes: {:02x?}", s1.to_bytes());
        eprintln!("s2 bytes: {:02x?}", s2.to_bytes());

        let p1 = b.scalar_mul(&s1); // s1*B
        eprintln!("s1*B: {:02x?}", p1.to_bytes());

        // Check intermediate point coordinates
        eprintln!(
            "s1*B coords: x={:?}, y={:?}, z={:?}, t={:?}",
            p1.x.to_bytes(),
            p1.y.to_bytes(),
            p1.z.to_bytes(),
            p1.t.to_bytes()
        );

        let s2_times_p1 = p1.scalar_mul(&s2); // s2*(s1*B)
        let s1s2 = s1 * s2;
        let direct = b.scalar_mul(&s1s2); // (s1*s2)*B

        eprintln!("s2*(s1*B): {:02x?}", s2_times_p1.to_bytes());
        eprintln!("(s1*s2)*B: {:02x?}", direct.to_bytes());
        eprintln!("equal: {}", s2_times_p1 == direct);

        assert!(sb == ka_plus_r, "Signature equation should hold");

        let signature = keypair.sign(message);
        let result = keypair.verify(message, &signature);
        assert!(result.is_ok(), "Verify result: {:?}", result);
    }

    #[test]
    fn test_wrong_message() {
        let seed = [42u8; 57];
        let keypair = Keypair::from_seed(&seed);
        let message = b"test message";
        let wrong_message = b"wrong message";

        let signature = keypair.sign(message);
        assert!(keypair.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_wrong_key() {
        let seed1 = [1u8; 57];
        let seed2 = [2u8; 57];
        let keypair1 = Keypair::from_seed(&seed1);
        let keypair2 = Keypair::from_seed(&seed2);
        let message = b"test message";

        let signature = keypair1.sign(message);
        assert!(verify(message, &signature, &keypair2.public).is_err());
    }

    #[test]
    fn test_context_signature() {
        let seed = [42u8; 57];
        let keypair = Keypair::from_seed(&seed);
        let message = b"test message";
        let context = b"test context";

        let signature = keypair.sign_with_context(message, context);
        let result = keypair.verify_with_context(message, &signature, context);
        assert!(result.is_ok());

        let wrong_context = b"wrong context";
        assert!(
            keypair
                .verify_with_context(message, &signature, wrong_context)
                .is_err()
        );
    }
}
