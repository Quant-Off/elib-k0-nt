//! X448 키 교환 알고리즘이 구현된 모듈입니다.
//!
//! RFC 7748 표준을 준수하며, Curve448 (Goldilocks) 타원 곡선을 사용합니다.
//!
//! # Features
//! - **RFC 7748 준수**: X448 명세 완전 구현
//! - **상수-시간 연산**: Montgomery ladder를 통한 타이밍 공격 방지
//! - **자동 메모리 소거**: 비밀키와 공유 비밀은 Drop 시 자동 제로화
//! - **no_std 지원**: 베어메탈/임베디드 환경에서 사용 가능
//! - **224비트 보안 강도**: X25519보다 높은 보안 수준 제공
//!
//! # Examples
//! ```rust,ignore
//! use x448::{SecretKey, PublicKey};
//!
//! // Alice 키쌍 생성
//! let alice_secret = SecretKey::from_bytes(alice_random_bytes);
//! let alice_public = alice_secret.public_key();
//!
//! // Bob 키쌍 생성
//! let bob_secret = SecretKey::from_bytes(bob_random_bytes);
//! let bob_public = bob_secret.public_key();
//!
//! // 공유 비밀 계산
//! let alice_shared = alice_secret.diffie_hellman(&bob_public);
//! let bob_shared = bob_secret.diffie_hellman(&alice_public);
//!
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//! ```
//!
//! # Authors
//! Q. T. Felix

#![cfg_attr(not(test), no_std)]

mod field;

use constant_time::{Choice, CtEqOps};
use field::FieldElement;
use zeroize::{Secret, Zeroize};

const BASEPOINT_U: [u8; 56] = [
    5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub struct SecretKey(Secret<[u8; 56]>);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; 56]) -> Self {
        SecretKey(Secret::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 56] {
        self.0.expose()
    }

    pub fn public_key(&self) -> PublicKey {
        let public_bytes = x448_base(self.0.expose());
        PublicKey(public_bytes)
    }

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        let mut shared = x448(self.0.expose(), &their_public.0);
        let result = SharedSecret(Secret::new(shared));
        shared.zeroize();
        result
    }
}

pub struct PublicKey([u8; 56]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 56]) -> Self {
        PublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.0
    }
}

pub struct SharedSecret(Secret<[u8; 56]>);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 56] {
        self.0.expose()
    }

    pub fn is_zero(&self) -> bool {
        let mut acc = 0u8;
        for b in self.0.expose() {
            acc |= *b;
        }
        acc == 0
    }
}

fn clamp_scalar(k: &mut [u8; 56]) {
    k[0] &= 0xFC;
    k[55] |= 0x80;
}

fn x448_base(k: &[u8; 56]) -> [u8; 56] {
    x448(k, &BASEPOINT_U)
}

fn x448(k: &[u8; 56], u: &[u8; 56]) -> [u8; 56] {
    let mut scalar = Secret::new(*k);
    clamp_scalar(scalar.expose_mut());
    montgomery_ladder(scalar.expose(), u)
    // scalar 는 스코프 종료 시 Secret::Drop 으로 자동 소거
}

fn montgomery_ladder(k: &[u8; 56], u: &[u8; 56]) -> [u8; 56] {
    let mut u_coord = FieldElement::from_bytes(u);

    let mut x_1 = u_coord;
    let mut x_2 = FieldElement::one();
    let mut z_2 = FieldElement::zero();
    let mut x_3 = u_coord;
    let mut z_3 = FieldElement::one();

    let mut swap: u8 = 0;

    for pos in (0..448).rev() {
        let byte_idx = pos / 8;
        let bit_idx = pos % 8;
        let k_t = (k[byte_idx] >> bit_idx) & 1;

        swap ^= k_t;
        let choice = Choice::from_u8(swap);
        FieldElement::conditional_swap(&mut x_2, &mut x_3, choice);
        FieldElement::conditional_swap(&mut z_2, &mut z_3, choice);
        swap = k_t;

        let a = x_2 + z_2;
        let aa = a.square();
        let b = x_2 - z_2;
        let bb = b.square();
        let e = aa - bb;
        let c = x_3 + z_3;
        let d = x_3 - z_3;
        let da = d * a;
        let cb = c * b;
        let sum = da + cb;
        let diff = da - cb;
        x_3 = sum.square();
        z_3 = x_1 * diff.square();
        x_2 = aa * bb;
        let a24_e = mul_by_a24(e);
        z_2 = e * (aa + a24_e);
    }

    let choice = Choice::from_u8(swap);
    FieldElement::conditional_swap(&mut x_2, &mut x_3, choice);
    FieldElement::conditional_swap(&mut z_2, &mut z_3, choice);

    let mut z_2_inv = z_2.invert();
    let mut result = x_2 * z_2_inv;
    let bytes = result.to_bytes();

    // 민감 중간값 명시적 소거
    u_coord.zeroize();
    x_1.zeroize();
    x_2.zeroize();
    z_2.zeroize();
    x_3.zeroize();
    z_3.zeroize();
    z_2_inv.zeroize();
    result.zeroize();
    swap.zeroize();

    bytes
}

fn mul_by_a24(e: FieldElement) -> FieldElement {
    let a = &e.0;
    let a24: u64 = 39081;

    let mut c = [0u128; 8];
    for i in 0..8 {
        c[i] = (a[i] as u128) * (a24 as u128);
    }

    let mask = (1u128 << 56) - 1;

    let carry = c[0] >> 56;
    c[0] &= mask;
    c[1] += carry;

    let carry = c[1] >> 56;
    c[1] &= mask;
    c[2] += carry;

    let carry = c[2] >> 56;
    c[2] &= mask;
    c[3] += carry;

    let carry = c[3] >> 56;
    c[3] &= mask;
    c[4] += carry;

    let carry = c[4] >> 56;
    c[4] &= mask;
    c[5] += carry;

    let carry = c[5] >> 56;
    c[5] &= mask;
    c[6] += carry;

    let carry = c[6] >> 56;
    c[6] &= mask;
    c[7] += carry;

    let carry = c[7] >> 56;
    c[7] &= mask;

    c[0] += carry;
    c[4] += carry;

    FieldElement([
        c[0] as u64,
        c[1] as u64,
        c[2] as u64,
        c[3] as u64,
        c[4] as u64,
        c[5] as u64,
        c[6] as u64,
        c[7] as u64,
    ])
}

pub fn generate_keypair<R: FnMut(&mut [u8])>(mut rng: R) -> (SecretKey, PublicKey) {
    let mut secret_bytes = [0u8; 56];
    rng(&mut secret_bytes);
    let secret = SecretKey::from_bytes(secret_bytes);
    secret_bytes.zeroize();
    let public = secret.public_key();
    (secret, public)
}

pub fn is_contributory(shared: &SharedSecret) -> Choice {
    let mut acc = 0u8;
    for b in shared.0.expose().iter() {
        acc |= *b;
    }
    CtEqOps::ne(&acc, &0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    /// SecretKey 의 Drop 으로 내부 56바이트가 0 으로 소거되는지 검증.
    #[test]
    fn test_secret_key_zeroize_on_drop() {
        let pattern: u8 = 0xAB;
        let mut storage: MaybeUninit<SecretKey> = MaybeUninit::uninit();

        unsafe {
            storage.write(SecretKey::from_bytes([pattern; 56]));
            let ptr = storage.assume_init_ref().as_bytes().as_ptr();

            let pre = core::slice::from_raw_parts(ptr, 56);
            assert!(pre.iter().all(|&b| b == pattern), "초기 패턴 미반영");

            storage.assume_init_drop();

            let post = core::slice::from_raw_parts(ptr, 56);
            assert!(
                post.iter().all(|&b| b == 0),
                "SecretKey 메모리가 Drop 후 소거되지 않음: {:?}",
                post
            );
        }
    }

    /// SharedSecret 의 Drop 으로 내부 56바이트가 0 으로 소거되는지 검증.
    #[test]
    fn test_shared_secret_zeroize_on_drop() {
        let alice_secret = SecretKey::from_bytes([0x11; 56]);
        let bob_secret = SecretKey::from_bytes([0x22; 56]);
        let bob_pk = bob_secret.public_key();

        let mut storage: MaybeUninit<SharedSecret> = MaybeUninit::uninit();

        unsafe {
            storage.write(alice_secret.diffie_hellman(&bob_pk));
            let ptr = storage.assume_init_ref().as_bytes().as_ptr();

            let pre = core::slice::from_raw_parts(ptr, 56);
            let nonzero = pre.iter().any(|&b| b != 0);
            assert!(nonzero, "공유 비밀이 비어 있음 — 테스트 전제 위반");

            storage.assume_init_drop();

            let post = core::slice::from_raw_parts(ptr, 56);
            assert!(
                post.iter().all(|&b| b == 0),
                "SharedSecret 메모리가 Drop 후 소거되지 않음: {:?}",
                post
            );
        }
    }

    /// FieldElement::zeroize 가 8개 limb 를 모두 0 으로 만드는지 검증.
    #[test]
    fn test_field_element_zeroize() {
        let mut fe = FieldElement::from_bytes(&[0xCD; 56]);
        let any_nonzero_before = fe.0.iter().any(|&w| w != 0);
        assert!(any_nonzero_before, "FieldElement 가 비어 있음");

        fe.zeroize();

        for (i, w) in fe.0.iter().enumerate() {
            assert_eq!(*w, 0, "FieldElement.0[{}] 미소거: {:#x}", i, w);
        }
    }

    /// SecretKey 내부 사본은 입력 버퍼와 분리되어 있고, Drop 만으로 사본만 소거됨을 확인.
    #[test]
    fn test_secret_key_drop_does_not_touch_input() {
        let input = [0x55u8; 56];
        let mut storage: MaybeUninit<SecretKey> = MaybeUninit::uninit();

        unsafe {
            storage.write(SecretKey::from_bytes(input));
            let internal_ptr = storage.assume_init_ref().as_bytes().as_ptr();
            assert_ne!(
                internal_ptr,
                input.as_ptr(),
                "SecretKey 가 입력 버퍼를 공유하면 안 됨"
            );
            storage.assume_init_drop();

            let post = core::slice::from_raw_parts(internal_ptr, 56);
            assert!(post.iter().all(|&b| b == 0), "내부 사본 미소거");
        }
        assert!(input.iter().all(|&b| b == 0x55), "입력 버퍼가 변경됨");
    }

    #[test]
    fn test_rfc7748_vector_1() {
        let scalar: [u8; 56] = [
            0x3d, 0x26, 0x2f, 0xdd, 0xf9, 0xec, 0x8e, 0x88, 0x49, 0x52, 0x66, 0xfe, 0xa1, 0x9a,
            0x34, 0xd2, 0x88, 0x82, 0xac, 0xef, 0x04, 0x51, 0x04, 0xd0, 0xd1, 0xaa, 0xe1, 0x21,
            0x70, 0x0a, 0x77, 0x9c, 0x98, 0x4c, 0x24, 0xf8, 0xcd, 0xd7, 0x8f, 0xbf, 0xf4, 0x49,
            0x43, 0xeb, 0xa3, 0x68, 0xf5, 0x4b, 0x29, 0x25, 0x9a, 0x4f, 0x1c, 0x60, 0x0a, 0xd3,
        ];
        let u_coord: [u8; 56] = [
            0x06, 0xfc, 0xe6, 0x40, 0xfa, 0x34, 0x87, 0xbf, 0xda, 0x5f, 0x6c, 0xf2, 0xd5, 0x26,
            0x3f, 0x8a, 0xad, 0x88, 0x33, 0x4c, 0xbd, 0x07, 0x43, 0x7f, 0x02, 0x0f, 0x08, 0xf9,
            0x81, 0x4d, 0xc0, 0x31, 0xdd, 0xbd, 0xc3, 0x8c, 0x19, 0xc6, 0xda, 0x25, 0x83, 0xfa,
            0x54, 0x29, 0xdb, 0x94, 0xad, 0xa1, 0x8a, 0xa7, 0xa7, 0xfb, 0x4e, 0xf8, 0xa0, 0x86,
        ];
        let expected: [u8; 56] = [
            0xce, 0x3e, 0x4f, 0xf9, 0x5a, 0x60, 0xdc, 0x66, 0x97, 0xda, 0x1d, 0xb1, 0xd8, 0x5e,
            0x6a, 0xfb, 0xdf, 0x79, 0xb5, 0x0a, 0x24, 0x12, 0xd7, 0x54, 0x6d, 0x5f, 0x23, 0x9f,
            0xe1, 0x4f, 0xba, 0xad, 0xeb, 0x44, 0x5f, 0xc6, 0x6a, 0x01, 0xb0, 0x77, 0x9d, 0x98,
            0x22, 0x39, 0x61, 0x11, 0x1e, 0x21, 0x76, 0x62, 0x82, 0xf7, 0x3d, 0xd9, 0x6b, 0x6f,
        ];

        let result = x448(&scalar, &u_coord);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_rfc7748_vector_2() {
        let scalar: [u8; 56] = [
            0x20, 0x3d, 0x49, 0x44, 0x28, 0xb8, 0x39, 0x93, 0x52, 0x66, 0x5d, 0xdc, 0xa4, 0x2f,
            0x9d, 0xe8, 0xfe, 0xf6, 0x00, 0x90, 0x8e, 0x0d, 0x46, 0x1c, 0xb0, 0x21, 0xf8, 0xc5,
            0x38, 0x34, 0x5d, 0xd7, 0x7c, 0x3e, 0x48, 0x06, 0xe2, 0x5f, 0x46, 0xd3, 0x31, 0x5c,
            0x44, 0xe0, 0xa5, 0xb4, 0x37, 0x12, 0x82, 0xdd, 0x2c, 0x8d, 0x5b, 0xe3, 0x09, 0x5f,
        ];
        let u_coord: [u8; 56] = [
            0x0f, 0xbc, 0xc2, 0xf9, 0x93, 0xcd, 0x56, 0xd3, 0x30, 0x5b, 0x0b, 0x7d, 0x9e, 0x55,
            0xd4, 0xc1, 0xa8, 0xfb, 0x5d, 0xbb, 0x52, 0xf8, 0xe9, 0xa1, 0xe9, 0xb6, 0x20, 0x1b,
            0x16, 0x5d, 0x01, 0x58, 0x94, 0xe5, 0x6c, 0x4d, 0x35, 0x70, 0xbe, 0xe5, 0x2f, 0xe2,
            0x05, 0xe2, 0x8a, 0x78, 0xb9, 0x1c, 0xdf, 0xbd, 0xe7, 0x1c, 0xe8, 0xd1, 0x57, 0xdb,
        ];
        let expected: [u8; 56] = [
            0x88, 0x4a, 0x02, 0x57, 0x62, 0x39, 0xff, 0x7a, 0x2f, 0x2f, 0x63, 0xb2, 0xdb, 0x6a,
            0x9f, 0xf3, 0x70, 0x47, 0xac, 0x13, 0x56, 0x8e, 0x1e, 0x30, 0xfe, 0x63, 0xc4, 0xa7,
            0xad, 0x1b, 0x3e, 0xe3, 0xa5, 0x70, 0x0d, 0xf3, 0x43, 0x21, 0xd6, 0x20, 0x77, 0xe6,
            0x36, 0x33, 0xc5, 0x75, 0xc1, 0xc9, 0x54, 0x51, 0x4e, 0x99, 0xda, 0x7c, 0x17, 0x9d,
        ];

        let result = x448(&scalar, &u_coord);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_basepoint() {
        let scalar: [u8; 56] = [
            0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57, 0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58,
            0x00, 0xd4, 0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65, 0xd4, 0x98, 0xc2, 0x8d,
            0xd9, 0xc9, 0xba, 0xf5, 0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91, 0x00, 0x63,
            0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d, 0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
        ];
        let expected: [u8; 56] = [
            0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6, 0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21,
            0x07, 0x4a, 0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63, 0xfa, 0xa7, 0x3d, 0x2c,
            0x22, 0xc5, 0xd9, 0xbb, 0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4, 0x0c, 0x5b,
            0x12, 0xda, 0x88, 0x12, 0x0d, 0x53, 0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0,
        ];

        let result = x448_base(&scalar);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_dh_exchange() {
        let alice_secret: [u8; 56] = [
            0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57, 0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58,
            0x00, 0xd4, 0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65, 0xd4, 0x98, 0xc2, 0x8d,
            0xd9, 0xc9, 0xba, 0xf5, 0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91, 0x00, 0x63,
            0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d, 0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
        ];
        let bob_secret: [u8; 56] = [
            0x1c, 0x30, 0x6a, 0x7a, 0xc2, 0xa0, 0xe2, 0xe0, 0x99, 0x0b, 0x29, 0x44, 0x70, 0xcb,
            0xa3, 0x39, 0xe6, 0x45, 0x37, 0x72, 0xb0, 0x75, 0x81, 0x1d, 0x8f, 0xad, 0x0d, 0x1d,
            0x69, 0x27, 0xc1, 0x20, 0xbb, 0x5e, 0xe8, 0x97, 0x2b, 0x0d, 0x3e, 0x21, 0x37, 0x4c,
            0x9c, 0x92, 0x1b, 0x09, 0xd1, 0xb0, 0x36, 0x6f, 0x10, 0xb6, 0x51, 0x73, 0x99, 0x2d,
        ];

        let alice_sk = SecretKey::from_bytes(alice_secret);
        let bob_sk = SecretKey::from_bytes(bob_secret);

        let alice_pk = alice_sk.public_key();
        let bob_pk = bob_sk.public_key();

        let alice_shared = alice_sk.diffie_hellman(&bob_pk);
        let bob_shared = bob_sk.diffie_hellman(&alice_pk);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());

        let expected: [u8; 56] = [
            0x07, 0xff, 0xf4, 0x18, 0x1a, 0xc6, 0xcc, 0x95, 0xec, 0x1c, 0x16, 0xa9, 0x4a, 0x0f,
            0x74, 0xd1, 0x2d, 0xa2, 0x32, 0xce, 0x40, 0xa7, 0x75, 0x52, 0x28, 0x1d, 0x28, 0x2b,
            0xb6, 0x0c, 0x0b, 0x56, 0xfd, 0x24, 0x64, 0xc3, 0x35, 0x54, 0x39, 0x36, 0x52, 0x1c,
            0x24, 0x40, 0x30, 0x85, 0xd5, 0x9a, 0x44, 0x9a, 0x50, 0x37, 0x51, 0x4a, 0x87, 0x9d,
        ];
        assert_eq!(alice_shared.as_bytes(), &expected);
    }

    #[test]
    fn test_iteration_1() {
        let mut k = BASEPOINT_U;
        let mut u = BASEPOINT_U;

        for _ in 0..1 {
            let result = x448(&k, &u);
            u = k;
            k = result;
        }

        let expected: [u8; 56] = [
            0x3f, 0x48, 0x2c, 0x8a, 0x9f, 0x19, 0xb0, 0x1e, 0x6c, 0x46, 0xee, 0x97, 0x11, 0xd9,
            0xdc, 0x14, 0xfd, 0x4b, 0xf6, 0x7a, 0xf3, 0x07, 0x65, 0xc2, 0xae, 0x2b, 0x84, 0x6a,
            0x4d, 0x23, 0xa8, 0xcd, 0x0d, 0xb8, 0x97, 0x08, 0x62, 0x39, 0x49, 0x2c, 0xaf, 0x35,
            0x0b, 0x51, 0xf8, 0x33, 0x86, 0x8b, 0x9b, 0xc2, 0xb3, 0xbc, 0xa9, 0xcf, 0x41, 0x13,
        ];
        assert_eq!(k, expected);
    }

    #[test]
    fn test_iteration_1000() {
        let mut k = BASEPOINT_U;
        let mut u = BASEPOINT_U;

        for _ in 0..1000 {
            let result = x448(&k, &u);
            u = k;
            k = result;
        }

        let expected: [u8; 56] = [
            0xaa, 0x3b, 0x47, 0x49, 0xd5, 0x5b, 0x9d, 0xaf, 0x1e, 0x5b, 0x00, 0x28, 0x88, 0x26,
            0xc4, 0x67, 0x27, 0x4c, 0xe3, 0xeb, 0xbd, 0xd5, 0xc1, 0x7b, 0x97, 0x5e, 0x09, 0xd4,
            0xaf, 0x6c, 0x67, 0xcf, 0x10, 0xd0, 0x87, 0x20, 0x2d, 0xb8, 0x82, 0x86, 0xe2, 0xb7,
            0x9f, 0xce, 0xea, 0x3e, 0xc3, 0x53, 0xef, 0x54, 0xfa, 0xa2, 0x6e, 0x21, 0x9f, 0x38,
        ];
        assert_eq!(k, expected);
    }

    #[test]
    fn test_low_order_point_rejection() {
        let secret = SecretKey::from_bytes([1u8; 56]);
        let low_order_points: [[u8; 56]; 2] = [
            [0u8; 56],
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ];

        for low_order in &low_order_points {
            let public = PublicKey::from_bytes(*low_order);
            let shared = secret.diffie_hellman(&public);
            assert!(
                shared.is_zero(),
                "low-order point should produce zero shared secret"
            );
        }
    }
}
