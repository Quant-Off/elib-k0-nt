//! X25519 키 교환 알고리즘이 구현된 모듈입니다.
//!
//! RFC 7748 표준을 준수하며, Curve25519 타원 곡선을 사용합니다.
//!
//! # Features
//! - **RFC 7748 준수**: X25519 명세 완전 구현
//! - **상수-시간 연산**: Montgomery ladder를 통한 타이밍 공격 방지
//! - **자동 메모리 소거**: 비밀키와 공유 비밀은 Drop 시 자동 제로화
//! - **no_std 지원**: 베어메탈/임베디드 환경에서 사용 가능
//!
//! # Examples
//! ```rust,ignore
//! use x25519::{SecretKey, PublicKey};
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

const BASEPOINT_U: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub struct SecretKey(Secret<[u8; 32]>);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SecretKey(Secret::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.expose()
    }

    pub fn public_key(&self) -> PublicKey {
        let public_bytes = x25519_base(self.0.expose());
        PublicKey(public_bytes)
    }

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        let mut shared = x25519(self.0.expose(), &their_public.0);
        let result = SharedSecret(Secret::new(shared));
        shared.zeroize();
        result
    }
}

pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct SharedSecret(Secret<[u8; 32]>);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
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

fn clamp_scalar(k: &mut [u8; 32]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

fn x25519_base(k: &[u8; 32]) -> [u8; 32] {
    x25519(k, &BASEPOINT_U)
}

fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut scalar = Secret::new(*k);
    clamp_scalar(scalar.expose_mut());
    montgomery_ladder(scalar.expose(), u)
    // scalar 는 스코프 종료 시 Secret::Drop 으로 자동 소거
}

fn montgomery_ladder(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut u_coord = FieldElement::from_bytes(u);

    let mut x_1 = u_coord;
    let mut x_2 = FieldElement::one();
    let mut z_2 = FieldElement::zero();
    let mut x_3 = u_coord;
    let mut z_3 = FieldElement::one();

    let mut swap: u8 = 0;

    for pos in (0..255).rev() {
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
    let a24: u64 = 121665;

    let m = |x: u64| -> u128 { (x as u128) * (a24 as u128) };

    let mut c0 = m(a[0]);
    let mut c1 = m(a[1]);
    let mut c2 = m(a[2]);
    let mut c3 = m(a[3]);
    let mut c4 = m(a[4]);

    let mask51 = (1u128 << 51) - 1;

    let carry = c0 >> 51;
    c0 &= mask51;
    c1 += carry;

    let carry = c1 >> 51;
    c1 &= mask51;
    c2 += carry;

    let carry = c2 >> 51;
    c2 &= mask51;
    c3 += carry;

    let carry = c3 >> 51;
    c3 &= mask51;
    c4 += carry;

    let carry = c4 >> 51;
    c4 &= mask51;
    c0 += carry * 19;

    FieldElement([c0 as u64, c1 as u64, c2 as u64, c3 as u64, c4 as u64])
}

pub fn generate_keypair<R: FnMut(&mut [u8])>(mut rng: R) -> (SecretKey, PublicKey) {
    let mut secret_bytes = [0u8; 32];
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

    /// SecretKey 의 Drop 으로 내부 32바이트가 0 으로 소거되는지 검증.
    #[test]
    fn test_secret_key_zeroize_on_drop() {
        let pattern: u8 = 0xAB;
        let mut storage: MaybeUninit<SecretKey> = MaybeUninit::uninit();

        unsafe {
            storage.write(SecretKey::from_bytes([pattern; 32]));
            let ptr = storage.assume_init_ref().as_bytes().as_ptr();

            let pre = core::slice::from_raw_parts(ptr, 32);
            assert!(pre.iter().all(|&b| b == pattern), "초기 패턴 미반영");

            storage.assume_init_drop();

            let post = core::slice::from_raw_parts(ptr, 32);
            assert!(
                post.iter().all(|&b| b == 0),
                "SecretKey 메모리가 Drop 후 소거되지 않음: {:?}",
                post
            );
        }
    }

    /// SharedSecret 의 Drop 으로 내부 32바이트가 0 으로 소거되는지 검증.
    #[test]
    fn test_shared_secret_zeroize_on_drop() {
        let alice_secret = SecretKey::from_bytes([0x11; 32]);
        let bob_secret = SecretKey::from_bytes([0x22; 32]);
        let bob_pk = bob_secret.public_key();

        let mut storage: MaybeUninit<SharedSecret> = MaybeUninit::uninit();

        unsafe {
            storage.write(alice_secret.diffie_hellman(&bob_pk));
            let ptr = storage.assume_init_ref().as_bytes().as_ptr();

            let pre = core::slice::from_raw_parts(ptr, 32);
            let nonzero = pre.iter().any(|&b| b != 0);
            assert!(nonzero, "공유 비밀이 비어 있음 — 테스트 전제 위반");

            storage.assume_init_drop();

            let post = core::slice::from_raw_parts(ptr, 32);
            assert!(
                post.iter().all(|&b| b == 0),
                "SharedSecret 메모리가 Drop 후 소거되지 않음: {:?}",
                post
            );
        }
    }

    /// FieldElement::zeroize 가 5개 limb 를 모두 0 으로 만드는지 검증.
    #[test]
    fn test_field_element_zeroize() {
        let mut fe = FieldElement::from_bytes(&[0xCD; 32]);
        let any_nonzero_before = fe.0.iter().any(|&w| w != 0);
        assert!(any_nonzero_before, "FieldElement 가 비어 있음");

        fe.zeroize();

        for (i, w) in fe.0.iter().enumerate() {
            assert_eq!(*w, 0, "FieldElement.0[{}] 미소거: {:#x}", i, w);
        }
    }

    /// from_bytes 입력 버퍼는 Copy 이므로 SecretKey 내부 위치와 별개임을 확인 후
    /// SecretKey Drop 만으로 SecretKey 가 보유한 사본이 소거되는지 재차 확인.
    #[test]
    fn test_secret_key_drop_does_not_touch_input() {
        let input = [0x55u8; 32];
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

            let post = core::slice::from_raw_parts(internal_ptr, 32);
            assert!(post.iter().all(|&b| b == 0), "내부 사본 미소거");
        }
        // 입력 버퍼는 호출자 책임이므로 변경되지 않아야 함
        assert!(input.iter().all(|&b| b == 0x55), "입력 버퍼가 변경됨");
    }

    #[test]
    fn test_rfc7748_vector_1() {
        let scalar: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];
        let u_coord: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];

        let result = x25519(&scalar, &u_coord);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_rfc7748_vector_2() {
        let scalar: [u8; 32] = [
            0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d,
            0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e,
            0x79, 0x18, 0xba, 0x0d,
        ];
        let u_coord: [u8; 32] = [
            0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38,
            0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49,
            0xc7, 0x15, 0xa4, 0x93,
        ];
        let expected: [u8; 32] = [
            0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8,
            0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64,
            0x7a, 0xac, 0x79, 0x57,
        ];

        let result = x25519(&scalar, &u_coord);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_basepoint() {
        let scalar: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let expected: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];

        let result = x25519_base(&scalar);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_dh_exchange() {
        let alice_secret: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_secret: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];

        let alice_sk = SecretKey::from_bytes(alice_secret);
        let bob_sk = SecretKey::from_bytes(bob_secret);

        let alice_pk = alice_sk.public_key();
        let bob_pk = bob_sk.public_key();

        let alice_shared = alice_sk.diffie_hellman(&bob_pk);
        let bob_shared = bob_sk.diffie_hellman(&alice_pk);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());

        let expected: [u8; 32] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];
        assert_eq!(alice_shared.as_bytes(), &expected);
    }

    #[test]
    fn test_iteration_1() {
        let mut k = BASEPOINT_U;
        let mut u = BASEPOINT_U;

        for _ in 0..1 {
            let result = x25519(&k, &u);
            u = k;
            k = result;
        }

        let expected: [u8; 32] = [
            0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc, 0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7,
            0x27, 0x9f, 0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78, 0x3c, 0x60, 0xe8, 0x03,
            0x11, 0xae, 0x30, 0x79,
        ];
        assert_eq!(k, expected);
    }

    #[test]
    fn test_iteration_1000() {
        let mut k = BASEPOINT_U;
        let mut u = BASEPOINT_U;

        for _ in 0..1000 {
            let result = x25519(&k, &u);
            u = k;
            k = result;
        }

        let expected: [u8; 32] = [
            0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55, 0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f,
            0x4d, 0x3c, 0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87, 0x5f, 0x2e, 0xb9, 0x4d,
            0x99, 0x53, 0x2c, 0x51,
        ];
        assert_eq!(k, expected);
    }

    #[test]
    fn test_low_order_point_rejection() {
        let secret = SecretKey::from_bytes([1u8; 32]);
        let low_order_points: [[u8; 32]; 5] = [
            [0u8; 32],
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ],
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
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
