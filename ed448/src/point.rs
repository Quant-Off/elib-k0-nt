#![allow(clippy::unusual_byte_groupings, clippy::question_mark, dead_code)]

use crate::field::FieldElement;
use crate::scalar::Scalar;
use core::ops::{Add, Neg, Sub};
use zeroize::Zeroize;

fn d_constant() -> FieldElement {
    // d = -39081 for Ed448-Goldilocks
    // 39081 = 0x98A9
    let mut bytes = [0u8; 56];
    bytes[0] = 0xa9;
    bytes[1] = 0x98;
    let neg = FieldElement::from_bytes(&bytes);
    -neg
}

// Ed448 기저점 B 의 y 좌표 (RFC 8032 §5.2.5), 리틀 엔디언 56바이트
const BASE_Y_BYTES: [u8; 56] = [
    0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98, 0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
    0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a, 0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
    0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b, 0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
    0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
];

#[derive(Clone, Copy, Debug)]
pub struct EdwardsPoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t: FieldElement,
}

impl EdwardsPoint {
    #[inline]
    pub const fn identity() -> Self {
        EdwardsPoint {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }

    pub fn basepoint() -> Self {
        let y = FieldElement::from_bytes(&BASE_Y_BYTES);
        let y2 = y.square();
        let d = d_constant();

        let u = y2 - FieldElement::one();
        let v = d * y2 - FieldElement::one();
        let v_inv = v.invert();
        let x2 = u * v_inv;

        let x = x2.sqrt().expect("basepoint x must exist");
        let x = if x.is_negative() { -x } else { x };

        EdwardsPoint {
            x,
            y,
            z: FieldElement::one(),
            t: x * y,
        }
    }

    pub fn from_bytes(bytes: &[u8; 57]) -> Option<Self> {
        let x_sign = (bytes[56] >> 7) & 1;

        let mut y_bytes = [0u8; 56];
        y_bytes.copy_from_slice(&bytes[..56]);
        let last_byte = bytes[56] & 0x7f;
        if last_byte != 0 {
            return None;
        }

        let y = FieldElement::from_bytes(&y_bytes);
        let y2 = y.square();
        let d = d_constant();

        let u = y2 - FieldElement::one();
        let v = d * y2 - FieldElement::one();
        let v_inv = v.invert();
        let x2 = u * v_inv;

        let x = x2.sqrt()?;
        let x = if (x.is_negative() as u8) != x_sign {
            -x
        } else {
            x
        };

        if x.is_zero() && x_sign == 1 {
            return None;
        }

        Some(EdwardsPoint {
            x,
            y,
            z: FieldElement::one(),
            t: x * y,
        })
    }

    pub fn to_bytes(self) -> [u8; 57] {
        let z_inv = self.z.invert();
        let x = self.x * z_inv;
        let y = self.y * z_inv;

        let mut bytes = [0u8; 57];
        let y_bytes = y.to_bytes();
        bytes[..56].copy_from_slice(&y_bytes);
        bytes[56] = (x.is_negative() as u8) << 7;
        bytes
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        let x1z2 = self.x * other.z;
        let x2z1 = other.x * self.z;
        let y1z2 = self.y * other.z;
        let y2z1 = other.y * self.z;

        x1z2 == x2z1 && y1z2 == y2z1
    }

    fn add_internal(&self, other: &Self) -> Self {
        let d = d_constant();

        let a = self.x * other.x;
        let b = self.y * other.y;
        let c = self.t * d * other.t;
        let dd = self.z * other.z;

        let e = (self.x + self.y) * (other.x + other.y) - a - b;
        let f = dd - c;
        let g = dd + c;
        let h = b - a;

        EdwardsPoint {
            x: e * f,
            y: g * h,
            z: f * g,
            t: e * h,
        }
    }

    fn double_internal(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().double();
        let d = a;

        let e = (self.x + self.y).square() - a - b;
        let g = d + b;
        let f = g - c;
        let h = d - b;

        EdwardsPoint {
            x: e * f,
            y: g * h,
            z: f * g,
            t: e * h,
        }
    }

    pub fn scalar_mul(&self, scalar: &Scalar) -> Self {
        // 스칼라 바이트는 비밀일 수 있으므로 사용 후 명시적 소거
        let mut s = scalar.to_bytes();
        let mut result = EdwardsPoint::identity();

        for i in (0..448).rev() {
            result = result.double_internal();

            let byte_idx = i / 8;
            let bit_idx = i % 8;
            if byte_idx < 57 {
                let bit = (s[byte_idx] >> bit_idx) & 1;
                if bit == 1 {
                    result = result.add_internal(self);
                }
            }
        }

        // 스칼라 사본 명시적 소거
        s.zeroize();
        result
    }

    pub fn basepoint_mul(scalar: &Scalar) -> Self {
        Self::basepoint().scalar_mul(scalar)
    }

    pub fn double_scalar_mul_basepoint(a: &Scalar, point_a: &Self, b: &Scalar) -> Self {
        let a_point = point_a.scalar_mul(a);
        let b_point = Self::basepoint_mul(b);
        a_point.add_internal(&b_point)
    }
}

impl Add for EdwardsPoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        self.add_internal(&rhs)
    }
}

impl Sub for EdwardsPoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.add_internal(&(-rhs))
    }
}

impl Neg for EdwardsPoint {
    type Output = Self;

    fn neg(self) -> Self {
        EdwardsPoint {
            x: -self.x,
            y: self.y,
            z: self.z,
            t: -self.t,
        }
    }
}

impl PartialEq for EdwardsPoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for EdwardsPoint {}

impl Zeroize for EdwardsPoint {
    #[inline]
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
        self.t.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity() {
        let id = EdwardsPoint::identity();
        let b = EdwardsPoint::basepoint();
        assert_eq!(id + b, b);
    }

    #[test]
    fn test_scalar_mul_identity() {
        let b = EdwardsPoint::basepoint();
        let one = Scalar::one();
        let result = b.scalar_mul(&one);
        assert_eq!(result, b);
    }

    #[test]
    fn test_scalar_mul_associativity() {
        use crate::scalar::sc_muladd;
        let b = EdwardsPoint::basepoint();

        // 2^224 = 256^28 테스트
        // s = 2^224
        let mut s_bytes = [0u8; 57];
        s_bytes[28] = 1;
        let s = Scalar::from_bytes(s_bytes);
        eprintln!("s (2^224) bytes: {:?}", &s.0[26..32]);

        // s^2 = 2^448 (mod L)
        let s_squared = sc_muladd(&s, &s, &Scalar::zero());
        eprintln!("s^2 (2^448 mod L) bytes: {:?}", &s_squared.0[..15]);

        // 2^448 mod L을 수동으로 계산해서 비교
        // L ≈ 2^446 이므로 2^448 = 4 * 2^446 = 4 * (L + c) = 4c (mod L)
        // c = 2^446 - L

        // s*B
        let s_b = b.scalar_mul(&s);
        eprintln!("s*B (2^224 * B) bytes: {:?}", &s_b.to_bytes()[..10]);

        // s*(s*B) = s^2 * B (in group theory)
        let s_times_s_b = s_b.scalar_mul(&s);
        eprintln!("s*(s*B) bytes: {:?}", &s_times_s_b.to_bytes()[..10]);

        // (s^2)*B
        let s_squared_b = b.scalar_mul(&s_squared);
        eprintln!("(s^2)*B bytes: {:?}", &s_squared_b.to_bytes()[..10]);

        // 비교
        eprintln!("s*(s*B) == (s^2)*B: {}", s_times_s_b.ct_eq(&s_squared_b));

        // 더 단순한 테스트: (2*s) * B vs 2 * (s*B)
        let two = Scalar::from_bytes({
            let mut b = [0u8; 57];
            b[0] = 2;
            b
        });
        let two_s = sc_muladd(&two, &s, &Scalar::zero());
        eprintln!("2*s bytes: {:?}", &two_s.0[26..32]);

        let two_s_b = b.scalar_mul(&two_s);
        let two_times_s_b = s_b.scalar_mul(&two);
        eprintln!("(2*s)*B == 2*(s*B): {}", two_s_b.ct_eq(&two_times_s_b));

        // 2*s는 2^225, 아직 L보다 작으므로 정확해야 함
        // s^2 = 2^448, L보다 큼 -> 축소 필요

        // 확인: s^2가 정확히 계산되는지
        // 2^448 mod L을 정확히 계산하려면...
        // 일단 포인트 연산이 맞다고 가정하고, s^2 값이 틀렸는지 확인

        // L의 역원을 이용해서 확인할 수 없음 (순환 논리)
        // 대신: s * (s*B)가 맞다고 가정하면, 이것과 일치하는 scalar k를 찾아야 함

        assert!(s_times_s_b.ct_eq(&s_squared_b), "2^224 squared test failed");
    }
}
