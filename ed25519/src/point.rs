//! Edwards 곡선 점 연산 모듈입니다.
//!
//! Ed25519 곡선: -x^2 + y^2 = 1 + d*x^2*y^2
//! d = -121665/121666

#![allow(
    clippy::unusual_byte_groupings,
    clippy::wrong_self_convention,
    clippy::question_mark,
    dead_code,
    unused_variables,
    unused_mut
)]

use crate::field::FieldElement;
use crate::scalar::Scalar;
use core::ops::{Add, Neg, Sub};

/// 곡선 파라미터 d = -121665/121666 mod p
/// RFC 8032 리틀 엔디언 바이트:
/// a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352
fn d_constant() -> FieldElement {
    let d_bytes: [u8; 32] = [
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70,
        0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c,
        0x03, 0x52,
    ];
    FieldElement::from_bytes(&d_bytes)
}

fn d2_constant() -> FieldElement {
    d_constant().double()
}

/// 기저점 B의 y 좌표
/// y = 4/5 mod p
const BASE_Y: FieldElement = FieldElement([
    0x6666666666658,
    0x4CCCCCCCCCCCC,
    0x1999999999999,
    0x3333333333333,
    0x6666666666666,
]);

/// 기저점 B의 x 좌표 (양수 제곱근 선택)
const BASE_X: FieldElement = FieldElement([
    0x62D608F25D51A,
    0x412A4B4F6592A,
    0x75B7171A4B31D,
    0x1FF60527118FE,
    0x216936D3CD6E5,
]);

/// 확장 좌표계의 Edwards 점입니다.
///
/// (X, Y, Z, T) where x = X/Z, y = Y/Z, x*y = T/Z
/// 항등원은 (0, 1, 1, 0)입니다.
#[derive(Clone, Copy, Debug)]
pub struct EdwardsPoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t: FieldElement,
}

impl EdwardsPoint {
    /// 항등원 (중립원)을 반환합니다.
    #[inline]
    pub const fn identity() -> Self {
        EdwardsPoint {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }

    /// 기저점 B를 반환합니다.
    pub fn basepoint() -> Self {
        EdwardsPoint {
            x: BASE_X,
            y: BASE_Y,
            z: FieldElement::one(),
            t: BASE_X * BASE_Y,
        }
    }

    /// 32바이트 압축 표현에서 점을 디코딩합니다.
    ///
    /// RFC 8032 Section 5.1.3에 따라 y 좌표와 x의 부호 비트에서 복원합니다.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        // 최상위 비트는 x의 부호
        let x_sign = (bytes[31] >> 7) & 1;

        // y 좌표 추출 (최상위 비트 클리어)
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7F;
        let y = FieldElement::from_bytes(&y_bytes);

        // x^2 = (y^2 - 1) / (d*y^2 + 1) 계산
        let y2 = y.square();
        let u = y2 - FieldElement::one(); // y^2 - 1
        let v = d_constant() * y2 + FieldElement::one(); // d*y^2 + 1

        // x = sqrt(u/v)
        let v_inv = v.invert();
        let uv_inv = u * v_inv;

        let x = match uv_inv.sqrt() {
            Some(x) => x,
            None => return None, // 곡선 위의 점이 아님
        };

        // x의 부호 확인
        let x = if (x.is_negative() as u8) != x_sign {
            -x
        } else {
            x
        };

        // x == 0이고 x_sign == 1이면 유효하지 않음
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

    /// 점을 32바이트 압축 표현으로 인코딩합니다.
    ///
    /// y 좌표의 하위 255비트와 x의 부호 비트(최상위)를 저장합니다.
    pub fn to_bytes(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x * z_inv;
        let y = self.y * z_inv;

        let mut bytes = y.to_bytes();
        bytes[31] |= (x.is_negative() as u8) << 7;
        bytes
    }

    /// 두 점이 같은지 확인합니다.
    pub fn ct_eq(&self, other: &Self) -> bool {
        // (X1/Z1, Y1/Z1) == (X2/Z2, Y2/Z2)
        // X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1
        let x1z2 = self.x * other.z;
        let x2z1 = other.x * self.z;
        let y1z2 = self.y * other.z;
        let y2z1 = other.y * self.z;

        x1z2 == x2z1 && y1z2 == y2z1
    }

    /// 점 덧셈 (확장 좌표계)
    ///
    /// RFC 8032 및 "Twisted Edwards Curves Revisited" 논문 참조
    fn add_internal(&self, other: &Self) -> Self {
        // 통합 덧셈 공식 (complete addition formula)
        // C = d * T1 * T2 (NOT 2*d)
        let a = self.x * other.x;
        let b = self.y * other.y;
        let c = self.t * d_constant() * other.t;
        let d = self.z * other.z;

        let e = (self.x + self.y) * (other.x + other.y) - a - b;
        let f = d - c;
        let g = d + c;
        let h = b + a; // -x^2 + y^2 커브이므로 b - (-a) = b + a

        // 실제로는 -x^2 + y^2 = 1 + d*x^2*y^2
        // a 커브이므로 a = -1
        let h = b - a * FieldElement::from_bytes(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ]); // a = -1이므로 h = b - a = b - (-1)*a = b + a

        // 단순화: Ed25519는 a = -1
        let h = b + a;

        EdwardsPoint {
            x: e * f,
            y: g * h,
            z: f * g,
            t: e * h,
        }
    }

    /// 점 더블링
    fn double_internal(&self) -> Self {
        // 더블링 공식
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().double();
        let d = -a; // a = -1이므로 a*X^2 = -X^2

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

    /// 스칼라 곱셈: s * P
    pub fn scalar_mul(&self, scalar: &Scalar) -> Self {
        // 고정-윈도우 방식 (4-bit window)
        // 또는 간단한 double-and-add

        let s = scalar.to_bytes();
        let mut result = EdwardsPoint::identity();

        // MSB부터 double-and-add
        for i in (0..256).rev() {
            result = result.double_internal();

            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = (s[byte_idx] >> bit_idx) & 1;

            if bit == 1 {
                result = result.add_internal(self);
            }
        }

        result
    }

    /// 기저점의 스칼라 곱셈: s * B
    pub fn basepoint_mul(scalar: &Scalar) -> Self {
        Self::basepoint().scalar_mul(scalar)
    }

    /// 이중 스칼라 곱셈: a*A + b*B
    ///
    /// 검증에서 사용됩니다. Straus/Shamir 기법으로 최적화 가능.
    pub fn double_scalar_mul_basepoint(a: &Scalar, point_a: &Self, b: &Scalar) -> Self {
        // 간단한 구현: 별도 계산 후 덧셈
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity() {
        let id = EdwardsPoint::identity();
        let b = EdwardsPoint::basepoint();
        assert_eq!(id + b, b);
    }

    fn check_on_curve(p: &EdwardsPoint, name: &str) -> bool {
        let z_inv = p.z.invert();
        let x = p.x * z_inv;
        let y = p.y * z_inv;

        let x2 = x.square();
        let y2 = y.square();
        let lhs = y2 - x2;
        let rhs = FieldElement::one() + d_constant() * x2 * y2;

        let on_curve = lhs == rhs;
        if !on_curve {
            eprintln!("{} NOT on curve!", name);
        }
        on_curve
    }

    #[test]
    fn test_double_on_curve() {
        let b = EdwardsPoint::basepoint();
        assert!(check_on_curve(&b, "B"));

        // 더블 테스트
        let b2 = b.double_internal();
        assert!(check_on_curve(&b2, "2*B (double)"));

        // add로 2*B 테스트
        let b2_add = b + b;
        assert!(check_on_curve(&b2_add, "2*B (add)"));

        // identity + B 테스트
        let id = EdwardsPoint::identity();
        let id_plus_b = id + b;
        assert!(check_on_curve(&id_plus_b, "0 + B"));

        // B + identity 테스트
        let b_plus_id = b + id;
        assert!(check_on_curve(&b_plus_id, "B + 0"));

        // 2*B + B 테스트
        let b3 = b2 + b;
        eprintln!("Computing 3*B = 2*B + B");
        assert!(check_on_curve(&b3, "3*B"));

        let b4 = b2.double_internal();
        assert!(check_on_curve(&b4, "4*B"));
    }

    #[test]
    fn test_basepoint_y_coordinate() {
        // RFC 8032: y = 4/5 mod p
        // 리틀 엔디언 바이트:
        // 5866666666666666666666666666666666666666666666666666666666666666
        let expected_y: [u8; 32] = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];
        let base_y_bytes = BASE_Y.to_bytes();
        assert_eq!(base_y_bytes, expected_y, "BASE_Y mismatch");
    }

    #[test]
    fn test_basepoint_on_curve() {
        // 곡선 방정식 검증: -x^2 + y^2 = 1 + d*x^2*y^2
        let x = BASE_X;
        let y = BASE_Y;

        let x2 = x.square();
        let y2 = y.square();

        // LHS: -x^2 + y^2 = y^2 - x^2
        let lhs = y2 - x2;

        // RHS: 1 + d*x^2*y^2
        let rhs = FieldElement::one() + d_constant() * x2 * y2;

        eprintln!("LHS (y^2 - x^2) bytes: {:02x?}", lhs.to_bytes());
        eprintln!("RHS (1 + d*x^2*y^2) bytes: {:02x?}", rhs.to_bytes());

        assert_eq!(lhs, rhs, "Basepoint should satisfy curve equation");
    }

    #[test]
    fn test_d_constant() {
        // d = -121665/121666 mod p
        // d 바이트 (RFC 8032):
        // a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352
        let expected_d: [u8; 32] = [
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a,
            0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b,
            0xee, 0x6c, 0x03, 0x52,
        ];
        let d_bytes = d_constant().to_bytes();
        eprintln!("D bytes: {:02x?}", d_bytes);
        eprintln!("Expected: {:02x?}", expected_d);
        assert_eq!(d_bytes, expected_d, "D constant mismatch");
    }

    #[test]
    fn test_basepoint_x_coordinate() {
        // RFC 8032: x 좌표 (양수 제곱근)
        // 리틀 엔디언 바이트:
        // 216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
        let expected_x: [u8; 32] = [
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7,
            0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd,
            0xd3, 0x36, 0x69, 0x21,
        ];
        let base_x_bytes = BASE_X.to_bytes();
        assert_eq!(base_x_bytes, expected_x, "BASE_X mismatch");
    }

    #[test]
    fn test_basepoint_encode_decode() {
        let b = EdwardsPoint::basepoint();
        let bytes = b.to_bytes();

        // RFC 8032 기저점 압축 형식:
        // 5866666666666666666666666666666666666666666666666666666666666658
        // (y 좌표 + x의 부호 비트)
        eprintln!("Encoded bytes: {:02x?}", bytes);

        // 수동으로 from_bytes 디버깅
        let x_sign = (bytes[31] >> 7) & 1;
        eprintln!("x_sign: {}", x_sign);

        let mut y_bytes = bytes;
        y_bytes[31] &= 0x7F;
        let y = FieldElement::from_bytes(&y_bytes);
        eprintln!("y decoded, is BASE_Y: {}", y == BASE_Y);

        // x^2 = (y^2 - 1) / (d*y^2 + 1)
        let y2 = y.square();
        let u = y2 - FieldElement::one();
        let v = d_constant() * y2 + FieldElement::one();
        let v_inv = v.invert();
        let uv = u * v_inv;

        eprintln!("Attempting sqrt of u/v...");
        let sqrt_result = uv.sqrt();
        eprintln!("sqrt result is_some: {}", sqrt_result.is_some());

        if let Some(x) = sqrt_result {
            eprintln!("x computed, checking against BASE_X");
            let x_final = if (x.is_negative() as u8) != x_sign {
                -x
            } else {
                x
            };
            eprintln!("x_final == BASE_X: {}", x_final == BASE_X);
        }

        let b2 = EdwardsPoint::from_bytes(&bytes).unwrap();
        assert_eq!(b, b2);
    }

    #[test]
    fn test_scalar_mul_identity() {
        let b = EdwardsPoint::basepoint();
        let one = Scalar::one();
        let result = b.scalar_mul(&one);
        assert_eq!(result, b);
    }

    #[test]
    fn test_scalar_mul_encode_decode() {
        // 임의의 스칼라로 곱한 점을 인코딩/디코딩
        let b = EdwardsPoint::basepoint();
        let scalar = Scalar::from_bytes([42u8; 32]);
        let point = b.scalar_mul(&scalar);

        // 점이 곡선 위에 있는지 확인
        let z_inv = point.z.invert();
        let x_norm = point.x * z_inv;
        let y_norm = point.y * z_inv;

        let x2 = x_norm.square();
        let y2 = y_norm.square();
        let lhs = y2 - x2;
        let rhs = FieldElement::one() + d_constant() * x2 * y2;

        eprintln!("Point on curve check:");
        eprintln!("  LHS: {:02x?}", lhs.to_bytes());
        eprintln!("  RHS: {:02x?}", rhs.to_bytes());
        eprintln!("  Equal: {}", lhs == rhs);

        let bytes = point.to_bytes();
        eprintln!("Point bytes: {:02x?}", bytes);

        // from_bytes 디버깅
        let x_sign = (bytes[31] >> 7) & 1;
        eprintln!("x_sign: {}", x_sign);

        let mut y_bytes = bytes;
        y_bytes[31] &= 0x7F;
        let y = FieldElement::from_bytes(&y_bytes);

        let y2 = y.square();
        let u = y2 - FieldElement::one();
        let v = d_constant() * y2 + FieldElement::one();
        let v_inv = v.invert();
        let uv = u * v_inv;

        eprintln!("u/v (should be x^2): {:02x?}", uv.to_bytes());
        eprintln!("Actual x^2: {:02x?}", x2.to_bytes());
        eprintln!("u/v == x^2: {}", uv == x2);

        let sqrt_result = uv.sqrt();
        eprintln!("sqrt exists: {}", sqrt_result.is_some());

        let decoded = EdwardsPoint::from_bytes(&bytes);
        assert!(decoded.is_some(), "Point should be decodable");
        let decoded_point = decoded.unwrap();

        // 디코딩된 점이 원래 점과 같아야 함
        assert_eq!(point, decoded_point, "Decoded point should equal original");
    }
}
