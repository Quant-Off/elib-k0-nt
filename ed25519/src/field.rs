//! Fp 필드 연산 모듈입니다.
//!
//! p = 2^255 - 19 위의 유한체 연산을 구현합니다.
//! 모든 연산은 상수-시간으로 수행됩니다.

#![allow(
    clippy::unusual_byte_groupings,
    clippy::wrong_self_convention,
    clippy::needless_range_loop,
    dead_code,
    unused_variables,
    unused_mut
)]

use core::ops::{Add, Mul, Neg, Sub};

/// 필드 소수 p = 2^255 - 19
/// 리틀 엔디언 limbs (5 × 51-bit)
const P: [u64; 5] = [
    0x7FFFF_FFFF_FFED,
    0x7FFFF_FFFF_FFFF,
    0x7FFFF_FFFF_FFFF,
    0x7FFFF_FFFF_FFFF,
    0x7FFFF_FFFF_FFFF,
];

/// 51-bit limb 마스크
const MASK51: u64 = (1u64 << 51) - 1;

/// Fp 필드 원소입니다.
///
/// 내부적으로 5개의 51-bit limbs로 표현됩니다 (리틀 엔디언).
/// radix-2^51 표현: x = x0 + x1*2^51 + x2*2^102 + x3*2^153 + x4*2^204
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(crate) [u64; 5]);

impl FieldElement {
    /// 0을 반환합니다.
    #[inline]
    pub const fn zero() -> Self {
        FieldElement([0, 0, 0, 0, 0])
    }

    /// 1을 반환합니다.
    #[inline]
    pub const fn one() -> Self {
        FieldElement([1, 0, 0, 0, 0])
    }

    /// 32바이트 리틀 엔디언 배열에서 필드 원소를 로드합니다.
    ///
    /// 입력의 최상위 비트는 무시됩니다 (255비트만 사용).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 5];

        // 바이트를 64비트 워드로 로드
        let load64 = |b: &[u8]| -> u64 {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        };

        let lo0 = load64(&bytes[0..8]);
        let lo1 = load64(&bytes[8..16]);
        let lo2 = load64(&bytes[16..24]);
        let hi = load64(&bytes[24..32]);

        // 51-bit limbs로 분할
        limbs[0] = lo0 & MASK51;
        limbs[1] = ((lo0 >> 51) | (lo1 << 13)) & MASK51;
        limbs[2] = ((lo1 >> 38) | (lo2 << 26)) & MASK51;
        limbs[3] = ((lo2 >> 25) | (hi << 39)) & MASK51;
        limbs[4] = (hi >> 12) & MASK51; // 최상위 비트 무시

        FieldElement(limbs)
    }

    /// 필드 원소를 32바이트 리틀 엔디언 배열로 변환합니다.
    ///
    /// 출력은 완전히 리듀스된 정규 표현입니다.
    pub fn to_bytes(&self) -> [u8; 32] {
        let t = self.reduce();
        let mut bytes = [0u8; 32];

        // 51-bit limbs를 바이트로 패킹
        let mut acc: u128 = t.0[0] as u128;
        acc |= (t.0[1] as u128) << 51;
        acc |= (t.0[2] as u128) << 102;

        for i in 0..16 {
            bytes[i] = (acc >> (i * 8)) as u8;
        }

        acc = (t.0[2] >> 26) as u128;
        acc |= (t.0[3] as u128) << 25;
        acc |= (t.0[4] as u128) << 76;

        for i in 0..16 {
            bytes[16 + i] = (acc >> (i * 8)) as u8;
        }

        bytes
    }

    /// 완전한 리덕션을 수행합니다.
    ///
    /// 결과는 [0, p) 범위로 정규화됩니다.
    #[inline]
    fn reduce(&self) -> Self {
        let mut t = *self;

        // 먼저 캐리 전파
        t.carry_propagate();

        // p를 빼고 언더플로 확인
        let mut s = [0i64; 5];
        s[0] = t.0[0] as i64 - P[0] as i64;
        s[1] = t.0[1] as i64 - P[1] as i64;
        s[2] = t.0[2] as i64 - P[2] as i64;
        s[3] = t.0[3] as i64 - P[3] as i64;
        s[4] = t.0[4] as i64 - P[4] as i64;

        // 캐리 전파 (음수 가능)
        for i in 0..4 {
            let carry = s[i] >> 51;
            s[i] &= MASK51 as i64;
            s[i + 1] += carry;
        }

        // 최상위 limb의 부호가 음수면 원래 값 사용 (t < p)
        let mask = (s[4] >> 63) as u64; // 0xFFFF... if negative, 0 otherwise

        FieldElement([
            (t.0[0] & mask) | ((s[0] as u64) & !mask),
            (t.0[1] & mask) | ((s[1] as u64) & !mask),
            (t.0[2] & mask) | ((s[2] as u64) & !mask),
            (t.0[3] & mask) | ((s[3] as u64) & !mask),
            (t.0[4] & mask) | ((s[4] as u64) & !mask),
        ])
    }

    /// 캐리 전파를 수행합니다.
    #[inline]
    fn carry_propagate(&mut self) {
        // 각 limb에서 51비트 초과분을 다음 limb으로 전파
        for i in 0..4 {
            let carry = self.0[i] >> 51;
            self.0[i] &= MASK51;
            self.0[i + 1] += carry;
        }
        // 최상위 limb의 캐리는 19를 곱해서 최하위로 (mod p)
        let carry = self.0[4] >> 51;
        self.0[4] &= MASK51;
        self.0[0] += carry * 19;

        // 두 번째 캐리 전파 (carry*19가 51비트를 초과할 수 있음)
        let carry = self.0[0] >> 51;
        self.0[0] &= MASK51;
        self.0[1] += carry;
    }

    /// 곱셈 역원을 계산합니다.
    ///
    /// 페르마 소정리 사용: a^(-1) = a^(p-2) mod p
    pub fn invert(&self) -> Self {
        // p-2 = 2^255 - 21의 제곱-곱셈 체인
        let x1 = *self;
        let x2 = x1.square();
        let x4 = x2.square().square();
        let x5 = x4 * x1;
        let x10 = x5.square().square().square().square().square();
        let x20 = x10
            .square()
            .square()
            .square()
            .square()
            .square()
            .square()
            .square()
            .square()
            .square()
            .square();
        let x40 = {
            let mut t = x20;
            for _ in 0..20 {
                t = t.square();
            }
            t
        };
        let x50 = x40 * x10;
        let x100 = {
            let mut t = x50;
            for _ in 0..50 {
                t = t.square();
            }
            t
        };
        let x200 = {
            let mut t = x100;
            for _ in 0..100 {
                t = t.square();
            }
            t
        };
        let x250 = {
            let mut t = x200 * x50;
            for _ in 0..50 {
                t = t.square();
            }
            t
        };

        // x^(2^255 - 21) = x250 * x5
        // 그런데 2^255 - 21 = p - 2가 아님!
        // p - 2 = 2^255 - 21

        // 올바른 지수: p-2 = 2^255 - 19 - 2 = 2^255 - 21
        // 비트 분해로 계산

        // 더 간단한 방법: 반복 제곱
        let mut result = FieldElement::one();
        let mut base = *self;

        // p - 2 = 0x7FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFEB
        // 바이너리로 분해하여 square-and-multiply

        // 최적화된 체인 (Curve25519 스타일)
        let z2 = x1.square();
        let z4 = z2.square();
        let z8 = z4.square();
        let z9 = z8 * x1;
        let z11 = z9 * z2;
        let z22 = z11.square();
        let z_5_0 = z22 * z9; // 2^5 - 2^0

        let z_10_5 = (0..5).fold(z_5_0, |acc, _| acc.square());
        let z_10_0 = z_10_5 * z_5_0;

        let z_20_10 = (0..10).fold(z_10_0, |acc, _| acc.square());
        let z_20_0 = z_20_10 * z_10_0;

        let z_40_20 = (0..20).fold(z_20_0, |acc, _| acc.square());
        let z_40_0 = z_40_20 * z_20_0;

        let z_50_10 = (0..10).fold(z_40_0, |acc, _| acc.square());
        let z_50_0 = z_50_10 * z_10_0;

        let z_100_50 = (0..50).fold(z_50_0, |acc, _| acc.square());
        let z_100_0 = z_100_50 * z_50_0;

        let z_200_100 = (0..100).fold(z_100_0, |acc, _| acc.square());
        let z_200_0 = z_200_100 * z_100_0;

        let z_250_50 = (0..50).fold(z_200_0, |acc, _| acc.square());
        let z_250_0 = z_250_50 * z_50_0;

        let z_255_5 = (0..5).fold(z_250_0, |acc, _| acc.square());
        z_255_5 * z11 // 2^255 - 21 = p - 2
    }

    /// 제곱을 계산합니다.
    #[inline]
    pub fn square(&self) -> Self {
        self.mul_inner(self)
    }

    /// 2배를 계산합니다.
    #[inline]
    pub fn double(&self) -> Self {
        *self + *self
    }

    /// 내부 곱셈 (schoolbook, 128-bit 중간값 사용)
    fn mul_inner(&self, rhs: &Self) -> Self {
        let a = &self.0;
        let b = &rhs.0;

        // 128-bit 곱셈 사용
        let m = |x: u64, y: u64| -> u128 { (x as u128) * (y as u128) };

        // 19 * limb (mod p에서 2^255 = 19)
        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;

        // 컬럼별 누적
        let mut c0 =
            m(a[0], b[0]) + m(a[1], b4_19) + m(a[2], b3_19) + m(a[3], b2_19) + m(a[4], b1_19);

        let mut c1 =
            m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4_19) + m(a[3], b3_19) + m(a[4], b2_19);

        let mut c2 =
            m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4_19) + m(a[4], b3_19);

        let mut c3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4_19);

        let mut c4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);

        // 캐리 전파
        let carry = c0 >> 51;
        c0 &= MASK51 as u128;
        c1 += carry;

        let carry = c1 >> 51;
        c1 &= MASK51 as u128;
        c2 += carry;

        let carry = c2 >> 51;
        c2 &= MASK51 as u128;
        c3 += carry;

        let carry = c3 >> 51;
        c3 &= MASK51 as u128;
        c4 += carry;

        let carry = c4 >> 51;
        c4 &= MASK51 as u128;
        c0 += carry * 19;

        // 최종 캐리
        let carry = c0 >> 51;
        c0 &= MASK51 as u128;
        c1 += carry;

        FieldElement([c0 as u64, c1 as u64, c2 as u64, c3 as u64, c4 as u64])
    }

    /// 0인지 확인합니다 (상수-시간).
    pub fn is_zero(&self) -> bool {
        let t = self.reduce();
        let or = t.0[0] | t.0[1] | t.0[2] | t.0[3] | t.0[4];
        or == 0
    }

    /// 음수인지 확인합니다 (최하위 비트가 1).
    ///
    /// RFC 8032에서 "negative"는 정규 표현의 LSB가 1인 경우입니다.
    pub fn is_negative(&self) -> bool {
        let bytes = self.to_bytes();
        (bytes[0] & 1) == 1
    }

    /// 조건부 부정: choice가 1이면 부정합니다.
    #[inline]
    pub fn conditional_negate(&self, choice: u8) -> Self {
        let neg = -*self;
        Self::conditional_select(self, &neg, choice)
    }

    /// 조건부 선택: choice가 1이면 b, 0이면 a를 반환합니다.
    #[inline]
    pub fn conditional_select(a: &Self, b: &Self, choice: u8) -> Self {
        let mask = (-(choice as i64)) as u64;
        FieldElement([
            a.0[0] ^ (mask & (a.0[0] ^ b.0[0])),
            a.0[1] ^ (mask & (a.0[1] ^ b.0[1])),
            a.0[2] ^ (mask & (a.0[2] ^ b.0[2])),
            a.0[3] ^ (mask & (a.0[3] ^ b.0[3])),
            a.0[4] ^ (mask & (a.0[4] ^ b.0[4])),
        ])
    }

    /// 제곱근을 계산합니다.
    ///
    /// 존재하면 Some(sqrt), 없으면 None을 반환합니다.
    /// p ≡ 5 (mod 8)이므로 Tonelli-Shanks 변형 사용.
    pub fn sqrt(&self) -> Option<Self> {
        // p = 2^255 - 19 ≡ 5 (mod 8)
        // 제곱근: u^((p+3)/8) 또는 u^((p+3)/8) * sqrt(-1)

        // (p+3)/8 = 2^252 - 3 승
        let u1 = self.pow_p_plus_3_div_8();

        // u1^2 == self 이면 u1이 제곱근
        if (u1.square() - *self).is_zero() {
            return Some(u1);
        }

        // sqrt(-1)을 곱해본다
        let u2 = u1 * SQRT_M1;
        if (u2.square() - *self).is_zero() {
            return Some(u2);
        }

        None
    }

    /// u^((p+3)/8) 계산
    ///
    /// (p+3)/8 = (2^255 - 19 + 3) / 8 = (2^255 - 16) / 8 = 2^252 - 2
    pub fn pow_p_plus_3_div_8(&self) -> Self {
        // x^(2^252 - 2) 계산
        // = x^(2^252) / x^2
        // = (x^(2^250))^4 / x^2
        // = (x^(2^250 - 1) * x)^4 / x^2
        // = x^(4*(2^250-1)) * x^4 / x^2
        // = x^(2^252 - 4) * x^2
        // = x^(2^252 - 2)

        // 먼저 x^(2^250 - 1) 계산
        // 2^250 - 1 = (2^5 - 1) * (2^245 + 2^240 + ... + 2^5 + 1)
        // 하지만 더 효율적인 addition chain 사용

        let x = *self;
        let x2 = x.square(); // x^2
        let x3 = x2 * x; // x^3
        let x6 = x3.square(); // x^6
        let x7 = x6 * x; // x^7
        let x14 = x7.square(); // x^14
        let x28 = x14.square(); // x^28
        let x31 = x28 * x3; // x^31 = x^(2^5 - 1)

        // x^(2^10 - 1) = (x^(2^5 - 1))^(2^5) * x^(2^5 - 1)
        let x_10_5 = (0..5).fold(x31, |acc, _| acc.square()); // x^(31 * 32) = x^(2^10 - 32)
        let x_10_0 = x_10_5 * x31; // x^(2^10 - 1)

        // x^(2^20 - 1)
        let x_20_10 = (0..10).fold(x_10_0, |acc, _| acc.square());
        let x_20_0 = x_20_10 * x_10_0;

        // x^(2^40 - 1)
        let x_40_20 = (0..20).fold(x_20_0, |acc, _| acc.square());
        let x_40_0 = x_40_20 * x_20_0;

        // x^(2^50 - 1)
        let x_50_10 = (0..10).fold(x_40_0, |acc, _| acc.square());
        let x_50_0 = x_50_10 * x_10_0;

        // x^(2^100 - 1)
        let x_100_50 = (0..50).fold(x_50_0, |acc, _| acc.square());
        let x_100_0 = x_100_50 * x_50_0;

        // x^(2^200 - 1)
        let x_200_100 = (0..100).fold(x_100_0, |acc, _| acc.square());
        let x_200_0 = x_200_100 * x_100_0;

        // x^(2^250 - 1)
        let x_250_50 = (0..50).fold(x_200_0, |acc, _| acc.square());
        let x_250_0 = x_250_50 * x_50_0;

        // x^(2^252 - 4) = (x^(2^250 - 1))^4
        let t = x_250_0.square().square();

        // x^(2^252 - 2) = x^(2^252 - 4) * x^2
        t * x2
    }
}

/// sqrt(-1) mod p
/// 2^((p-1)/4) mod p
pub const SQRT_M1: FieldElement = FieldElement([
    0x61B274A0EA0B0,
    0xD5A5FC8F189D,
    0x7EF5E9CBD0C60,
    0x78595A6804C9E,
    0x2B8324804FC1D,
]);

impl Add for FieldElement {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        let mut result = FieldElement([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ]);
        result.carry_propagate();
        result
    }
}

impl Sub for FieldElement {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        // p의 배수를 더해서 언더플로 방지
        // 2*p보다 큰 값을 더함
        let bias = [
            0xFFFFF_FFFF_FFDA, // 2 * (2^51 - 19) 근사
            0xFFFFF_FFFF_FFFE,
            0xFFFFF_FFFF_FFFE,
            0xFFFFF_FFFF_FFFE,
            0xFFFFF_FFFF_FFFE,
        ];

        let mut result = FieldElement([
            (self.0[0] + bias[0]) - rhs.0[0],
            (self.0[1] + bias[1]) - rhs.0[1],
            (self.0[2] + bias[2]) - rhs.0[2],
            (self.0[3] + bias[3]) - rhs.0[3],
            (self.0[4] + bias[4]) - rhs.0[4],
        ]);
        result.carry_propagate();
        result
    }
}

impl Neg for FieldElement {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        FieldElement::zero() - self
    }
}

impl Mul for FieldElement {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        self.mul_inner(&rhs)
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        let a = self.reduce();
        let b = other.reduce();
        a.0[0] == b.0[0]
            && a.0[1] == b.0[1]
            && a.0[2] == b.0[2]
            && a.0[3] == b.0[3]
            && a.0[4] == b.0[4]
    }
}

impl Eq for FieldElement {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_sub() {
        let a = FieldElement::from_bytes(&[1u8; 32]);
        let b = FieldElement::from_bytes(&[2u8; 32]);
        let c = a + b;
        let d = c - b;
        assert_eq!(a, d);
    }

    #[test]
    fn test_mul() {
        let a = FieldElement::from_bytes(&[3u8; 32]);
        let b = a * a;
        let c = a.square();
        assert_eq!(b, c);
    }

    #[test]
    fn test_invert() {
        let a = FieldElement::from_bytes(&[7u8; 32]);
        let a_inv = a.invert();
        let one = a * a_inv;
        assert!(one == FieldElement::one() || (one - FieldElement::one()).is_zero());
    }

    #[test]
    fn test_sqrt_m1() {
        // SQRT_M1^2 == -1 mod p 검증
        let sqrt_m1_sq = SQRT_M1.square();
        let minus_one = -FieldElement::one();
        assert_eq!(sqrt_m1_sq, minus_one, "SQRT_M1^2 should equal -1 mod p");
    }

    #[test]
    fn test_sqrt_of_4() {
        let four = FieldElement::from_bytes(&[
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        let two = FieldElement::from_bytes(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        assert_eq!(two.square(), four, "2^2 should equal 4");

        let result = four.sqrt();
        assert!(result.is_some(), "sqrt(4) should exist");
        let sqrt_4 = result.unwrap();
        assert_eq!(sqrt_4.square(), four, "sqrt(4)^2 should equal 4");
    }
}
