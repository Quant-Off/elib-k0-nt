#![allow(
    clippy::unusual_byte_groupings,
    clippy::wrong_self_convention,
    clippy::needless_range_loop,
    dead_code
)]

use constant_time::{Choice, CtSelOps};
use core::ops::{Add, Mul, Neg, Sub};

const MASK51: u64 = (1u64 << 51) - 1;

#[derive(Clone, Copy)]
pub struct FieldElement(pub(crate) [u64; 5]);

impl FieldElement {
    #[inline]
    pub const fn zero() -> Self {
        FieldElement([0, 0, 0, 0, 0])
    }

    #[inline]
    pub const fn one() -> Self {
        FieldElement([1, 0, 0, 0, 0])
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 5];

        let load64 = |b: &[u8]| -> u64 {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        };

        let lo0 = load64(&bytes[0..8]);
        let lo1 = load64(&bytes[8..16]);
        let lo2 = load64(&bytes[16..24]);
        let hi = load64(&bytes[24..32]);

        limbs[0] = lo0 & MASK51;
        limbs[1] = ((lo0 >> 51) | (lo1 << 13)) & MASK51;
        limbs[2] = ((lo1 >> 38) | (lo2 << 26)) & MASK51;
        limbs[3] = ((lo2 >> 25) | (hi << 39)) & MASK51;
        limbs[4] = (hi >> 12) & MASK51;

        FieldElement(limbs)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let t = self.reduce();
        let mut bytes = [0u8; 32];

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

    #[inline]
    fn reduce(&self) -> Self {
        let mut t = *self;
        t.carry_propagate();

        let p: [u64; 5] = [
            0x7FFFF_FFFF_FFED,
            0x7FFFF_FFFF_FFFF,
            0x7FFFF_FFFF_FFFF,
            0x7FFFF_FFFF_FFFF,
            0x7FFFF_FFFF_FFFF,
        ];

        let mut s = [0i64; 5];
        s[0] = t.0[0] as i64 - p[0] as i64;
        s[1] = t.0[1] as i64 - p[1] as i64;
        s[2] = t.0[2] as i64 - p[2] as i64;
        s[3] = t.0[3] as i64 - p[3] as i64;
        s[4] = t.0[4] as i64 - p[4] as i64;

        for i in 0..4 {
            let carry = s[i] >> 51;
            s[i] &= MASK51 as i64;
            s[i + 1] += carry;
        }

        let mask = (s[4] >> 63) as u64;

        FieldElement([
            (t.0[0] & mask) | ((s[0] as u64) & !mask),
            (t.0[1] & mask) | ((s[1] as u64) & !mask),
            (t.0[2] & mask) | ((s[2] as u64) & !mask),
            (t.0[3] & mask) | ((s[3] as u64) & !mask),
            (t.0[4] & mask) | ((s[4] as u64) & !mask),
        ])
    }

    #[inline]
    fn carry_propagate(&mut self) {
        for i in 0..4 {
            let carry = self.0[i] >> 51;
            self.0[i] &= MASK51;
            self.0[i + 1] += carry;
        }
        let carry = self.0[4] >> 51;
        self.0[4] &= MASK51;
        self.0[0] += carry * 19;

        let carry = self.0[0] >> 51;
        self.0[0] &= MASK51;
        self.0[1] += carry;
    }

    pub fn invert(&self) -> Self {
        let x1 = *self;
        let z2 = x1.square();
        let z4 = z2.square();
        let z8 = z4.square();
        let z9 = z8 * x1;
        let z11 = z9 * z2;
        let z22 = z11.square();
        let z_5_0 = z22 * z9;

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
        z_255_5 * z11
    }

    #[inline]
    pub fn square(&self) -> Self {
        self.mul_inner(self)
    }

    fn mul_inner(&self, rhs: &Self) -> Self {
        let a = &self.0;
        let b = &rhs.0;

        let m = |x: u64, y: u64| -> u128 { (x as u128) * (y as u128) };

        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;

        let mut c0 =
            m(a[0], b[0]) + m(a[1], b4_19) + m(a[2], b3_19) + m(a[3], b2_19) + m(a[4], b1_19);

        let mut c1 =
            m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4_19) + m(a[3], b3_19) + m(a[4], b2_19);

        let mut c2 =
            m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4_19) + m(a[4], b3_19);

        let mut c3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4_19);

        let mut c4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);

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

        let carry = c0 >> 51;
        c0 &= MASK51 as u128;
        c1 += carry;

        FieldElement([c0 as u64, c1 as u64, c2 as u64, c3 as u64, c4 as u64])
    }

    pub fn is_zero(&self) -> Choice {
        let t = self.reduce();
        let or = t.0[0] | t.0[1] | t.0[2] | t.0[3] | t.0[4];
        Choice::from_u8((or == 0) as u8)
    }

    #[inline]
    pub fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        for i in 0..5 {
            u64::swap(&mut a.0[i], &mut b.0[i], choice);
        }
    }
}

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
        let bias = [
            0xFFFFF_FFFF_FFDA,
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
