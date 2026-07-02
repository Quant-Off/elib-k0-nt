#![allow(
    clippy::unusual_byte_groupings,
    clippy::wrong_self_convention,
    clippy::needless_range_loop
)]

use constant_time::{Choice, CtSelOps};
use core::ops::{Add, Mul, Sub};
use zeroize::Zeroize;

const LIMBS: usize = 8;
const LIMB_BITS: usize = 56;
const MASK: u64 = (1u64 << 56) - 1;

const P: [u64; LIMBS] = [
    0xFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFF,
];

#[derive(Clone, Copy)]
pub struct FieldElement(pub(crate) [u64; LIMBS]);

impl FieldElement {
    #[inline]
    pub const fn zero() -> Self {
        FieldElement([0; LIMBS])
    }

    #[inline]
    pub const fn one() -> Self {
        FieldElement([1, 0, 0, 0, 0, 0, 0, 0])
    }

    pub fn from_bytes(bytes: &[u8; 56]) -> Self {
        let mut limbs = [0u64; LIMBS];
        for i in 0..LIMBS {
            let offset = i * 7;
            let mut word = 0u64;
            for j in 0..7 {
                word |= (bytes[offset + j] as u64) << (j * 8);
            }
            limbs[i] = word;
        }
        FieldElement(limbs)
    }

    pub fn to_bytes(&self) -> [u8; 56] {
        let t = self.reduce();
        let mut bytes = [0u8; 56];
        for i in 0..LIMBS {
            let offset = i * 7;
            for j in 0..7 {
                bytes[offset + j] = ((t.0[i] >> (j * 8)) & 0xff) as u8;
            }
        }
        bytes
    }

    fn weak_reduce(&self) -> Self {
        let mut t = *self;
        let mut carry: u64;

        carry = t.0[0] >> LIMB_BITS;
        t.0[0] &= MASK;
        t.0[1] += carry;

        carry = t.0[1] >> LIMB_BITS;
        t.0[1] &= MASK;
        t.0[2] += carry;

        carry = t.0[2] >> LIMB_BITS;
        t.0[2] &= MASK;
        t.0[3] += carry;

        carry = t.0[3] >> LIMB_BITS;
        t.0[3] &= MASK;
        t.0[4] += carry;

        carry = t.0[4] >> LIMB_BITS;
        t.0[4] &= MASK;
        t.0[5] += carry;

        carry = t.0[5] >> LIMB_BITS;
        t.0[5] &= MASK;
        t.0[6] += carry;

        carry = t.0[6] >> LIMB_BITS;
        t.0[6] &= MASK;
        t.0[7] += carry;

        carry = t.0[7] >> LIMB_BITS;
        t.0[7] &= MASK;

        t.0[0] += carry;
        t.0[4] += carry;

        carry = t.0[0] >> LIMB_BITS;
        t.0[0] &= MASK;
        t.0[1] += carry;

        carry = t.0[4] >> LIMB_BITS;
        t.0[4] &= MASK;
        t.0[5] += carry;

        t
    }

    fn reduce(&self) -> Self {
        let mut t = self.weak_reduce();
        t = t.weak_reduce();
        t = t.weak_reduce();

        for _ in 0..3 {
            let mut under = 0i64;
            for i in 0..LIMBS {
                let diff = (t.0[i] as i64) - (P[i] as i64) + under;
                under = diff >> 63;
            }

            if under >= 0 {
                let mut borrow = 0i64;
                for i in 0..LIMBS {
                    let diff = (t.0[i] as i64) - (P[i] as i64) - borrow;
                    borrow = if diff < 0 { 1 } else { 0 };
                    t.0[i] = (diff as u64) & MASK;
                }
            }
        }

        t
    }

    fn mul_inner(&self, rhs: &Self) -> Self {
        let a = &self.0;
        let b = &rhs.0;

        let mut c = [0u128; 16];

        for i in 0..LIMBS {
            for j in 0..LIMBS {
                c[i + j] += (a[i] as u128) * (b[j] as u128);
            }
        }

        for i in (8..15).rev() {
            let hi = c[i];
            c[i] = 0;
            c[i - 8] += hi;
            c[i - 4] += hi;
        }

        for i in (8..12).rev() {
            let hi = c[i];
            c[i] = 0;
            c[i - 8] += hi;
            c[i - 4] += hi;
        }

        let mut result = [0u64; LIMBS];
        let mut carry = 0u128;
        for i in 0..LIMBS {
            let sum = c[i] + carry;
            result[i] = (sum as u64) & MASK;
            carry = sum >> LIMB_BITS;
        }

        result[0] += carry as u64;
        result[4] += carry as u64;

        let mut fe = FieldElement(result);
        fe = fe.weak_reduce();
        c.zeroize();
        carry.zeroize();
        result.zeroize();
        fe
    }

    #[inline]
    pub fn square(&self) -> Self {
        self.mul_inner(self)
    }

    pub fn invert(&self) -> Self {
        let mut result = FieldElement::one();
        let mut base = *self;

        for i in 0..448u32 {
            if i != 1 && i != 224 {
                result = result * base;
            }
            base = base.square();
        }

        base.zeroize();
        result
    }

    #[inline]
    pub fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        for i in 0..LIMBS {
            u64::swap(&mut a.0[i], &mut b.0[i], choice);
        }
    }
}

impl Add for FieldElement {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        let mut result = [0u64; LIMBS];
        for i in 0..LIMBS {
            result[i] = self.0[i] + rhs.0[i];
        }
        FieldElement(result).weak_reduce()
    }
}

impl Sub for FieldElement {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        // 2*p 바이어스를 더해 분기 없이 언더플로 방지 (상수시간)
        // 약하게 축소된 limb 은 2*P[i] 미만이므로 limb 단위 음수 발생 안 함
        let mut result = [0u64; LIMBS];
        for i in 0..LIMBS {
            result[i] = (self.0[i] + 2 * P[i]) - rhs.0[i];
        }
        FieldElement(result).weak_reduce()
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
        let mut acc = 0u64;
        for i in 0..LIMBS {
            acc |= a.0[i] ^ b.0[i];
        }
        acc == 0
    }
}

impl Eq for FieldElement {}

impl Zeroize for FieldElement {
    #[inline]
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
