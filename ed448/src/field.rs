#![allow(clippy::unusual_byte_groupings, clippy::needless_range_loop, dead_code)]

use core::ops::{Add, Mul, Neg, Sub};

const LIMBS: usize = 8;
const LIMB_BITS: usize = 56;
const MASK: u64 = (1u64 << 56) - 1;

// p = 2^448 - 2^224 - 1 (Goldilocks prime)
// In binary: bits 0-223 = all 1s, bit 224 = 0, bits 225-447 = all 1s
const P: [u64; LIMBS] = [
    0xFFFFFFFFFFFFFF, // limb 0: bits 0-55, all 1s
    0xFFFFFFFFFFFFFF, // limb 1: bits 56-111
    0xFFFFFFFFFFFFFF, // limb 2: bits 112-167
    0xFFFFFFFFFFFFFF, // limb 3: bits 168-223
    0xFFFFFFFFFFFFFE, // limb 4: bits 224-279, bit 224 = 0 (due to -2^224)
    0xFFFFFFFFFFFFFF, // limb 5: bits 280-335
    0xFFFFFFFFFFFFFF, // limb 6: bits 336-391
    0xFFFFFFFFFFFFFF, // limb 7: bits 392-447
];

#[derive(Clone, Copy, Debug)]
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

    pub fn to_bytes(self) -> [u8; 56] {
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

        // Goldilocks 축소: 2^448 ≡ 2^224 + 1 (mod p)
        // 역순으로 축소하여 c[8..15]를 c[0..7]로 변환
        for i in (8..15).rev() {
            let hi = c[i];
            c[i] = 0;
            c[i - 8] += hi; // +1 부분
            c[i - 4] += hi; // +2^224 부분
        }

        // c[8..11]에 남은 값 처리 (c[12..14] 축소 시 발생)
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
        fe
    }

    #[inline]
    pub fn square(&self) -> Self {
        self.mul_inner(self)
    }

    #[inline]
    pub fn double(&self) -> Self {
        *self + *self
    }

    pub fn invert(&self) -> Self {
        // p - 2 = 2^448 - 2^224 - 3
        // 지수를 효율적 덧셈 체인으로 계산
        let x = *self;
        let x2 = x.square();
        let x3 = x2 * x;
        let x6 = x3.square();
        let x9 = x6 * x3;
        let x11 = x9 * x2;
        let x22 = x11.square();
        let x44 = (0..22).fold(x22, |acc, _| acc.square());
        let x44_full = x44 * x22;
        let x88 = (0..44).fold(x44_full, |acc, _| acc.square());
        let x88_full = x88 * x44_full;
        let x176 = (0..88).fold(x88_full, |acc, _| acc.square());
        let x176_full = x176 * x88_full;
        let x220 = (0..44).fold(x176_full, |acc, _| acc.square());
        let x220_full = x220 * x44_full;
        let _x222 = x220_full.square().square() * x2;

        // x^(2^222 - 1) 계산 완료, 이제 전체 지수 계산
        // p-2 = 2^446 * (2^2-1) + 2^224 * (2^222-1) - 2^224 + (2^222-1) + (2^2-1) - 1
        // 더 간단한 방법: 직접 비트 패턴 사용

        // p - 2 bit pattern: bit 447..225 = 1, bit 224 = 0, bit 223..2 = 1, bit 1 = 0, bit 0 = 1
        // = 2^447 + 2^446 + ... + 2^225 + 2^223 + ... + 2^2 + 2^0
        // = (2^448 - 2^225) + (2^224 - 4) + 1
        // = 2^448 - 2^225 + 2^224 - 3
        // = 2^448 - 2^224 - 3

        // 간단히: x^(p-2)를 square-and-multiply로 계산
        let mut result = FieldElement::one();
        let mut base = *self;

        // p - 2의 각 비트에 대해
        for i in 0..448u32 {
            if i != 1 && i != 224 {
                result = result * base;
            }
            base = base.square();
        }

        result
    }

    pub fn is_zero(&self) -> bool {
        let t = self.reduce();
        let mut or = 0u64;
        for i in 0..LIMBS {
            or |= t.0[i];
        }
        or == 0
    }

    pub fn is_negative(&self) -> bool {
        let bytes = self.to_bytes();
        (bytes[0] & 1) == 1
    }

    #[inline]
    pub fn conditional_negate(&self, choice: u8) -> Self {
        let neg = -*self;
        Self::conditional_select(self, &neg, choice)
    }

    #[inline]
    pub fn conditional_select(a: &Self, b: &Self, choice: u8) -> Self {
        let mask = (-(choice as i64)) as u64;
        let mut result = [0u64; LIMBS];
        for i in 0..LIMBS {
            result[i] = a.0[i] ^ (mask & (a.0[i] ^ b.0[i]));
        }
        FieldElement(result)
    }

    pub fn sqrt(&self) -> Option<Self> {
        // (p+1)/4 = (2^448 - 2^224)/4 = 2^446 - 2^222
        // = 2^222 * (2^224 - 1)
        let u1 = self.pow_p_plus_1_div_4();
        if (u1.square() - *self).is_zero() {
            return Some(u1);
        }
        None
    }

    fn pow_p_plus_1_div_4(&self) -> Self {
        // (p+1)/4 = 2^446 - 2^222 = 2^222 * (2^224 - 1)
        // 먼저 x^(2^224 - 1) 계산, 그 후 222번 제곱
        let x = *self;

        // x^(2^224 - 1) 계산 - 효율적 덧셈 체인 사용
        // 2^224 - 1 = 111...1 (224개의 1)
        let x2 = x.square(); // x^2
        let x3 = x2 * x; // x^3
        let x6 = x3.square(); // x^6
        let x7 = x6 * x; // x^7
        let x14 = x7.square(); // x^14
        let x28 = x14.square(); // x^28
        let _x56 = x28.square(); // x^56

        // x^(2^7 - 1) = x^127
        let _x127 = (0..6).fold(x, |acc, _| acc.square() * x);
        // 실제로 필요한 건 x^(2^k - 1) 패턴
        // 더 간단한 방법: 직접 bit-by-bit

        // x^(2^224 - 1)을 square-and-multiply로 계산
        let mut result = FieldElement::one();
        let mut base = x;
        for _ in 0..224 {
            result = result * base;
            base = base.square();
        }
        // 이 시점에서 result = x^(1+2+4+...+2^223) = x^(2^224 - 1)

        // 222번 제곱하여 x^(2^222 * (2^224 - 1)) = x^(2^446 - 2^222) 계산
        for _ in 0..222 {
            result = result.square();
        }

        result
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
        let a = self.reduce();
        let b = rhs.reduce();
        let mut result = [0u64; LIMBS];
        let mut borrow = 0i64;

        for i in 0..LIMBS {
            let diff = (a.0[i] as i64) - (b.0[i] as i64) - borrow;
            if diff < 0 {
                result[i] = ((diff + (MASK as i64) + 1) as u64) & MASK;
                borrow = 1;
            } else {
                result[i] = (diff as u64) & MASK;
                borrow = 0;
            }
        }

        if borrow != 0 {
            let mut carry = 0i64;
            for i in 0..LIMBS {
                let sum = (result[i] as i64) + (P[i] as i64) + carry;
                result[i] = (sum as u64) & MASK;
                carry = sum >> LIMB_BITS;
            }
        }

        FieldElement(result)
    }
}

impl Neg for FieldElement {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        let t = self.reduce();
        let mut result = [0u64; LIMBS];
        let mut borrow = 0i64;
        for i in 0..LIMBS {
            let diff = (P[i] as i64) - (t.0[i] as i64) - borrow;
            if diff < 0 {
                result[i] = ((diff + (MASK as i64) + 1) as u64) & MASK;
                borrow = 1;
            } else {
                result[i] = (diff as u64) & MASK;
                borrow = 0;
            }
        }
        FieldElement(result)
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
        let mut eq = true;
        for i in 0..LIMBS {
            eq = eq && (a.0[i] == b.0[i]);
        }
        eq
    }
}

impl Eq for FieldElement {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_one() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();
        assert!(zero.is_zero());
        assert!(!one.is_zero());
    }

    #[test]
    fn test_prime_value() {
        // Verify P represents 2^448 - 2^224 - 1
        // P + 1 should give us 2^448 - 2^224, which in limbs is:
        // limbs 0-3: 0, limb 4: 0, limbs 5-7: 0, with overflow from position 448
        // Actually: 2^448 - 2^224 in limbs should be:
        // limb 0-3: 0, limb 4: 2^56 - 1 (wait no)
        //
        // 2^448 = limb[8] = 1 (overflow)
        // 2^224 = limb[4] at position 0
        // 2^448 - 2^224:
        //   In limb representation with Goldilocks reduction:
        //   2^448 ≡ 2^224 + 1
        //   So 2^448 - 2^224 = 2^224 + 1 - 2^224 = 1
        //
        // Let's verify: p + 1 = 2^448 - 2^224 ≡ 1 (mod p)
        let p = FieldElement(P);
        let one = FieldElement::one();
        let p_plus_one = p + one;
        eprintln!("P = {:?}", P);
        eprintln!("P + 1 = {:?}", p_plus_one.0);
        eprintln!("P + 1 (reduced) = {:?}", p_plus_one.reduce().0);
        // P + 1 should equal 0 mod p (since P ≡ -1 mod p, so P + 1 ≡ 0)
        // Wait no: P IS the prime, so P ≡ 0 mod P, thus P + 1 ≡ 1 mod P
        assert_eq!(p_plus_one.reduce(), one, "P + 1 should equal 1 mod P");
    }

    #[test]
    fn test_add_sub() {
        let a = FieldElement::from_bytes(&[1u8; 56]);
        let b = FieldElement::from_bytes(&[2u8; 56]);
        let c = a + b;
        let d = c - b;
        assert_eq!(a, d);
    }

    #[test]
    fn test_mul() {
        let a = FieldElement::from_bytes(&[3u8; 56]);
        let b = a * a;
        let c = a.square();
        assert_eq!(b, c);
    }

    #[test]
    fn test_square_simple() {
        let two = FieldElement::from_bytes(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let four = two.square();
        let four_expected = FieldElement::from_bytes(&[
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(four, four_expected, "2^2 should be 4");
    }

    #[test]
    fn test_pow_simple() {
        let two = FieldElement::from_bytes(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let eight = two * two * two;
        let eight_expected = FieldElement::from_bytes(&[
            8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(eight, eight_expected, "2^3 should be 8");

        let mut result = FieldElement::one();
        let base = two;
        for _ in 0..3 {
            result = result * base;
        }
        assert_eq!(result, eight_expected, "2^3 via loop should be 8");
    }

    #[test]
    fn test_sq_multiply() {
        let x = FieldElement::from_bytes(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let mut result = FieldElement::one();
        let mut base = x;
        let exp = 5u64;

        for i in 0..4 {
            if (exp >> i) & 1 == 1 {
                result = result * base;
            }
            base = base.square();
        }

        let expected = FieldElement::from_bytes(&[
            32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        eprintln!("result = {:?}", result.to_bytes()[0]);
        eprintln!("expected (5) = 32");
        assert_eq!(result, expected, "2^(1+4) = 2^5 = 32");
    }

    #[test]
    fn test_mul_basic() {
        // 2 * 2 = 4
        let two = FieldElement::from_bytes(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let four = two * two;
        eprintln!("two = {:?}", two.0);
        eprintln!("two * two = {:?}", four.0);
        let expected = FieldElement::from_bytes(&[
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(four, expected, "2 * 2 should equal 4");
    }

    #[test]
    fn test_power_chain() {
        // 3^10 = 59049
        let three = FieldElement::from_bytes(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let mut result = FieldElement::one();
        for _ in 0..10 {
            result = result * three;
        }
        // 59049 = 0xE6A9 = [0xA9, 0xE6, 0, ...]
        let bytes = result.to_bytes();
        let val = bytes[0] as u64 | ((bytes[1] as u64) << 8);
        eprintln!("3^10 = {} (expected 59049)", val);
        assert_eq!(val, 59049);
    }

    #[test]
    fn test_power_100() {
        // Test a larger power that may accumulate errors
        let three = FieldElement::from_bytes(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        // Use repeated squaring: 3^100 = 3^64 * 3^32 * 3^4
        let x2 = three.square();
        let x4 = x2.square();
        let x8 = x4.square();
        let x16 = x8.square();
        let x32 = x16.square();
        let x64 = x32.square();
        let x100 = x64 * x32 * x4;

        let bytes = x100.to_bytes();
        eprintln!("3^100 limbs = {:?}", x100.0);
        eprintln!("3^100 bytes[0..10] = {:?}", &bytes[0..10]);
        // 3^100 mod p should be some specific value - verify manually
    }

    #[test]
    fn test_small_exp() {
        // Test 3^6 using square-and-multiply (6 = 110 in binary = bits 1,2 set)
        let a = FieldElement::from_bytes(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let mut result = FieldElement::one();
        let mut base = a;

        // 6 = 0b110, bits 1 and 2 are set
        for i in 0..3u32 {
            if (6 >> i) & 1 == 1 {
                result = result * base;
            }
            base = base.square();
        }

        // 3^6 = 729
        let bytes = result.to_bytes();
        let val = bytes[0] as u64 | ((bytes[1] as u64) << 8);
        eprintln!("3^6 = {} (expected 729)", val);
        assert_eq!(val, 729);
    }

    #[test]
    fn test_square_many() {
        // a^(2^448) should equal a (since 2^448 ≡ 2^224 + 1 mod (p-1)... actually complex)
        // Let's just verify squaring many times doesn't blow up
        let a = FieldElement::from_bytes(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let mut x = a;
        for i in 0..448 {
            x = x.square();
            // Verify limbs are within bounds
            for (j, &limb) in x.0.iter().enumerate() {
                if limb > 0x01FFFFFFFFFFFFFF {
                    panic!("Limb {} overflow at iteration {}: {:x}", j, i, limb);
                }
            }
        }
        eprintln!("After 448 squarings, x = {:?}", x.0);
    }

    #[test]
    fn test_sqmul_vs_direct() {
        // Verify square-and-multiply gives same result as direct multiplication
        // 3^10 using square-and-multiply: 10 = 1010 in binary, bits 1 and 3 set
        let a = FieldElement::from_bytes(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        // Square-and-multiply for 3^10
        let mut result_sqmul = FieldElement::one();
        let mut base = a;
        let exp = 10u32; // 1010 binary

        for i in 0..4 {
            if (exp >> i) & 1 == 1 {
                result_sqmul = result_sqmul * base;
            }
            base = base.square();
        }

        // Direct: 3^10
        let mut result_direct = FieldElement::one();
        for _ in 0..10 {
            result_direct = result_direct * a;
        }

        let sqmul_bytes = result_sqmul.to_bytes();
        let direct_bytes = result_direct.to_bytes();
        eprintln!("3^10 sqmul = {:?}", &sqmul_bytes[..4]);
        eprintln!("3^10 direct = {:?}", &direct_bytes[..4]);
        assert_eq!(result_sqmul, result_direct, "3^10 should match");
    }

    #[test]
    fn test_mul_large() {
        // Test multiplication of two large field elements
        let a = FieldElement::from_bytes(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        // Compute 3^254 and 3^256 via direct multiplication
        let mut three_254 = FieldElement::one();
        for _ in 0..254 {
            three_254 = three_254 * a;
        }

        let mut three_256 = FieldElement::one();
        for _ in 0..256 {
            three_256 = three_256 * a;
        }

        // Compute 3^510 via multiplying 3^254 * 3^256
        let three_510_mul = three_254 * three_256;

        // Compute 3^510 via direct multiplication
        let mut three_510_direct = FieldElement::one();
        for _ in 0..510 {
            three_510_direct = three_510_direct * a;
        }

        eprintln!("3^254 = {:?}", three_254.0);
        eprintln!("3^256 = {:?}", three_256.0);
        eprintln!("3^254 * 3^256 = {:?}", three_510_mul.0);
        eprintln!("3^510 direct = {:?}", three_510_direct.0);
        assert_eq!(
            three_510_mul, three_510_direct,
            "3^254 * 3^256 should equal 3^510"
        );
    }

    #[test]
    fn test_fermat() {
        // a^(p-1) = 1 mod p (Fermat's little theorem)
        // p - 1 = 2^448 - 2^224 - 2
        // bits: bit 447..225 = 1, bit 224 = 0, bit 223..1 = 1, bit 0 = 0
        let a = FieldElement::from_bytes(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let mut result = FieldElement::one();
        let mut base = a;

        for i in 0..448u32 {
            // p-1 = 2^448 - 2^224 - 2: bit 0 = 0, bit 224 = 0, all others = 1
            if i != 0 && i != 224 {
                result = result * base;
            }
            base = base.square();
        }

        eprintln!("a^(p-1) = {:?}", result.0);
        eprintln!("one = {:?}", FieldElement::one().0);
        assert_eq!(
            result,
            FieldElement::one(),
            "Fermat's little theorem: a^(p-1) = 1"
        );
    }

    #[test]
    fn test_invert() {
        let a = FieldElement::from_bytes(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let a_inv = a.invert();
        let one = a * a_inv;
        eprintln!("a = {:?}", a.0);
        eprintln!("a_inv = {:?}", a_inv.0);
        eprintln!("a * a_inv = {:?}", one.0);
        eprintln!("reduced = {:?}", one.reduce().0);
        eprintln!("one = {:?}", FieldElement::one().0);
        assert!(one == FieldElement::one() || (one - FieldElement::one()).is_zero());
    }
}
