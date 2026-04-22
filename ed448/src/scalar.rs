#![allow(
    clippy::unusual_byte_groupings,
    clippy::needless_range_loop,
    dead_code,
    unused_assignments
)]

use core::ops::{Add, Mul, Sub};

pub const L_BYTES: [u8; 57] = [
    0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
    0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 0x00,
];

#[derive(Clone, Copy, Debug)]
pub struct Scalar(pub(crate) [u8; 57]);

impl Scalar {
    #[inline]
    pub const fn zero() -> Self {
        Scalar([0u8; 57])
    }

    #[inline]
    pub const fn one() -> Self {
        let mut bytes = [0u8; 57];
        bytes[0] = 1;
        Scalar(bytes)
    }

    #[inline]
    pub const fn from_bytes(bytes: [u8; 57]) -> Self {
        Scalar(bytes)
    }

    pub fn from_bytes_mod_order_wide(bytes: &[u8; 114]) -> Self {
        let mut s = [0u64; 18];

        for i in 0..18 {
            let offset = i * 7;
            let end = if offset + 7 <= 114 { offset + 7 } else { 114 };
            let mut word = 0u64;
            for j in offset..end {
                word |= (bytes[j] as u64) << ((j - offset) * 8);
            }
            s[i] = word & 0x00FFFFFFFFFFFFFF;
        }
        s[16] = (s[16] & 0xFFFFFFFFFFFF) | ((bytes[112] as u64) << 48);
        if 113 < 114 {
            s[16] |= (bytes[113] as u64) << 56;
        }

        sc_reduce_wide(&mut s);

        let mut result = [0u8; 57];
        for i in 0..8 {
            let offset = i * 7;
            for j in 0..7 {
                if offset + j < 56 {
                    result[offset + j] = ((s[i] >> (j * 8)) & 0xff) as u8;
                }
            }
        }
        // byte 55 from s[7] bits 48-55
        result[55] = ((s[7] >> 48) & 0xff) as u8;
        // byte 56 must be 0 for canonical scalars (L[56] = 0)
        result[56] = 0;

        Scalar(result)
    }

    #[inline]
    pub const fn to_bytes(self) -> [u8; 57] {
        self.0
    }

    pub fn is_canonical(&self) -> bool {
        let mut borrow = 0i16;
        for i in 0..57 {
            borrow = (self.0[i] as i16) - (L_BYTES[i] as i16) - borrow;
            borrow = (borrow >> 8) & 1;
        }
        borrow == 1
    }
}

// 2^448 mod L = 4 * (2^446 - L) = 4c
// c = 2^446 - L ≈ 2^222
const R_448: [u8; 29] = [
    0x34, 0xec, 0x9e, 0x52, 0xb5, 0xf5, 0x1c, 0x72, 0xab, 0xc2, 0xe9, 0xc8, 0x35, 0xf6, 0x4c, 0x7a,
    0xbf, 0x25, 0xa7, 0x44, 0xd9, 0x92, 0xc4, 0xee, 0x58, 0x70, 0xd7, 0x0c, 0x02,
];

fn sc_reduce_wide(s: &mut [u64; 18]) {
    // 캐리 전파
    for _ in 0..4 {
        for i in 0..17 {
            let carry = s[i] >> 56;
            s[i] &= 0x00FFFFFFFFFFFFFF;
            s[i + 1] = s[i + 1].wrapping_add(carry);
        }
        s[17] &= 0x00FFFFFFFFFFFFFF;
    }

    // limb -> bytes 변환
    let mut bytes = [0u8; 128];
    for i in 0..18 {
        let limb = s[i];
        let offset = i * 7;
        for j in 0..7 {
            if offset + j < 128 {
                bytes[offset + j] = ((limb >> (j * 8)) & 0xff) as u8;
            }
        }
    }

    // bytes[56..] * R_448 축소: 2^448 ≡ R_448 (mod L)
    // 상위 바이트에 R_448을 곱해서 하위에 더함
    for _ in 0..3 {
        // bytes[56..]이 모두 0인지 확인
        let mut all_zero = true;
        for i in 56..128 {
            if bytes[i] != 0 {
                all_zero = false;
                break;
            }
        }
        if all_zero {
            break;
        }

        // bytes[56..] * R_448을 계산해서 bytes[0..56]에 더함
        let mut product = [0u32; 128];
        for i in 56..128 {
            if bytes[i] == 0 {
                continue;
            }
            let b = bytes[i] as u32;
            for j in 0..29 {
                let target = (i - 56) + j;
                if target < 128 {
                    product[target] += b * (R_448[j] as u32);
                }
            }
            bytes[i] = 0;
        }

        // product를 bytes[0..128]에 더함 (캐리 전파)
        let mut carry = 0u32;
        for i in 0..128 {
            let sum = (bytes[i] as u32) + product[i] + carry;
            bytes[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
    }

    // bytes >= L인 동안 L 빼기
    loop {
        // bytes[56..]이 비어있지 않으면 L 빼기
        let mut high_nonzero = false;
        for i in 56..128 {
            if bytes[i] != 0 {
                high_nonzero = true;
                break;
            }
        }

        if !high_nonzero {
            // bytes[0..57]과 L 비교
            let mut ge = true;
            for i in (0..57).rev() {
                if bytes[i] > L_BYTES[i] {
                    break;
                }
                if bytes[i] < L_BYTES[i] {
                    ge = false;
                    break;
                }
            }
            if !ge {
                break;
            }
        }

        // bytes -= L
        let mut borrow = 0i32;
        for i in 0..57 {
            let diff = (bytes[i] as i32) - (L_BYTES[i] as i32) - borrow;
            bytes[i] = diff.rem_euclid(256) as u8;
            borrow = if diff < 0 { 1 } else { 0 };
        }
        for i in 57..128 {
            if borrow == 0 {
                break;
            }
            let diff = (bytes[i] as i32) - borrow;
            bytes[i] = diff.rem_euclid(256) as u8;
            borrow = if diff < 0 { 1 } else { 0 };
        }
    }

    // limb 복원
    for i in 0..7 {
        let offset = i * 7;
        let mut limb = 0u64;
        for j in 0..7 {
            limb |= (bytes[offset + j] as u64) << (j * 8);
        }
        s[i] = limb;
    }
    s[7] = 0;
    for j in 0..6 {
        s[7] |= (bytes[49 + j] as u64) << (j * 8);
    }
    s[7] |= (bytes[55] as u64) << 48;

    for i in 8..18 {
        s[i] = 0;
    }
}

pub fn sc_muladd(a: &Scalar, b: &Scalar, c: &Scalar) -> Scalar {
    let mut s = [0u64; 18];

    let mut a_limbs = [0u64; 8];
    let mut b_limbs = [0u64; 8];
    let mut c_limbs = [0u64; 8];

    for i in 0..8 {
        let offset = i * 7;
        for j in 0..7 {
            if offset + j < 57 {
                a_limbs[i] |= (a.0[offset + j] as u64) << (j * 8);
                b_limbs[i] |= (b.0[offset + j] as u64) << (j * 8);
                c_limbs[i] |= (c.0[offset + j] as u64) << (j * 8);
            }
        }
        a_limbs[i] &= 0x00FFFFFFFFFFFFFF;
        b_limbs[i] &= 0x00FFFFFFFFFFFFFF;
        c_limbs[i] &= 0x00FFFFFFFFFFFFFF;
    }

    s[..8].copy_from_slice(&c_limbs);

    for i in 0..8 {
        for j in 0..8 {
            let prod = (a_limbs[i] as u128) * (b_limbs[j] as u128);
            s[i + j] = ((s[i + j] as u128) + (prod & 0x00FFFFFFFFFFFFFF)) as u64;
            if i + j + 1 < 18 {
                s[i + j + 1] = ((s[i + j + 1] as u128) + (prod >> 56)) as u64;
            }
        }
    }

    sc_reduce_wide(&mut s);

    let mut result = [0u8; 57];
    for i in 0..8 {
        let offset = i * 7;
        for j in 0..7 {
            if offset + j < 56 {
                result[offset + j] = ((s[i] >> (j * 8)) & 0xff) as u8;
            }
        }
    }
    // byte 55 from s[7] bits 48-55
    result[55] = ((s[7] >> 48) & 0xff) as u8;
    // byte 56 must be 0 for canonical scalars
    result[56] = 0;

    Scalar(result)
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        sc_muladd(&Scalar::one(), &self, &rhs)
    }
}

impl Sub for Scalar {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self {
        let mut neg_bytes = [0xffu8; 57];
        neg_bytes[56] = 0;
        let neg_rhs = sc_muladd(&Scalar(neg_bytes), &rhs, &Scalar::zero());
        sc_muladd(&Scalar::one(), &self, &neg_rhs)
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        sc_muladd(&self, &rhs, &Scalar::zero())
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for i in 0..57 {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }
}

impl Eq for Scalar {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_canonical() {
        // Test that scalar operations produce canonical results
        let a = Scalar::one();
        let b = Scalar::one();
        let result = sc_muladd(&a, &b, &Scalar::zero());
        eprintln!("1 * 1 + 0 = {:?}", result.0);
        assert!(result.is_canonical(), "1*1+0 should be canonical");
    }

    #[test]
    fn test_scalar_from_wide() {
        // Test reduction from wide bytes
        let mut wide = [0u8; 114];
        wide[0] = 1;
        let s = Scalar::from_bytes_mod_order_wide(&wide);
        eprintln!("from_wide([1,0,...]) = {:?}", s.0);
        assert!(s.is_canonical(), "reduced scalar should be canonical");
    }

    #[test]
    fn test_muladd_canonical() {
        // Test with larger values
        let mut a_bytes = [0u8; 57];
        a_bytes[0] = 0x10;
        let mut b_bytes = [0u8; 57];
        b_bytes[0] = 0x20;
        let mut c_bytes = [0u8; 57];
        c_bytes[0] = 0x30;

        let a = Scalar::from_bytes(a_bytes);
        let b = Scalar::from_bytes(b_bytes);
        let c = Scalar::from_bytes(c_bytes);
        let result = sc_muladd(&a, &b, &c);
        eprintln!("a*b+c = {:?}", result.0);
        // 0x10 * 0x20 + 0x30 = 0x200 + 0x30 = 0x230
        assert_eq!(result.0[0], 0x30, "low byte should be 0x30");
        assert_eq!(result.0[1], 0x02, "next byte should be 0x02");
        assert!(result.is_canonical(), "result should be canonical");
    }

    #[test]
    fn test_muladd_large() {
        // Simulate what happens in signing: k * a + r where all are reduced from wide hashes
        let wide_k = [0xffu8; 114];
        let wide_r = [0xabu8; 114];
        let mut a_bytes = [0u8; 57];
        a_bytes[..28].fill(0xcd);

        let k = Scalar::from_bytes_mod_order_wide(&wide_k);
        let _r = Scalar::from_bytes_mod_order_wide(&wide_r);
        let _a = Scalar::from_bytes(a_bytes);

        eprintln!("k full = {:?}", k.0);
        eprintln!("L_BYTES = {:?}", L_BYTES);
        eprintln!("k[55] = {}, k[56] = {}", k.0[55], k.0[56]);
        eprintln!("L[55] = {}, L[56] = {}", L_BYTES[55], L_BYTES[56]);
        eprintln!("k canonical: {}", k.is_canonical());

        // 수동으로 비교
        let mut borrow = 0i16;
        for i in 0..57 {
            borrow = (k.0[i] as i16) - (L_BYTES[i] as i16) - borrow;
            borrow = (borrow >> 8) & 1;
        }
        eprintln!("Manual borrow after all bytes: {}", borrow);

        assert!(k.is_canonical(), "k should be canonical");
    }
}
