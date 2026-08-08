use zeroize::{Secret, Zeroize};

#[inline]
const fn bmul32(x: u32, y: u32) -> u64 {
    const MX0: u32 = 0x1111_1111;
    const MX1: u32 = 0x2222_2222;
    const MX2: u32 = 0x4444_4444;
    const MX3: u32 = 0x8888_8888;

    const MZ0: u64 = 0x1111_1111_1111_1111;
    const MZ1: u64 = 0x2222_2222_2222_2222;
    const MZ2: u64 = 0x4444_4444_4444_4444;
    const MZ3: u64 = 0x8888_8888_8888_8888;

    let x0 = (x & MX0) as u64;
    let x1 = (x & MX1) as u64;
    let x2 = (x & MX2) as u64;
    let x3 = (x & MX3) as u64;
    let y0 = (y & MX0) as u64;
    let y1 = (y & MX1) as u64;
    let y2 = (y & MX2) as u64;
    let y3 = (y & MX3) as u64;

    let z0 = x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
    let z1 = x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
    let z2 = x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
    let z3 = x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);

    (z0 & MZ0) | (z1 & MZ1) | (z2 & MZ2) | (z3 & MZ3)
}

#[inline]
fn bmul64(x: u64, y: u64) -> u128 {
    let xh = (x >> 32) as u32;
    let xl = x as u32;
    let yh = (y >> 32) as u32;
    let yl = y as u32;

    let p_ll = bmul32(xl, yl) as u128;
    let p_hh = bmul32(xh, yh) as u128;
    let p_lh = bmul32(xl ^ xh, yl ^ yh) as u128;
    let p_mid = p_lh ^ p_ll ^ p_hh;

    p_ll ^ (p_mid << 32) ^ (p_hh << 64)
}

#[inline]
fn poly_mul_128(x: u128, y: u128) -> (u128, u128) {
    let xh = (x >> 64) as u64;
    let xl = x as u64;
    let yh = (y >> 64) as u64;
    let yl = y as u64;

    let p_ll = bmul64(xl, yl);
    let p_hh = bmul64(xh, yh);
    let p_lh = bmul64(xl ^ xh, yl ^ yh);
    let p_mid = p_lh ^ p_ll ^ p_hh;

    let lo = p_ll ^ (p_mid << 64);
    let hi = p_hh ^ (p_mid >> 64);
    (lo, hi)
}

#[inline]
fn reduce_natural(lo: u128, hi: u128) -> u128 {
    let t_lo = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
    let t_hi = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
    let t2 = t_hi ^ (t_hi << 1) ^ (t_hi << 2) ^ (t_hi << 7);
    lo ^ t_lo ^ t2
}

/// 테스트 검증용 GHASH 비트-역순 표기에서의 GF(2^128) 곱셈
/// 입력 `x`, `y`는 `u128::from_be_bytes` 결과(NIST SP 800-38D의 비트역순 표현)를 가정합니다.
/// `GHash::update`는 H의 사전 변환 결과를 캐시하므로 이 래퍼를 사용하지 않습니다.
#[inline]
#[must_use]
#[cfg(test)]
fn gf128_mul(x: u128, y: u128) -> u128 {
    let x_n = x.reverse_bits();
    let y_n = y.reverse_bits();
    let (lo, hi) = poly_mul_128(x_n, y_n);
    reduce_natural(lo, hi).reverse_bits()
}

#[derive(Default)]
pub struct GHash {
    h_n: Secret<u128>,
    state_n: Secret<u128>,
}

impl GHash {
    /// 인증 서브키를 제자리에서 설정하고 상태를 초기화합니다.
    ///
    /// # Arguments
    /// - `h`: 16바이트 인증 서브키
    pub fn init(&mut self, h: &[u8; 16]) {
        self.h_n
            .init_with(|v| *v = u128::from_be_bytes(*h).reverse_bits());
        self.state_n.zeroize();
    }

    pub fn update(&mut self, block: &[u8; 16]) {
        let x_n = u128::from_be_bytes(*block).reverse_bits();
        let combined = *self.state_n.expose() ^ x_n;
        let (lo, hi) = poly_mul_128(combined, *self.h_n.expose());
        *self.state_n.expose_mut() = reduce_natural(lo, hi);
    }

    pub fn update_padded(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(16);
        for chunk in chunks.by_ref() {
            let block: [u8; 16] = chunk.try_into().unwrap();
            self.update(&block);
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut block = [0u8; 16];
            block[..remainder.len()].copy_from_slice(remainder);
            self.update(&block);
        }
    }

    /// 누적 상태를 태그로 출력하고 상태를 제자리에서 소거합니다.
    ///
    /// # Security Note
    /// `self` 를 이동 소비하지 않으므로 원본 슬롯에 사본이 남지 않으며,
    /// 서브키 소거는 스코프 종료 시 `Drop` 이 제자리에서 수행합니다.
    #[must_use]
    pub fn finalize(&mut self) -> [u8; 16] {
        let tag = self.state_n.expose().reverse_bits().to_be_bytes();
        self.state_n.zeroize();
        tag
    }

    pub fn reset(&mut self) {
        self.state_n.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    // GHash 의 h(인증 서브키)와 state는 모두 비밀
    // Drop 후 메모리가 0으로 소거되는지 검증
    #[test]
    fn test_ghash_zeroize_on_drop() {
        let h: [u8; 16] = [0xDEu8; 16];
        let mut storage: MaybeUninit<GHash> = MaybeUninit::uninit();

        unsafe {
            storage.write(GHash::default());
            (*storage.as_mut_ptr()).init(&h);
            (*storage.as_mut_ptr()).update(&[0xAAu8; 16]);

            let h_ptr = (*storage.as_ptr()).h_n.expose() as *const u128 as *const u8;
            let s_ptr = (*storage.as_ptr()).state_n.expose() as *const u128 as *const u8;

            let pre_h = core::slice::from_raw_parts(h_ptr, 16);
            let pre_s = core::slice::from_raw_parts(s_ptr, 16);
            assert!(pre_h.iter().any(|&b| b != 0), "GHash h 가 비어 있음");
            assert!(pre_s.iter().any(|&b| b != 0), "GHash state 가 비어 있음");

            storage.assume_init_drop();

            let post_h = core::slice::from_raw_parts(h_ptr, 16);
            let post_s = core::slice::from_raw_parts(s_ptr, 16);
            assert!(post_h.iter().all(|&b| b == 0), "GHash h 미소거");
            assert!(post_s.iter().all(|&b| b == 0), "GHash state 미소거");
        }
    }

    #[test]
    fn ghash_basic() {
        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let data: [u8; 16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        let expected: [u8; 16] = [
            0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x62, 0x88, 0x2c, 0x85, 0xb0, 0x68, 0x53, 0x53,
            0xde, 0xb7,
        ];

        let mut ghash = GHash::default();
        ghash.init(&h);
        ghash.update(&data);
        let result = ghash.finalize();
        assert_eq!(result, expected);
    }

    #[test]
    fn gf128_mul_test() {
        let a: u128 = 0x0388_dace_60b6_a392_f328_c2b9_71b2_fe78;
        let b: u128 = 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2e;
        let expected: u128 = 0x5e2e_c746_9170_6288_2c85_b068_5353_deb7;
        assert_eq!(gf128_mul(a, b), expected);
    }

    /// bmul32가 carryless(GF(2)[X]) 다항식 곱과 일치하는지 검증합니다.
    #[test]
    fn bmul32_against_bitserial() {
        fn bitserial(x: u32, y: u32) -> u64 {
            let mut z = 0u64;
            for i in 0..32 {
                if (x >> i) & 1 == 1 {
                    z ^= (y as u64) << i;
                }
            }
            z
        }
        let cases: [(u32, u32); 6] = [
            (0, 0),
            (0xFFFF_FFFF, 0xFFFF_FFFF),
            (0xDEAD_BEEF, 0xCAFE_BABE),
            (0x1234_5678, 0x9ABC_DEF0),
            (0x8000_0001, 0x8000_0001),
            (0x5555_5555, 0xAAAA_AAAA),
        ];
        for (x, y) in cases {
            assert_eq!(bmul32(x, y), bitserial(x, y), "bmul32({x:08x}, {y:08x})");
        }
    }
}
