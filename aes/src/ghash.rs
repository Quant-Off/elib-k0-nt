use zeroize::Zeroize;

// 32 비트 다항식(carryless) 곱셈
// BearSSL `bmul32` 트릭: 피연산자를 4비트 간격 (mask 0x1111_1111) 로 4등분하여
// 일반 정수 곱셈으로 GF(2)[X] 곱을 얻음. 32비트 입력 기준 한 lane당 최대 8개
// 부분곱이 합산되며 (8 < 16), 4비트 lane안에 carry없이 들어가므로 정확히 다항식 비트가 추출
//
// AES-NI/PCLMULQDQ 미지원 환경 (TCG 등) 에서 정수 곱셈만으로 상수-시간으로 실행됨
// (AMD64/AArch64 정수 곱셈은 데이터 비종속 시간 보장, todo: 근데 추가적인 구글링 필요)
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

// 64 비트 다항식 곱셈을 32 비트 Karatsuba 로 합성
//   (xh·X^32 + xl)(yh·X^32 + yl) = xh·yh·X^64 + (xh·yl ⊕ xl·yh)·X^32 + xl·yl
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

// 128비트 다항식 곱. 256비트 결과를 (low_128, high_128)로 반환
// 64비트 Karatsuba 합성: 3회의 bmul64 호출
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
// (lo, hi) 의 256 비트 다항식을 p(X) = X^128 + X^7 + X^2 + X + 1 로 환원 (자연 순서)
// hi 의 i 번째 비트는 X^(128+i), 그리고 X^128 ≡ X^7 + X^2 + X + 1 (mod p)
// 구글링해보니
//   T = hi · (1 + X + X^2 + X^7), 차수 ≤ 134
//   T_lo  = u128폭 안의 비트 (0..127)
//   T_hi  = 오버플로우 비트 (128..134, 7비트)
//   T_hi 를 같은 식으로 한번 더 환원 (차수 ≤ 13, 추가 오버플로우 없음)
#[inline]
fn reduce_natural(lo: u128, hi: u128) -> u128 {
    let t_lo = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
    let t_hi = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
    let t2 = t_hi ^ (t_hi << 1) ^ (t_hi << 2) ^ (t_hi << 7);
    lo ^ t_lo ^ t2
}

/// 테스트 검증용 GHASH 비트역순 표기에서의 GF(2^128) 곱셈
/// 입력 `x`, `y` 는 `u128::from_be_bytes` 결과 (NIST SP 800-38D의 비트역순 표현) 를 가정합니다.
/// `GHash::update` 는 H의 사전 변환 결과를 캐시하므로 이 래퍼를 사용하지 않습니다.
#[inline]
#[must_use]
#[cfg(test)]
fn gf128_mul(x: u128, y: u128) -> u128 {
    let x_n = x.reverse_bits();
    let y_n = y.reverse_bits();
    let (lo, hi) = poly_mul_128(x_n, y_n);
    reduce_natural(lo, hi).reverse_bits()
}

pub struct GHash {
    // 자연 순서로 변환된 H. 매 update 마다의 비트 역변환 비용 제거
    h_n: u128,
    // 자연 순서 누적 상태. finalize 시점에 GHASH 표기로 역변환
    state_n: u128,
}

impl GHash {
    #[must_use]
    pub fn new(h: &[u8; 16]) -> Self {
        Self {
            h_n: u128::from_be_bytes(*h).reverse_bits(),
            state_n: 0,
        }
    }

    pub fn update(&mut self, block: &[u8; 16]) {
        let x_n = u128::from_be_bytes(*block).reverse_bits();
        let combined = self.state_n ^ x_n;
        let (lo, hi) = poly_mul_128(combined, self.h_n);
        self.state_n = reduce_natural(lo, hi);
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

    #[must_use]
    pub fn finalize(self) -> [u8; 16] {
        self.state_n.reverse_bits().to_be_bytes()
    }

    pub fn reset(&mut self) {
        self.state_n = 0;
    }
}

impl Drop for GHash {
    fn drop(&mut self) {
        self.h_n.zeroize();
        self.state_n.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    /// GHash 의 h (인증 서브키) 와 state 는 모두 비밀.
    /// Drop 후 메모리가 0 으로 소거되는지 검증.
    #[test]
    fn test_ghash_zeroize_on_drop() {
        let h: [u8; 16] = [0xDEu8; 16];
        let mut storage: MaybeUninit<GHash> = MaybeUninit::uninit();

        unsafe {
            storage.write(GHash::new(&h));
            // update 로 state 를 0 이 아닌 값으로 만듦
            (*storage.as_mut_ptr()).update(&[0xAAu8; 16]);

            let h_ptr = &raw const (*storage.as_ptr()).h_n as *const u8;
            let s_ptr = &raw const (*storage.as_ptr()).state_n as *const u8;

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

        let mut ghash = GHash::new(&h);
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

    /// bmul32가 carryless (GF(2)[X]) 다항식 곱과 일치하는지 검증합니다.
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
