//! 스칼라 연산 모듈입니다.
//!
//! L = 2^252 + 27742317777372353535851937790883648493 위의 스칼라 연산을 구현합니다.
//! Ed25519 기저점의 차수입니다.
//!
//! 리덕션은 SUPERCOP ref10의 sc_reduce / sc_muladd 알고리즘에 기반합니다.

#![allow(
    clippy::unusual_byte_groupings,
    clippy::wrong_self_convention,
    clippy::needless_range_loop
)]

use core::ops::{Add, Mul, Sub};
use zeroize::Zeroize;

/// 그룹 차수 L = 2^252 + 27742317777372353535851937790883648493
/// 리틀 엔디언 바이트 배열
pub const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// (L - 1) mod L = -1 (스칼라 부정에 사용)
const MINUS_ONE: Scalar = {
    let mut b = L_BYTES;
    b[0] = L_BYTES[0] - 1;
    Scalar(b)
};

/// L의 21-bit signed limb 분해 계수 (low 부분, l3/l5는 음수)
/// L = 2^252 + (L0 + L1·2^21 + L2·2^42 + L3·2^63 + L4·2^84 + L5·2^105)
const L0: i64 = 666643;
const L1: i64 = 470296;
const L2: i64 = 654183;
const L3: i64 = -997805;
const L4: i64 = 136657;
const L5: i64 = -683901;

/// 스칼라 원소입니다.
///
/// 32바이트 리틀 엔디언 표현으로 저장됩니다.
/// mod L 로 리듀스되지 않을 수 있습니다.
#[derive(Clone, Copy, Debug)]
pub struct Scalar(pub(crate) [u8; 32]);

impl Scalar {
    /// 0을 반환합니다.
    #[inline]
    pub const fn zero() -> Self {
        Scalar([0u8; 32])
    }

    /// 1을 반환합니다.
    #[inline]
    pub const fn one() -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        Scalar(bytes)
    }

    /// 32바이트 배열에서 스칼라를 로드합니다.
    ///
    /// mod L 리덕션 없이 그대로 저장합니다.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Scalar(bytes)
    }

    /// 64바이트 배열에서 스칼라를 로드하고 mod L 리듀스합니다.
    ///
    /// SHA-512 출력을 스칼라로 변환할 때 사용합니다.
    pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        let mut s = load_24_from_64(bytes);
        sc_reduce_24(&mut s);
        let out = Scalar(pack_12_to_32(&[
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11],
        ]));
        s.zeroize();
        out
    }

    /// 바이트 배열을 반환합니다.
    #[inline]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// 스칼라가 정규 형태인지 확인합니다 (< L).
    pub fn is_canonical(&self) -> bool {
        // 바이트 단위로 L과 비교 (리틀 엔디언)
        let mut borrow = 0i16;
        for i in 0..32 {
            borrow = (self.0[i] as i16) - (L_BYTES[i] as i16) - borrow;
            borrow = (borrow >> 8) & 1;
        }
        // borrow == 1이면 self < L
        borrow == 1
    }
}

/// 스칼라 곱셈 후 덧셈: (a · b + c) mod L
pub fn sc_muladd(a: &Scalar, b: &Scalar, c: &Scalar) -> Scalar {
    let mut a_limbs = load_12_from_32(&a.0);
    let mut b_limbs = load_12_from_32(&b.0);
    let mut c_limbs = load_12_from_32(&c.0);

    // s = c + a · b
    // i+j 위치에 a[i]·b[j] 곱을 누적; c는 0..11 에 더함
    // 곱셈 결과 s[22] 까지 채워질 수 있음 (a11·b11 = 2^50 정도)
    let mut s = [0i64; 24];
    s[..12].copy_from_slice(&c_limbs);
    for i in 0..12 {
        for j in 0..12 {
            s[i + j] += a_limbs[i] * b_limbs[j];
        }
    }

    // 곱셈 직후 limb 크기를 21-bit 범위로 줄이기 위한 첫 캐리 전파.
    // (sc_reduce_24 의 첫 폴딩에서 s[22]*L0 ≈ 2^50·2^20 = 2^70 오버플로 방지)
    first_carry_pass_24(&mut s);

    sc_reduce_24(&mut s);

    let out = Scalar(pack_12_to_32(&[
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11],
    ]));

    // 비밀 스칼라에서 유래한 limb 중간값 소거
    a_limbs.zeroize();
    b_limbs.zeroize();
    c_limbs.zeroize();
    s.zeroize();
    out
}

/// 24-limb 배열에 대한 첫 rounded 캐리 전파 (짝수 → 홀수, 인덱스 0..22).
fn first_carry_pass_24(s: &mut [i64; 24]) {
    let mut carry: i64;
    // 짝수 인덱스 0, 2, ..., 22
    carry = (s[0] + (1 << 20)) >> 21;
    s[1] += carry;
    s[0] -= carry << 21;
    carry = (s[2] + (1 << 20)) >> 21;
    s[3] += carry;
    s[2] -= carry << 21;
    carry = (s[4] + (1 << 20)) >> 21;
    s[5] += carry;
    s[4] -= carry << 21;
    carry = (s[6] + (1 << 20)) >> 21;
    s[7] += carry;
    s[6] -= carry << 21;
    carry = (s[8] + (1 << 20)) >> 21;
    s[9] += carry;
    s[8] -= carry << 21;
    carry = (s[10] + (1 << 20)) >> 21;
    s[11] += carry;
    s[10] -= carry << 21;
    carry = (s[12] + (1 << 20)) >> 21;
    s[13] += carry;
    s[12] -= carry << 21;
    carry = (s[14] + (1 << 20)) >> 21;
    s[15] += carry;
    s[14] -= carry << 21;
    carry = (s[16] + (1 << 20)) >> 21;
    s[17] += carry;
    s[16] -= carry << 21;
    carry = (s[18] + (1 << 20)) >> 21;
    s[19] += carry;
    s[18] -= carry << 21;
    carry = (s[20] + (1 << 20)) >> 21;
    s[21] += carry;
    s[20] -= carry << 21;
    carry = (s[22] + (1 << 20)) >> 21;
    s[23] += carry;
    s[22] -= carry << 21;

    // 홀수 인덱스 1, 3, ..., 21
    carry = (s[1] + (1 << 20)) >> 21;
    s[2] += carry;
    s[1] -= carry << 21;
    carry = (s[3] + (1 << 20)) >> 21;
    s[4] += carry;
    s[3] -= carry << 21;
    carry = (s[5] + (1 << 20)) >> 21;
    s[6] += carry;
    s[5] -= carry << 21;
    carry = (s[7] + (1 << 20)) >> 21;
    s[8] += carry;
    s[7] -= carry << 21;
    carry = (s[9] + (1 << 20)) >> 21;
    s[10] += carry;
    s[9] -= carry << 21;
    carry = (s[11] + (1 << 20)) >> 21;
    s[12] += carry;
    s[11] -= carry << 21;
    carry = (s[13] + (1 << 20)) >> 21;
    s[14] += carry;
    s[13] -= carry << 21;
    carry = (s[15] + (1 << 20)) >> 21;
    s[16] += carry;
    s[15] -= carry << 21;
    carry = (s[17] + (1 << 20)) >> 21;
    s[18] += carry;
    s[17] -= carry << 21;
    carry = (s[19] + (1 << 20)) >> 21;
    s[20] += carry;
    s[19] -= carry << 21;
    carry = (s[21] + (1 << 20)) >> 21;
    s[22] += carry;
    s[21] -= carry << 21;
}

impl Zeroize for Scalar {
    #[inline]
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
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
        // a - b = a + (-1)*b mod L, (-1) = (L - 1) mod L
        let neg_rhs = sc_muladd(&MINUS_ONE, &rhs, &Scalar::zero());
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
        // 상수-시간 비교
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }
}

impl Eq for Scalar {}

//
// 내부 헬퍼
//

/// 3바이트를 64-bit 정수로 로드합니다 (LE).
#[inline]
fn load_3(b: &[u8]) -> u64 {
    (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16)
}

/// 4바이트를 64-bit 정수로 로드합니다 (LE).
#[inline]
fn load_4(b: &[u8]) -> u64 {
    (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16) | ((b[3] as u64) << 24)
}

/// 32바이트를 12개의 21-bit limb 으로 디코딩합니다.
fn load_12_from_32(bytes: &[u8; 32]) -> [i64; 12] {
    [
        2097151 & load_3(&bytes[0..3]) as i64,
        2097151 & (load_4(&bytes[2..6]) >> 5) as i64,
        2097151 & (load_3(&bytes[5..8]) >> 2) as i64,
        2097151 & (load_4(&bytes[7..11]) >> 7) as i64,
        2097151 & (load_4(&bytes[10..14]) >> 4) as i64,
        2097151 & (load_3(&bytes[13..16]) >> 1) as i64,
        2097151 & (load_4(&bytes[15..19]) >> 6) as i64,
        2097151 & (load_3(&bytes[18..21]) >> 3) as i64,
        2097151 & load_3(&bytes[21..24]) as i64,
        2097151 & (load_4(&bytes[23..27]) >> 5) as i64,
        2097151 & (load_3(&bytes[26..29]) >> 2) as i64,
        (load_4(&bytes[28..32]) >> 7) as i64,
    ]
}

/// 64바이트를 24개의 21-bit limb 으로 디코딩합니다.
fn load_24_from_64(bytes: &[u8; 64]) -> [i64; 24] {
    [
        2097151 & load_3(&bytes[0..3]) as i64,
        2097151 & (load_4(&bytes[2..6]) >> 5) as i64,
        2097151 & (load_3(&bytes[5..8]) >> 2) as i64,
        2097151 & (load_4(&bytes[7..11]) >> 7) as i64,
        2097151 & (load_4(&bytes[10..14]) >> 4) as i64,
        2097151 & (load_3(&bytes[13..16]) >> 1) as i64,
        2097151 & (load_4(&bytes[15..19]) >> 6) as i64,
        2097151 & (load_3(&bytes[18..21]) >> 3) as i64,
        2097151 & load_3(&bytes[21..24]) as i64,
        2097151 & (load_4(&bytes[23..27]) >> 5) as i64,
        2097151 & (load_3(&bytes[26..29]) >> 2) as i64,
        2097151 & (load_4(&bytes[28..32]) >> 7) as i64,
        2097151 & (load_4(&bytes[31..35]) >> 4) as i64,
        2097151 & (load_3(&bytes[34..37]) >> 1) as i64,
        2097151 & (load_4(&bytes[36..40]) >> 6) as i64,
        2097151 & (load_3(&bytes[39..42]) >> 3) as i64,
        2097151 & load_3(&bytes[42..45]) as i64,
        2097151 & (load_4(&bytes[44..48]) >> 5) as i64,
        2097151 & (load_3(&bytes[47..50]) >> 2) as i64,
        2097151 & (load_4(&bytes[49..53]) >> 7) as i64,
        2097151 & (load_4(&bytes[52..56]) >> 4) as i64,
        2097151 & (load_3(&bytes[55..58]) >> 1) as i64,
        2097151 & (load_4(&bytes[57..61]) >> 6) as i64,
        (load_4(&bytes[60..64]) >> 3) as i64,
    ]
}

/// 12개의 21-bit limb 을 32바이트로 패킹합니다.
fn pack_12_to_32(s: &[i64; 12]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0] = s[0] as u8;
    bytes[1] = (s[0] >> 8) as u8;
    bytes[2] = ((s[0] >> 16) | (s[1] << 5)) as u8;
    bytes[3] = (s[1] >> 3) as u8;
    bytes[4] = (s[1] >> 11) as u8;
    bytes[5] = ((s[1] >> 19) | (s[2] << 2)) as u8;
    bytes[6] = (s[2] >> 6) as u8;
    bytes[7] = ((s[2] >> 14) | (s[3] << 7)) as u8;
    bytes[8] = (s[3] >> 1) as u8;
    bytes[9] = (s[3] >> 9) as u8;
    bytes[10] = ((s[3] >> 17) | (s[4] << 4)) as u8;
    bytes[11] = (s[4] >> 4) as u8;
    bytes[12] = (s[4] >> 12) as u8;
    bytes[13] = ((s[4] >> 20) | (s[5] << 1)) as u8;
    bytes[14] = (s[5] >> 7) as u8;
    bytes[15] = ((s[5] >> 15) | (s[6] << 6)) as u8;
    bytes[16] = (s[6] >> 2) as u8;
    bytes[17] = (s[6] >> 10) as u8;
    bytes[18] = ((s[6] >> 18) | (s[7] << 3)) as u8;
    bytes[19] = (s[7] >> 5) as u8;
    bytes[20] = (s[7] >> 13) as u8;
    bytes[21] = s[8] as u8;
    bytes[22] = (s[8] >> 8) as u8;
    bytes[23] = ((s[8] >> 16) | (s[9] << 5)) as u8;
    bytes[24] = (s[9] >> 3) as u8;
    bytes[25] = (s[9] >> 11) as u8;
    bytes[26] = ((s[9] >> 19) | (s[10] << 2)) as u8;
    bytes[27] = (s[10] >> 6) as u8;
    bytes[28] = ((s[10] >> 14) | (s[11] << 7)) as u8;
    bytes[29] = (s[11] >> 1) as u8;
    bytes[30] = (s[11] >> 9) as u8;
    bytes[31] = (s[11] >> 17) as u8;
    bytes
}

/// SUPERCOP ref10 기반 24-limb mod L 리듀스. s[12..]는 0으로 만들어집니다.
///
/// 알고리즘 개요 (SUPERCOP/ref10 sc_reduce):
/// 1. s[18..24] 를 s[6..17] 로 폴딩 (각 s[i] 에 L0..L5 곱)
/// 2. s[6..17] 캐리 전파 (rounded, even/odd 패스)
/// 3. s[12..18] 를 s[0..11] 로 폴딩
/// 4. s[0..12] 캐리 전파 (rounded)
/// 5. s[11] 의 캐리에서 발생한 s[12] 를 s[0..5] 로 추가 폴딩
/// 6. 최종 unrounded 캐리 전파로 정규화
fn sc_reduce_24(s: &mut [i64; 24]) {
    // 1라운드: s[23..18] -> s[11..16] (각 s[i] -> s[i-12..=i-7])
    s[11] += s[23] * L0;
    s[12] += s[23] * L1;
    s[13] += s[23] * L2;
    s[14] += s[23] * L3;
    s[15] += s[23] * L4;
    s[16] += s[23] * L5;

    s[10] += s[22] * L0;
    s[11] += s[22] * L1;
    s[12] += s[22] * L2;
    s[13] += s[22] * L3;
    s[14] += s[22] * L4;
    s[15] += s[22] * L5;

    s[9] += s[21] * L0;
    s[10] += s[21] * L1;
    s[11] += s[21] * L2;
    s[12] += s[21] * L3;
    s[13] += s[21] * L4;
    s[14] += s[21] * L5;

    s[8] += s[20] * L0;
    s[9] += s[20] * L1;
    s[10] += s[20] * L2;
    s[11] += s[20] * L3;
    s[12] += s[20] * L4;
    s[13] += s[20] * L5;

    s[7] += s[19] * L0;
    s[8] += s[19] * L1;
    s[9] += s[19] * L2;
    s[10] += s[19] * L3;
    s[11] += s[19] * L4;
    s[12] += s[19] * L5;

    s[6] += s[18] * L0;
    s[7] += s[18] * L1;
    s[8] += s[18] * L2;
    s[9] += s[18] * L3;
    s[10] += s[18] * L4;
    s[11] += s[18] * L5;

    s[18] = 0;
    s[19] = 0;
    s[20] = 0;
    s[21] = 0;
    s[22] = 0;
    s[23] = 0;

    // 캐리 전파 (s[6..17], 짝수 → 홀수, rounded)
    let mut carry: i64;
    carry = (s[6] + (1 << 20)) >> 21;
    s[7] += carry;
    s[6] -= carry << 21;
    carry = (s[8] + (1 << 20)) >> 21;
    s[9] += carry;
    s[8] -= carry << 21;
    carry = (s[10] + (1 << 20)) >> 21;
    s[11] += carry;
    s[10] -= carry << 21;
    carry = (s[12] + (1 << 20)) >> 21;
    s[13] += carry;
    s[12] -= carry << 21;
    carry = (s[14] + (1 << 20)) >> 21;
    s[15] += carry;
    s[14] -= carry << 21;
    carry = (s[16] + (1 << 20)) >> 21;
    s[17] += carry;
    s[16] -= carry << 21;

    carry = (s[7] + (1 << 20)) >> 21;
    s[8] += carry;
    s[7] -= carry << 21;
    carry = (s[9] + (1 << 20)) >> 21;
    s[10] += carry;
    s[9] -= carry << 21;
    carry = (s[11] + (1 << 20)) >> 21;
    s[12] += carry;
    s[11] -= carry << 21;
    carry = (s[13] + (1 << 20)) >> 21;
    s[14] += carry;
    s[13] -= carry << 21;
    carry = (s[15] + (1 << 20)) >> 21;
    s[16] += carry;
    s[15] -= carry << 21;

    // 2라운드: s[17..12] -> s[5..10], ..., s[0..5]
    s[5] += s[17] * L0;
    s[6] += s[17] * L1;
    s[7] += s[17] * L2;
    s[8] += s[17] * L3;
    s[9] += s[17] * L4;
    s[10] += s[17] * L5;

    s[4] += s[16] * L0;
    s[5] += s[16] * L1;
    s[6] += s[16] * L2;
    s[7] += s[16] * L3;
    s[8] += s[16] * L4;
    s[9] += s[16] * L5;

    s[3] += s[15] * L0;
    s[4] += s[15] * L1;
    s[5] += s[15] * L2;
    s[6] += s[15] * L3;
    s[7] += s[15] * L4;
    s[8] += s[15] * L5;

    s[2] += s[14] * L0;
    s[3] += s[14] * L1;
    s[4] += s[14] * L2;
    s[5] += s[14] * L3;
    s[6] += s[14] * L4;
    s[7] += s[14] * L5;

    s[1] += s[13] * L0;
    s[2] += s[13] * L1;
    s[3] += s[13] * L2;
    s[4] += s[13] * L3;
    s[5] += s[13] * L4;
    s[6] += s[13] * L5;

    s[0] += s[12] * L0;
    s[1] += s[12] * L1;
    s[2] += s[12] * L2;
    s[3] += s[12] * L3;
    s[4] += s[12] * L4;
    s[5] += s[12] * L5;

    s[12] = 0;
    s[13] = 0;
    s[14] = 0;
    s[15] = 0;
    s[16] = 0;
    s[17] = 0;

    // 캐리 전파 (s[0..12], 짝수 → 홀수, rounded)
    carry = (s[0] + (1 << 20)) >> 21;
    s[1] += carry;
    s[0] -= carry << 21;
    carry = (s[2] + (1 << 20)) >> 21;
    s[3] += carry;
    s[2] -= carry << 21;
    carry = (s[4] + (1 << 20)) >> 21;
    s[5] += carry;
    s[4] -= carry << 21;
    carry = (s[6] + (1 << 20)) >> 21;
    s[7] += carry;
    s[6] -= carry << 21;
    carry = (s[8] + (1 << 20)) >> 21;
    s[9] += carry;
    s[8] -= carry << 21;
    carry = (s[10] + (1 << 20)) >> 21;
    s[11] += carry;
    s[10] -= carry << 21;

    carry = (s[1] + (1 << 20)) >> 21;
    s[2] += carry;
    s[1] -= carry << 21;
    carry = (s[3] + (1 << 20)) >> 21;
    s[4] += carry;
    s[3] -= carry << 21;
    carry = (s[5] + (1 << 20)) >> 21;
    s[6] += carry;
    s[5] -= carry << 21;
    carry = (s[7] + (1 << 20)) >> 21;
    s[8] += carry;
    s[7] -= carry << 21;
    carry = (s[9] + (1 << 20)) >> 21;
    s[10] += carry;
    s[9] -= carry << 21;
    carry = (s[11] + (1 << 20)) >> 21;
    s[12] += carry;
    s[11] -= carry << 21;

    // s[11] 캐리에서 발생한 s[12] 를 다시 폴딩
    s[0] += s[12] * L0;
    s[1] += s[12] * L1;
    s[2] += s[12] * L2;
    s[3] += s[12] * L3;
    s[4] += s[12] * L4;
    s[5] += s[12] * L5;
    s[12] = 0;

    // 최종 캐리 전파 (unrounded, s[0..11])
    carry = s[0] >> 21;
    s[1] += carry;
    s[0] -= carry << 21;
    carry = s[1] >> 21;
    s[2] += carry;
    s[1] -= carry << 21;
    carry = s[2] >> 21;
    s[3] += carry;
    s[2] -= carry << 21;
    carry = s[3] >> 21;
    s[4] += carry;
    s[3] -= carry << 21;
    carry = s[4] >> 21;
    s[5] += carry;
    s[4] -= carry << 21;
    carry = s[5] >> 21;
    s[6] += carry;
    s[5] -= carry << 21;
    carry = s[6] >> 21;
    s[7] += carry;
    s[6] -= carry << 21;
    carry = s[7] >> 21;
    s[8] += carry;
    s[7] -= carry << 21;
    carry = s[8] >> 21;
    s[9] += carry;
    s[8] -= carry << 21;
    carry = s[9] >> 21;
    s[10] += carry;
    s[9] -= carry << 21;
    carry = s[10] >> 21;
    s[11] += carry;
    s[10] -= carry << 21;
    carry = s[11] >> 21;
    s[12] += carry;
    s[11] -= carry << 21;

    // s[12] 마지막 폴딩
    s[0] += s[12] * L0;
    s[1] += s[12] * L1;
    s[2] += s[12] * L2;
    s[3] += s[12] * L3;
    s[4] += s[12] * L4;
    s[5] += s[12] * L5;
    s[12] = 0;

    // 마지막 unrounded 캐리 전파
    carry = s[0] >> 21;
    s[1] += carry;
    s[0] -= carry << 21;
    carry = s[1] >> 21;
    s[2] += carry;
    s[1] -= carry << 21;
    carry = s[2] >> 21;
    s[3] += carry;
    s[2] -= carry << 21;
    carry = s[3] >> 21;
    s[4] += carry;
    s[3] -= carry << 21;
    carry = s[4] >> 21;
    s[5] += carry;
    s[4] -= carry << 21;
    carry = s[5] >> 21;
    s[6] += carry;
    s[5] -= carry << 21;
    carry = s[6] >> 21;
    s[7] += carry;
    s[6] -= carry << 21;
    carry = s[7] >> 21;
    s[8] += carry;
    s[7] -= carry << 21;
    carry = s[8] >> 21;
    s[9] += carry;
    s[8] -= carry << 21;
    carry = s[9] >> 21;
    s[10] += carry;
    s[9] -= carry << 21;
    carry = s[10] >> 21;
    s[11] += carry;
    s[10] -= carry << 21;

    // s[11] -> s[12] drain (이 단계가 누락되어 결함 발생)
    carry = s[11] >> 21;
    s[12] += carry;
    s[11] -= carry << 21;

    // s[12] 세 번째 fold (잔재 carry 처리)
    s[0] += s[12] * L0;
    s[1] += s[12] * L1;
    s[2] += s[12] * L2;
    s[3] += s[12] * L3;
    s[4] += s[12] * L4;
    s[5] += s[12] * L5;
    s[12] = 0;

    // 마지막 unrounded carry pass (s[0]..s[10] only — s[11] 은 이미 < 2^21)
    carry = s[0] >> 21;
    s[1] += carry;
    s[0] -= carry << 21;
    carry = s[1] >> 21;
    s[2] += carry;
    s[1] -= carry << 21;
    carry = s[2] >> 21;
    s[3] += carry;
    s[2] -= carry << 21;
    carry = s[3] >> 21;
    s[4] += carry;
    s[3] -= carry << 21;
    carry = s[4] >> 21;
    s[5] += carry;
    s[4] -= carry << 21;
    carry = s[5] >> 21;
    s[6] += carry;
    s[5] -= carry << 21;
    carry = s[6] >> 21;
    s[7] += carry;
    s[6] -= carry << 21;
    carry = s[7] >> 21;
    s[8] += carry;
    s[7] -= carry << 21;
    carry = s[8] >> 21;
    s[9] += carry;
    s[8] -= carry << 21;
    carry = s[9] >> 21;
    s[10] += carry;
    s[9] -= carry << 21;
    carry = s[10] >> 21;
    s[11] += carry;
    s[10] -= carry << 21;
}
