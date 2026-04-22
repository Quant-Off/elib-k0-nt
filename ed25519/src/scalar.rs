//! 스칼라 연산 모듈입니다.
//!
//! L = 2^252 + 27742317777372353535851937790883648493 위의 스칼라 연산을 구현합니다.
//! Ed25519 기저점의 차수입니다.

#![allow(
    clippy::unusual_byte_groupings,
    clippy::wrong_self_convention,
    clippy::needless_range_loop,
    dead_code,
    unused_variables,
    unused_mut,
    unused_assignments
)]

use core::ops::{Add, Mul, Sub};

/// 그룹 차수 L = 2^252 + 27742317777372353535851937790883648493
/// 리틀 엔디언 바이트 배열
pub const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// 스칼라 원소입니다.
///
/// 32바이트 리틀 엔디언 표현으로 저장됩니다.
/// mod L로 리듀스되지 않을 수 있습니다.
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
    /// ref10/SUPERCOP sc_reduce 구현 기반
    pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        // 21-bit limbs로 로드
        let mut s0 = 2097151 & load_3(&bytes[0..3]) as i64;
        let mut s1 = 2097151 & (load_4(&bytes[2..6]) >> 5) as i64;
        let mut s2 = 2097151 & (load_3(&bytes[5..8]) >> 2) as i64;
        let mut s3 = 2097151 & (load_4(&bytes[7..11]) >> 7) as i64;
        let mut s4 = 2097151 & (load_4(&bytes[10..14]) >> 4) as i64;
        let mut s5 = 2097151 & (load_3(&bytes[13..16]) >> 1) as i64;
        let mut s6 = 2097151 & (load_4(&bytes[15..19]) >> 6) as i64;
        let mut s7 = 2097151 & (load_3(&bytes[18..21]) >> 3) as i64;
        let mut s8 = 2097151 & load_3(&bytes[21..24]) as i64;
        let mut s9 = 2097151 & (load_4(&bytes[23..27]) >> 5) as i64;
        let mut s10 = 2097151 & (load_3(&bytes[26..29]) >> 2) as i64;
        let mut s11 = 2097151 & (load_4(&bytes[28..32]) >> 7) as i64;
        let mut s12 = 2097151 & (load_4(&bytes[31..35]) >> 4) as i64;
        let mut s13 = 2097151 & (load_3(&bytes[34..37]) >> 1) as i64;
        let mut s14 = 2097151 & (load_4(&bytes[36..40]) >> 6) as i64;
        let mut s15 = 2097151 & (load_3(&bytes[39..42]) >> 3) as i64;
        let mut s16 = 2097151 & load_3(&bytes[42..45]) as i64;
        let mut s17 = 2097151 & (load_4(&bytes[44..48]) >> 5) as i64;
        let s18 = 2097151 & (load_3(&bytes[47..50]) >> 2) as i64;
        let s19 = 2097151 & (load_4(&bytes[49..53]) >> 7) as i64;
        let s20 = 2097151 & (load_4(&bytes[52..56]) >> 4) as i64;
        let s21 = 2097151 & (load_3(&bytes[55..58]) >> 1) as i64;
        let s22 = 2097151 & (load_4(&bytes[57..61]) >> 6) as i64;
        let s23 = (load_4(&bytes[60..64]) >> 3) as i64;

        // 리덕션
        // s23 부터 역순으로 처리
        s11 += s23 * 666643;
        s12 += s23 * 470296;
        s13 += s23 * 654183;
        s14 -= s23 * 997805;
        s15 += s23 * 136657;
        s16 -= s23 * 683901;

        s10 += s22 * 666643;
        s11 += s22 * 470296;
        s12 += s22 * 654183;
        s13 -= s22 * 997805;
        s14 += s22 * 136657;
        s15 -= s22 * 683901;

        s9 += s21 * 666643;
        s10 += s21 * 470296;
        s11 += s21 * 654183;
        s12 -= s21 * 997805;
        s13 += s21 * 136657;
        s14 -= s21 * 683901;

        s8 += s20 * 666643;
        s9 += s20 * 470296;
        s10 += s20 * 654183;
        s11 -= s20 * 997805;
        s12 += s20 * 136657;
        s13 -= s20 * 683901;

        s7 += s19 * 666643;
        s8 += s19 * 470296;
        s9 += s19 * 654183;
        s10 -= s19 * 997805;
        s11 += s19 * 136657;
        s12 -= s19 * 683901;

        s6 += s18 * 666643;
        s7 += s18 * 470296;
        s8 += s18 * 654183;
        s9 -= s18 * 997805;
        s10 += s18 * 136657;
        s11 -= s18 * 683901;

        // 캐리 전파
        let mut carry: i64;
        carry = (s6 + (1 << 20)) >> 21;
        s7 += carry;
        s6 -= carry << 21;
        carry = (s8 + (1 << 20)) >> 21;
        s9 += carry;
        s8 -= carry << 21;
        carry = (s10 + (1 << 20)) >> 21;
        s11 += carry;
        s10 -= carry << 21;
        carry = (s12 + (1 << 20)) >> 21;
        s13 += carry;
        s12 -= carry << 21;
        carry = (s14 + (1 << 20)) >> 21;
        s15 += carry;
        s14 -= carry << 21;
        carry = (s16 + (1 << 20)) >> 21;
        s17 += carry;
        s16 -= carry << 21;

        carry = (s7 + (1 << 20)) >> 21;
        s8 += carry;
        s7 -= carry << 21;
        carry = (s9 + (1 << 20)) >> 21;
        s10 += carry;
        s9 -= carry << 21;
        carry = (s11 + (1 << 20)) >> 21;
        s12 += carry;
        s11 -= carry << 21;
        carry = (s13 + (1 << 20)) >> 21;
        s14 += carry;
        s13 -= carry << 21;
        carry = (s15 + (1 << 20)) >> 21;
        s16 += carry;
        s15 -= carry << 21;

        // s17 처리
        s5 += s17 * 666643;
        s6 += s17 * 470296;
        s7 += s17 * 654183;
        s8 -= s17 * 997805;
        s9 += s17 * 136657;
        s10 -= s17 * 683901;

        s4 += s16 * 666643;
        s5 += s16 * 470296;
        s6 += s16 * 654183;
        s7 -= s16 * 997805;
        s8 += s16 * 136657;
        s9 -= s16 * 683901;

        s3 += s15 * 666643;
        s4 += s15 * 470296;
        s5 += s15 * 654183;
        s6 -= s15 * 997805;
        s7 += s15 * 136657;
        s8 -= s15 * 683901;

        s2 += s14 * 666643;
        s3 += s14 * 470296;
        s4 += s14 * 654183;
        s5 -= s14 * 997805;
        s6 += s14 * 136657;
        s7 -= s14 * 683901;

        s1 += s13 * 666643;
        s2 += s13 * 470296;
        s3 += s13 * 654183;
        s4 -= s13 * 997805;
        s5 += s13 * 136657;
        s6 -= s13 * 683901;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        s12 = 0;

        // 캐리 전파
        carry = (s0 + (1 << 20)) >> 21;
        s1 += carry;
        s0 -= carry << 21;
        carry = (s2 + (1 << 20)) >> 21;
        s3 += carry;
        s2 -= carry << 21;
        carry = (s4 + (1 << 20)) >> 21;
        s5 += carry;
        s4 -= carry << 21;
        carry = (s6 + (1 << 20)) >> 21;
        s7 += carry;
        s6 -= carry << 21;
        carry = (s8 + (1 << 20)) >> 21;
        s9 += carry;
        s8 -= carry << 21;
        carry = (s10 + (1 << 20)) >> 21;
        s11 += carry;
        s10 -= carry << 21;

        carry = (s1 + (1 << 20)) >> 21;
        s2 += carry;
        s1 -= carry << 21;
        carry = (s3 + (1 << 20)) >> 21;
        s4 += carry;
        s3 -= carry << 21;
        carry = (s5 + (1 << 20)) >> 21;
        s6 += carry;
        s5 -= carry << 21;
        carry = (s7 + (1 << 20)) >> 21;
        s8 += carry;
        s7 -= carry << 21;
        carry = (s9 + (1 << 20)) >> 21;
        s10 += carry;
        s9 -= carry << 21;
        carry = (s11 + (1 << 20)) >> 21;
        s12 += carry;
        s11 -= carry << 21;

        // s12 처리
        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        s12 = 0;

        // 최종 캐리 전파
        carry = (s0 + (1 << 20)) >> 21;
        s1 += carry;
        s0 -= carry << 21;
        carry = (s1 + (1 << 20)) >> 21;
        s2 += carry;
        s1 -= carry << 21;
        carry = (s2 + (1 << 20)) >> 21;
        s3 += carry;
        s2 -= carry << 21;
        carry = (s3 + (1 << 20)) >> 21;
        s4 += carry;
        s3 -= carry << 21;
        carry = (s4 + (1 << 20)) >> 21;
        s5 += carry;
        s4 -= carry << 21;
        carry = (s5 + (1 << 20)) >> 21;
        s6 += carry;
        s5 -= carry << 21;
        carry = (s6 + (1 << 20)) >> 21;
        s7 += carry;
        s6 -= carry << 21;
        carry = (s7 + (1 << 20)) >> 21;
        s8 += carry;
        s7 -= carry << 21;
        carry = (s8 + (1 << 20)) >> 21;
        s9 += carry;
        s8 -= carry << 21;
        carry = (s9 + (1 << 20)) >> 21;
        s10 += carry;
        s9 -= carry << 21;
        carry = (s10 + (1 << 20)) >> 21;
        s11 += carry;
        s10 -= carry << 21;
        carry = (s11 + (1 << 20)) >> 21;
        s12 += carry;
        s11 -= carry << 21;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;

        carry = s0 >> 21;
        s1 += carry;
        s0 -= carry << 21;
        carry = s1 >> 21;
        s2 += carry;
        s1 -= carry << 21;
        carry = s2 >> 21;
        s3 += carry;
        s2 -= carry << 21;
        carry = s3 >> 21;
        s4 += carry;
        s3 -= carry << 21;
        carry = s4 >> 21;
        s5 += carry;
        s4 -= carry << 21;
        carry = s5 >> 21;
        s6 += carry;
        s5 -= carry << 21;
        carry = s6 >> 21;
        s7 += carry;
        s6 -= carry << 21;
        carry = s7 >> 21;
        s8 += carry;
        s7 -= carry << 21;
        carry = s8 >> 21;
        s9 += carry;
        s8 -= carry << 21;
        carry = s9 >> 21;
        s10 += carry;
        s9 -= carry << 21;
        carry = s10 >> 21;
        s11 += carry;
        s10 -= carry << 21;

        // 바이트로 변환
        let mut s = [0u8; 32];
        s[0] = s0 as u8;
        s[1] = (s0 >> 8) as u8;
        s[2] = ((s0 >> 16) | (s1 << 5)) as u8;
        s[3] = (s1 >> 3) as u8;
        s[4] = (s1 >> 11) as u8;
        s[5] = ((s1 >> 19) | (s2 << 2)) as u8;
        s[6] = (s2 >> 6) as u8;
        s[7] = ((s2 >> 14) | (s3 << 7)) as u8;
        s[8] = (s3 >> 1) as u8;
        s[9] = (s3 >> 9) as u8;
        s[10] = ((s3 >> 17) | (s4 << 4)) as u8;
        s[11] = (s4 >> 4) as u8;
        s[12] = (s4 >> 12) as u8;
        s[13] = ((s4 >> 20) | (s5 << 1)) as u8;
        s[14] = (s5 >> 7) as u8;
        s[15] = ((s5 >> 15) | (s6 << 6)) as u8;
        s[16] = (s6 >> 2) as u8;
        s[17] = (s6 >> 10) as u8;
        s[18] = ((s6 >> 18) | (s7 << 3)) as u8;
        s[19] = (s7 >> 5) as u8;
        s[20] = (s7 >> 13) as u8;
        s[21] = s8 as u8;
        s[22] = (s8 >> 8) as u8;
        s[23] = ((s8 >> 16) | (s9 << 5)) as u8;
        s[24] = (s9 >> 3) as u8;
        s[25] = (s9 >> 11) as u8;
        s[26] = ((s9 >> 19) | (s10 << 2)) as u8;
        s[27] = (s10 >> 6) as u8;
        s[28] = ((s10 >> 14) | (s11 << 7)) as u8;
        s[29] = (s11 >> 1) as u8;
        s[30] = (s11 >> 9) as u8;
        s[31] = (s11 >> 17) as u8;

        Scalar(s)
    }

    /// 64바이트 입력을 mod L로 리듀스합니다.
    fn sc_reduce(s: &[u8; 64]) -> Self {
        // 입력을 21개의 24-bit limbs로 분해
        let mut a = [0i64; 24];

        a[0] = 0x1FFFFF & load_3(&s[0..3]) as i64;
        a[1] = 0x1FFFFF & (load_4(&s[2..6]) >> 5) as i64;
        a[2] = 0x1FFFFF & (load_3(&s[5..8]) >> 2) as i64;
        a[3] = 0x1FFFFF & (load_4(&s[7..11]) >> 7) as i64;
        a[4] = 0x1FFFFF & (load_4(&s[10..14]) >> 4) as i64;
        a[5] = 0x1FFFFF & (load_3(&s[13..16]) >> 1) as i64;
        a[6] = 0x1FFFFF & (load_4(&s[15..19]) >> 6) as i64;
        a[7] = 0x1FFFFF & (load_3(&s[18..21]) >> 3) as i64;
        a[8] = 0x1FFFFF & load_3(&s[21..24]) as i64;
        a[9] = 0x1FFFFF & (load_4(&s[23..27]) >> 5) as i64;
        a[10] = 0x1FFFFF & (load_3(&s[26..29]) >> 2) as i64;
        a[11] = 0x1FFFFF & (load_4(&s[28..32]) >> 7) as i64;
        a[12] = 0x1FFFFF & (load_4(&s[31..35]) >> 4) as i64;
        a[13] = 0x1FFFFF & (load_3(&s[34..37]) >> 1) as i64;
        a[14] = 0x1FFFFF & (load_4(&s[36..40]) >> 6) as i64;
        a[15] = 0x1FFFFF & (load_3(&s[39..42]) >> 3) as i64;
        a[16] = 0x1FFFFF & load_3(&s[42..45]) as i64;
        a[17] = 0x1FFFFF & (load_4(&s[44..48]) >> 5) as i64;
        a[18] = 0x1FFFFF & (load_3(&s[47..50]) >> 2) as i64;
        a[19] = 0x1FFFFF & (load_4(&s[49..53]) >> 7) as i64;
        a[20] = 0x1FFFFF & (load_4(&s[52..56]) >> 4) as i64;
        a[21] = 0x1FFFFF & (load_3(&s[55..58]) >> 1) as i64;
        a[22] = 0x1FFFFF & (load_4(&s[57..61]) >> 6) as i64;
        a[23] = (load_4(&s[60..64]) >> 3) as i64;

        // L = 2^252 + 27742317777372353535851937790883648493
        // L in 21-bit limbs
        // 상위 limbs를 mod L로 접음
        sc_muladd_inner(&mut a);

        let mut result = [0u8; 32];
        result[0] = a[0] as u8;
        result[1] = (a[0] >> 8) as u8;
        result[2] = ((a[0] >> 16) | (a[1] << 5)) as u8;
        result[3] = (a[1] >> 3) as u8;
        result[4] = (a[1] >> 11) as u8;
        result[5] = ((a[1] >> 19) | (a[2] << 2)) as u8;
        result[6] = (a[2] >> 6) as u8;
        result[7] = ((a[2] >> 14) | (a[3] << 7)) as u8;
        result[8] = (a[3] >> 1) as u8;
        result[9] = (a[3] >> 9) as u8;
        result[10] = ((a[3] >> 17) | (a[4] << 4)) as u8;
        result[11] = (a[4] >> 4) as u8;
        result[12] = (a[4] >> 12) as u8;
        result[13] = ((a[4] >> 20) | (a[5] << 1)) as u8;
        result[14] = (a[5] >> 7) as u8;
        result[15] = ((a[5] >> 15) | (a[6] << 6)) as u8;
        result[16] = (a[6] >> 2) as u8;
        result[17] = (a[6] >> 10) as u8;
        result[18] = ((a[6] >> 18) | (a[7] << 3)) as u8;
        result[19] = (a[7] >> 5) as u8;
        result[20] = (a[7] >> 13) as u8;
        result[21] = a[8] as u8;
        result[22] = (a[8] >> 8) as u8;
        result[23] = ((a[8] >> 16) | (a[9] << 5)) as u8;
        result[24] = (a[9] >> 3) as u8;
        result[25] = (a[9] >> 11) as u8;
        result[26] = ((a[9] >> 19) | (a[10] << 2)) as u8;
        result[27] = (a[10] >> 6) as u8;
        result[28] = ((a[10] >> 14) | (a[11] << 7)) as u8;
        result[29] = (a[11] >> 1) as u8;
        result[30] = (a[11] >> 9) as u8;
        result[31] = (a[11] >> 17) as u8;

        Scalar(result)
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

/// 3바이트를 로드합니다.
#[inline]
fn load_3(b: &[u8]) -> u64 {
    (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16)
}

/// 4바이트를 로드합니다.
#[inline]
fn load_4(b: &[u8]) -> u64 {
    (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16) | ((b[3] as u64) << 24)
}

/// 내부 리덕션 함수
fn sc_muladd_inner(a: &mut [i64; 24]) {
    // L의 계수들 (L = 2^252 + l0, l0 분해)
    // 상위 limbs를 접어서 하위로 전파

    // 12번째 limb부터 역순으로 처리
    // a[i] = a[i] - a[j] * l[k] 형태의 연산

    // L의 21-bit limbs 표현
    // l0 = 27742317777372353535851937790883648493
    // l0 in limbs: [0x6ED, ...]

    // 간략화: L의 상위 252비트는 1이므로
    // a[12..24]를 a[0..12]로 접음

    let l0 = 666643i64;
    let l1 = 470296i64;
    let l2 = 654183i64;
    let l3 = -997805i64;
    let l4 = 136657i64;
    let l5 = -683901i64;

    // a[12..23]을 접음
    a[0] = a[0].wrapping_sub(a[12].wrapping_mul(l0));
    a[1] = a[1].wrapping_sub(a[12].wrapping_mul(l1));
    a[2] = a[2].wrapping_sub(a[12].wrapping_mul(l2));
    a[3] = a[3].wrapping_sub(a[12].wrapping_mul(l3));
    a[4] = a[4].wrapping_sub(a[12].wrapping_mul(l4));
    a[5] = a[5].wrapping_sub(a[12].wrapping_mul(l5));
    a[12] = 0;

    for i in 13..24 {
        let j = i - 12;
        a[j] = a[j].wrapping_sub(a[i].wrapping_mul(l0));
        a[j + 1] = a[j + 1].wrapping_sub(a[i].wrapping_mul(l1));
        a[j + 2] = a[j + 2].wrapping_sub(a[i].wrapping_mul(l2));
        a[j + 3] = a[j + 3].wrapping_sub(a[i].wrapping_mul(l3));
        a[j + 4] = a[j + 4].wrapping_sub(a[i].wrapping_mul(l4));
        a[j + 5] = a[j + 5].wrapping_sub(a[i].wrapping_mul(l5));
        a[i] = 0;
    }

    // 캐리 전파
    for i in 0..11 {
        let carry = (a[i] + (1 << 20)) >> 21;
        a[i + 1] += carry;
        a[i] -= carry << 21;
    }

    // a[11]의 상위 비트 처리
    let carry = (a[11].wrapping_add(1 << 20)) >> 21;
    a[0] = a[0].wrapping_add(carry.wrapping_mul(l0));
    a[1] = a[1].wrapping_add(carry.wrapping_mul(l1));
    a[2] = a[2].wrapping_add(carry.wrapping_mul(l2));
    a[3] = a[3].wrapping_add(carry.wrapping_mul(l3));
    a[4] = a[4].wrapping_add(carry.wrapping_mul(l4));
    a[5] = a[5].wrapping_add(carry.wrapping_mul(l5));
    a[11] = a[11].wrapping_sub(carry << 21);

    // 최종 캐리 전파
    for i in 0..11 {
        let carry = a[i] >> 21;
        a[i + 1] += carry;
        a[i] &= 0x1FFFFF;
    }
    a[11] &= 0x1FFFFF;
}

/// 스칼라 곱셈 후 덧셈: (a * b + c) mod L
pub fn sc_muladd(a: &Scalar, b: &Scalar, c: &Scalar) -> Scalar {
    let mut s = [0i64; 24];

    // a의 limbs
    let a0 = 0x1FFFFF & load_3(&a.0[0..3]) as i64;
    let a1 = 0x1FFFFF & (load_4(&a.0[2..6]) >> 5) as i64;
    let a2 = 0x1FFFFF & (load_3(&a.0[5..8]) >> 2) as i64;
    let a3 = 0x1FFFFF & (load_4(&a.0[7..11]) >> 7) as i64;
    let a4 = 0x1FFFFF & (load_4(&a.0[10..14]) >> 4) as i64;
    let a5 = 0x1FFFFF & (load_3(&a.0[13..16]) >> 1) as i64;
    let a6 = 0x1FFFFF & (load_4(&a.0[15..19]) >> 6) as i64;
    let a7 = 0x1FFFFF & (load_3(&a.0[18..21]) >> 3) as i64;
    let a8 = 0x1FFFFF & load_3(&a.0[21..24]) as i64;
    let a9 = 0x1FFFFF & (load_4(&a.0[23..27]) >> 5) as i64;
    let a10 = 0x1FFFFF & (load_3(&a.0[26..29]) >> 2) as i64;
    let a11 = (load_4(&a.0[28..32]) >> 7) as i64;

    // b의 limbs
    let b0 = 0x1FFFFF & load_3(&b.0[0..3]) as i64;
    let b1 = 0x1FFFFF & (load_4(&b.0[2..6]) >> 5) as i64;
    let b2 = 0x1FFFFF & (load_3(&b.0[5..8]) >> 2) as i64;
    let b3 = 0x1FFFFF & (load_4(&b.0[7..11]) >> 7) as i64;
    let b4 = 0x1FFFFF & (load_4(&b.0[10..14]) >> 4) as i64;
    let b5 = 0x1FFFFF & (load_3(&b.0[13..16]) >> 1) as i64;
    let b6 = 0x1FFFFF & (load_4(&b.0[15..19]) >> 6) as i64;
    let b7 = 0x1FFFFF & (load_3(&b.0[18..21]) >> 3) as i64;
    let b8 = 0x1FFFFF & load_3(&b.0[21..24]) as i64;
    let b9 = 0x1FFFFF & (load_4(&b.0[23..27]) >> 5) as i64;
    let b10 = 0x1FFFFF & (load_3(&b.0[26..29]) >> 2) as i64;
    let b11 = (load_4(&b.0[28..32]) >> 7) as i64;

    // c의 limbs
    let c0 = 0x1FFFFF & load_3(&c.0[0..3]) as i64;
    let c1 = 0x1FFFFF & (load_4(&c.0[2..6]) >> 5) as i64;
    let c2 = 0x1FFFFF & (load_3(&c.0[5..8]) >> 2) as i64;
    let c3 = 0x1FFFFF & (load_4(&c.0[7..11]) >> 7) as i64;
    let c4 = 0x1FFFFF & (load_4(&c.0[10..14]) >> 4) as i64;
    let c5 = 0x1FFFFF & (load_3(&c.0[13..16]) >> 1) as i64;
    let c6 = 0x1FFFFF & (load_4(&c.0[15..19]) >> 6) as i64;
    let c7 = 0x1FFFFF & (load_3(&c.0[18..21]) >> 3) as i64;
    let c8 = 0x1FFFFF & load_3(&c.0[21..24]) as i64;
    let c9 = 0x1FFFFF & (load_4(&c.0[23..27]) >> 5) as i64;
    let c10 = 0x1FFFFF & (load_3(&c.0[26..29]) >> 2) as i64;
    let c11 = (load_4(&c.0[28..32]) >> 7) as i64;

    // a * b 계산
    s[0] = c0 + a0 * b0;
    s[1] = c1 + a0 * b1 + a1 * b0;
    s[2] = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    s[3] = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    s[4] = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    s[5] = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    s[6] = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    s[7] = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    s[8] = c8
        + a0 * b8
        + a1 * b7
        + a2 * b6
        + a3 * b5
        + a4 * b4
        + a5 * b3
        + a6 * b2
        + a7 * b1
        + a8 * b0;
    s[9] = c9
        + a0 * b9
        + a1 * b8
        + a2 * b7
        + a3 * b6
        + a4 * b5
        + a5 * b4
        + a6 * b3
        + a7 * b2
        + a8 * b1
        + a9 * b0;
    s[10] = c10
        + a0 * b10
        + a1 * b9
        + a2 * b8
        + a3 * b7
        + a4 * b6
        + a5 * b5
        + a6 * b4
        + a7 * b3
        + a8 * b2
        + a9 * b1
        + a10 * b0;
    s[11] = c11
        + a0 * b11
        + a1 * b10
        + a2 * b9
        + a3 * b8
        + a4 * b7
        + a5 * b6
        + a6 * b5
        + a7 * b4
        + a8 * b3
        + a9 * b2
        + a10 * b1
        + a11 * b0;
    s[12] = a1 * b11
        + a2 * b10
        + a3 * b9
        + a4 * b8
        + a5 * b7
        + a6 * b6
        + a7 * b5
        + a8 * b4
        + a9 * b3
        + a10 * b2
        + a11 * b1;
    s[13] = a2 * b11
        + a3 * b10
        + a4 * b9
        + a5 * b8
        + a6 * b7
        + a7 * b6
        + a8 * b5
        + a9 * b4
        + a10 * b3
        + a11 * b2;
    s[14] =
        a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
    s[15] = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    s[16] = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    s[17] = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    s[18] = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    s[19] = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    s[20] = a9 * b11 + a10 * b10 + a11 * b9;
    s[21] = a10 * b11 + a11 * b10;
    s[22] = a11 * b11;
    s[23] = 0;

    // mod L 리덕션
    sc_muladd_inner(&mut s);

    // 결과를 바이트로 변환
    let mut result = [0u8; 32];
    result[0] = s[0] as u8;
    result[1] = (s[0] >> 8) as u8;
    result[2] = ((s[0] >> 16) | (s[1] << 5)) as u8;
    result[3] = (s[1] >> 3) as u8;
    result[4] = (s[1] >> 11) as u8;
    result[5] = ((s[1] >> 19) | (s[2] << 2)) as u8;
    result[6] = (s[2] >> 6) as u8;
    result[7] = ((s[2] >> 14) | (s[3] << 7)) as u8;
    result[8] = (s[3] >> 1) as u8;
    result[9] = (s[3] >> 9) as u8;
    result[10] = ((s[3] >> 17) | (s[4] << 4)) as u8;
    result[11] = (s[4] >> 4) as u8;
    result[12] = (s[4] >> 12) as u8;
    result[13] = ((s[4] >> 20) | (s[5] << 1)) as u8;
    result[14] = (s[5] >> 7) as u8;
    result[15] = ((s[5] >> 15) | (s[6] << 6)) as u8;
    result[16] = (s[6] >> 2) as u8;
    result[17] = (s[6] >> 10) as u8;
    result[18] = ((s[6] >> 18) | (s[7] << 3)) as u8;
    result[19] = (s[7] >> 5) as u8;
    result[20] = (s[7] >> 13) as u8;
    result[21] = s[8] as u8;
    result[22] = (s[8] >> 8) as u8;
    result[23] = ((s[8] >> 16) | (s[9] << 5)) as u8;
    result[24] = (s[9] >> 3) as u8;
    result[25] = (s[9] >> 11) as u8;
    result[26] = ((s[9] >> 19) | (s[10] << 2)) as u8;
    result[27] = (s[10] >> 6) as u8;
    result[28] = ((s[10] >> 14) | (s[11] << 7)) as u8;
    result[29] = (s[11] >> 1) as u8;
    result[30] = (s[11] >> 9) as u8;
    result[31] = (s[11] >> 17) as u8;

    Scalar(result)
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        // 단순 덧셈 후 리덕션
        sc_muladd(&Scalar::one(), &self, &rhs)
    }
}

impl Sub for Scalar {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self {
        // a - b = a + (L - b) mod L
        // 단순화: negation 후 덧셈
        let neg_rhs = sc_muladd(&Scalar([0xff; 32]), &rhs, &Scalar::zero());
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
