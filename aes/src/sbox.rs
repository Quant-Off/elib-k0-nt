//! AES S-box / inverse S-box
//!
//! 과거 구현에서 종전 구현은 256회 constant-time 스캔 방식이었으나, AES-NI 미지원 환경 (TCG 등)
//! 에서는 라운드 1회당 수만 명령어가 발생해 처리량이 급격히 떨어집니다.
//! Boyar–Peralta 최소 게이트 회로 (논리 게이트 ~115 개)로 교체됐습니다. 모든 연산이
//! AND/XOR/NOT 비트 연산이라 비밀 의존 분기·메모리 접근이 없으며 본질적으로 상수-시간입니다.
//!
//! 16바이트 블록은 비트슬라이스 표현 [u32; 8]로 변환해 1회의 BP 회로로 16바이트
//! SubBytes를 일괄 처리합니다. 단일 바이트 sub_byte / inv_sub_byte 는 키 스케쥴
//! (sub_word) 에서 호출되며 동일 회로를 1비트만 사용하는 형태로 호출한다.
//!
//! 회로 출처: Boyar & Peralta, "A New Combinational Logic Minimization Technique
//! with Applications to Cryptology" (2010). BearSSL `aes_ct.c` 의 동일 회로 기반
//! TODO: Dosctring 수정

#![allow(clippy::many_single_char_names, clippy::similar_names)]

// 16바이트 블록을 [u32; 8]비트슬라이스 평면으로 변환
// q[k]의 i번째 비트 = bytes[i]의 k번째 비트
#[inline]
fn bitslice_block(bytes: &[u8; 16]) -> [u32; 8] {
    let mut q = [0u32; 8];
    for (i, &b) in bytes.iter().enumerate() {
        let b = u32::from(b);
        q[0] |= (b & 1) << i;
        q[1] |= ((b >> 1) & 1) << i;
        q[2] |= ((b >> 2) & 1) << i;
        q[3] |= ((b >> 3) & 1) << i;
        q[4] |= ((b >> 4) & 1) << i;
        q[5] |= ((b >> 5) & 1) << i;
        q[6] |= ((b >> 6) & 1) << i;
        q[7] |= ((b >> 7) & 1) << i;
    }
    q
}

#[inline]
fn unbitslice_block(q: &[u32; 8]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = (((q[0] >> i) & 1) as u8)
            | ((((q[1] >> i) & 1) as u8) << 1)
            | ((((q[2] >> i) & 1) as u8) << 2)
            | ((((q[3] >> i) & 1) as u8) << 3)
            | ((((q[4] >> i) & 1) as u8) << 4)
            | ((((q[5] >> i) & 1) as u8) << 5)
            | ((((q[6] >> i) & 1) as u8) << 6)
            | ((((q[7] >> i) & 1) as u8) << 7);
    }
    bytes
}

// Boyar–Peralta forward S-box circuit
// q[0] = LSB plane, q[7] = MSB plane
fn bitsliced_sbox(q: &mut [u32; 8]) {
    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    // Top linear transformation
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear (multiplicative inverse) section
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;
    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear transformation (affine map application)
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

// 역 S-box: 입력에 AES affine 의 역 (= 인접 비트 회전 + 상수 0x05) 을 적용하고
// 정방향 S-box 를 통과시킨 뒤 같은 affine 역변환을 한 번 더 적용
// (S-box(x) = Affine(Inv(x)) 이므로 InvSBox(y) = Inv(Affine⁻¹(y)) = Affine⁻¹(SBox(Affine⁻¹(y))).)
fn bitsliced_inv_sbox(q: &mut [u32; 8]) {
    inv_affine(q);
    bitsliced_sbox(q);
    inv_affine(q);
}

#[inline]
fn inv_affine(q: &mut [u32; 8]) {
    let q0 = !q[0];
    let q1 = !q[1];
    let q2 = q[2];
    let q3 = q[3];
    let q4 = q[4];
    let q5 = !q[5];
    let q6 = !q[6];
    let q7 = q[7];
    q[7] = q1 ^ q4 ^ q6;
    q[6] = q0 ^ q3 ^ q5;
    q[5] = q7 ^ q2 ^ q4;
    q[4] = q6 ^ q1 ^ q3;
    q[3] = q5 ^ q0 ^ q2;
    q[2] = q4 ^ q7 ^ q1;
    q[1] = q3 ^ q6 ^ q0;
    q[0] = q2 ^ q5 ^ q7;
}

/// 16 바이트 블록 SubBytes 를 비트슬라이스 BP 회로로 일괄 적용합니다.
pub fn sub_bytes_block(bytes: &mut [u8; 16]) {
    let mut q = bitslice_block(bytes);
    bitsliced_sbox(&mut q);
    *bytes = unbitslice_block(&q);
}

/// 16 바이트 블록 InvSubBytes 를 비트슬라이스 BP 회로로 일괄 적용합니다.
pub fn inv_sub_bytes_block(bytes: &mut [u8; 16]) {
    let mut q = bitslice_block(bytes);
    bitsliced_inv_sbox(&mut q);
    *bytes = unbitslice_block(&q);
}

/// 단일 바이트 S-box. 키 스케줄 (sub_word) 에서 호출됩니다.
/// 동일 BP 회로를 비트 1 개만 사용하는 형태로 적용 (회로 자체가 데이터 비종속)
#[inline]
#[must_use]
pub fn sub_byte(x: u8) -> u8 {
    let mut q = [0u32; 8];
    for (k, plane) in q.iter_mut().enumerate() {
        *plane = u32::from((x >> k) & 1);
    }
    bitsliced_sbox(&mut q);
    let mut out = 0u8;
    for (k, plane) in q.iter().enumerate() {
        out |= ((*plane & 1) as u8) << k;
    }
    out
}

/// 단일 바이트 역 S-box. 테스트와 향후 디코딩 경로의 셀별 호출용
#[inline]
#[must_use]
#[cfg(test)]
fn inv_sub_byte(x: u8) -> u8 {
    let mut q = [0u32; 8];
    for (k, plane) in q.iter_mut().enumerate() {
        *plane = u32::from((x >> k) & 1);
    }
    bitsliced_inv_sbox(&mut q);
    let mut out = 0u8;
    for (k, plane) in q.iter().enumerate() {
        out |= ((*plane & 1) as u8) << k;
    }
    out
}

#[inline]
#[must_use]
pub fn sub_word(w: u32) -> u32 {
    let b0 = sub_byte((w >> 24) as u8);
    let b1 = sub_byte((w >> 16) as u8);
    let b2 = sub_byte((w >> 8) as u8);
    let b3 = sub_byte(w as u8);
    ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unreadable_literal)]
    const SBOX_REF: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    #[test]
    fn sub_byte_matches_reference() {
        for i in 0..=255u16 {
            let x = i as u8;
            assert_eq!(sub_byte(x), SBOX_REF[x as usize], "sub_byte({x:#04x})");
        }
    }

    #[test]
    fn inv_sub_byte_is_inverse() {
        for i in 0..=255u16 {
            let x = i as u8;
            assert_eq!(inv_sub_byte(sub_byte(x)), x, "round-trip {x:#04x}");
            assert_eq!(sub_byte(inv_sub_byte(x)), x, "round-trip {x:#04x}");
        }
    }

    #[test]
    fn sub_bytes_block_matches_per_byte() {
        let input: [u8; 16] = [
            0x00, 0x01, 0x53, 0xff, 0x10, 0x32, 0x76, 0x88, 0xab, 0xcd, 0xef, 0x42, 0x9a, 0x5e,
            0x7f, 0xc1,
        ];
        let mut block = input;
        sub_bytes_block(&mut block);
        for i in 0..16 {
            assert_eq!(block[i], sub_byte(input[i]), "sub_bytes_block byte {i}");
        }
    }

    #[test]
    fn inv_sub_bytes_block_inverts() {
        let input: [u8; 16] = [
            0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x00, 0xff,
            0x55, 0xaa,
        ];
        let mut block = input;
        sub_bytes_block(&mut block);
        inv_sub_bytes_block(&mut block);
        assert_eq!(block, input);
    }
}
