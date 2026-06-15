#![allow(clippy::needless_range_loop)]

use crate::sbox::{inv_sub_bytes_block, sub_bytes_block};
use zeroize::Zeroize;

const NB: usize = 4;
const NR: usize = 14;

pub type State = [[u8; 4]; 4];

#[inline]
pub fn block_to_state(block: &[u8; 16]) -> State {
    let mut state = [[0u8; 4]; 4];
    for c in 0..4 {
        for r in 0..4 {
            state[r][c] = block[c * 4 + r];
        }
    }
    state
}

#[inline]
pub fn state_to_block(state: &State) -> [u8; 16] {
    let mut block = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            block[c * 4 + r] = state[r][c];
        }
    }
    block
}

// SubBytes 는 셀 위치에 의존 안해서 행렬 -> 16 바이트 -> BP 회로 -> 16 바이트
// -> 행렬 순서로 우회됌. 비트슬라이스 변환/복원 비용은 라운드 1회 약 60게이트
// 수준으로, 셀별 256회 스캔(이전) 보다 압도적으로 작다!
#[inline]
fn sub_bytes(state: &mut State) {
    let mut bytes = [0u8; 16];
    for r in 0..4 {
        for c in 0..4 {
            bytes[r * 4 + c] = state[r][c];
        }
    }
    sub_bytes_block(&mut bytes);
    for r in 0..4 {
        for c in 0..4 {
            state[r][c] = bytes[r * 4 + c];
        }
    }
    bytes.zeroize();
}

#[inline]
fn inv_sub_bytes(state: &mut State) {
    let mut bytes = [0u8; 16];
    for r in 0..4 {
        for c in 0..4 {
            bytes[r * 4 + c] = state[r][c];
        }
    }
    inv_sub_bytes_block(&mut bytes);
    for r in 0..4 {
        for c in 0..4 {
            state[r][c] = bytes[r * 4 + c];
        }
    }
    bytes.zeroize();
}

#[inline]
fn shift_rows(state: &mut State) {
    let t = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = t;

    let t0 = state[2][0];
    let t1 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = t0;
    state[2][3] = t1;

    let t = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = t;
}

#[inline]
fn inv_shift_rows(state: &mut State) {
    let t = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = t;

    let t0 = state[2][0];
    let t1 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = t0;
    state[2][3] = t1;

    let t = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = t;
}

#[inline]
fn xtime(x: u8) -> u8 {
    let hi = (x >> 7) & 1;
    let shifted = x << 1;
    shifted ^ (hi * 0x1b)
}

#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & ((b & 1).wrapping_neg());
        let hi = (a >> 7) & 1;
        a = (a << 1) ^ (hi * 0x1b);
        b >>= 1;
    }
    p
}

#[inline]
fn mix_column(col: [u8; 4]) -> [u8; 4] {
    let (s0, s1, s2, s3) = (col[0], col[1], col[2], col[3]);
    [
        xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3,
        s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3,
        s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3,
        xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3),
    ]
}

#[inline]
fn mix_columns(state: &mut State) {
    for c in 0..4 {
        let col = [state[0][c], state[1][c], state[2][c], state[3][c]];
        let mixed = mix_column(col);
        state[0][c] = mixed[0];
        state[1][c] = mixed[1];
        state[2][c] = mixed[2];
        state[3][c] = mixed[3];
    }
}

#[inline]
fn inv_mix_column(col: [u8; 4]) -> [u8; 4] {
    let (s0, s1, s2, s3) = (col[0], col[1], col[2], col[3]);
    [
        gf_mul(s0, 0x0e) ^ gf_mul(s1, 0x0b) ^ gf_mul(s2, 0x0d) ^ gf_mul(s3, 0x09),
        gf_mul(s0, 0x09) ^ gf_mul(s1, 0x0e) ^ gf_mul(s2, 0x0b) ^ gf_mul(s3, 0x0d),
        gf_mul(s0, 0x0d) ^ gf_mul(s1, 0x09) ^ gf_mul(s2, 0x0e) ^ gf_mul(s3, 0x0b),
        gf_mul(s0, 0x0b) ^ gf_mul(s1, 0x0d) ^ gf_mul(s2, 0x09) ^ gf_mul(s3, 0x0e),
    ]
}

#[inline]
fn inv_mix_columns(state: &mut State) {
    for c in 0..4 {
        let col = [state[0][c], state[1][c], state[2][c], state[3][c]];
        let mixed = inv_mix_column(col);
        state[0][c] = mixed[0];
        state[1][c] = mixed[1];
        state[2][c] = mixed[2];
        state[3][c] = mixed[3];
    }
}

#[inline]
fn add_round_key(state: &mut State, round_key: &[u32]) {
    for c in 0..NB {
        let k = round_key[c].to_be_bytes();
        state[0][c] ^= k[0];
        state[1][c] ^= k[1];
        state[2][c] ^= k[2];
        state[3][c] ^= k[3];
    }
}

pub fn encrypt_block(block: &[u8; 16], round_keys: &[u32; NB * (NR + 1)]) -> [u8; 16] {
    let mut state = block_to_state(block);

    add_round_key(&mut state, &round_keys[0..NB]);

    for round in 1..NR {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &round_keys[round * NB..(round + 1) * NB]);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[NR * NB..(NR + 1) * NB]);

    let out = state_to_block(&state);
    state.zeroize();
    out
}

pub fn decrypt_block(block: &[u8; 16], round_keys: &[u32; NB * (NR + 1)]) -> [u8; 16] {
    let mut state = block_to_state(block);

    add_round_key(&mut state, &round_keys[NR * NB..(NR + 1) * NB]);

    for round in (1..NR).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &round_keys[round * NB..(round + 1) * NB]);
        inv_mix_columns(&mut state);
    }

    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, &round_keys[0..NB]);

    let out = state_to_block(&state);
    state.zeroize();
    out
}
