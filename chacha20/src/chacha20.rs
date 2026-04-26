#![allow(clippy::identity_op)]

use zeroize::{Secret, Zeroize};

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn rotl(v: u32, n: u32) -> u32 {
    v.rotate_left(n)
}

#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = rotl(state[d], 16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = rotl(state[b], 12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = rotl(state[d], 8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = rotl(state[b], 7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];

    state[0] = CONSTANTS[0];
    state[1] = CONSTANTS[1];
    state[2] = CONSTANTS[2];
    state[3] = CONSTANTS[3];

    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }

    state[12] = counter;

    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    let mut working = state;

    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);

        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    for i in 0..16 {
        working[i] = working[i].wrapping_add(state[i]);
    }

    let mut output = [0u8; 64];
    for i in 0..16 {
        let bytes = working[i].to_le_bytes();
        output[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }

    // 키, 카운터를 포함하는 내부 워크 버퍼 명시적 소거
    state.zeroize();
    working.zeroize();

    output
}

pub struct ChaCha20 {
    key: Secret<[u8; 32]>,
    nonce: [u8; 12],
    counter: u32,
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self {
            key: Secret::new(*key),
            nonce: *nonce,
            counter: 0,
        }
    }

    pub fn new_with_counter(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        Self {
            key: Secret::new(*key),
            nonce: *nonce,
            counter,
        }
    }

    pub fn keystream_block(&mut self) -> [u8; 64] {
        let block = chacha20_block(self.key.expose(), self.counter, &self.nonce);
        self.counter = self.counter.wrapping_add(1);
        block
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let mut keystream = self.keystream_block();
            let remaining = data.len() - offset;
            let to_process = remaining.min(64);

            for i in 0..to_process {
                data[offset + i] ^= keystream[i];
            }

            keystream.zeroize();
            offset += to_process;
        }
    }

    pub fn generate_poly1305_key(&mut self) -> [u8; 32] {
        let mut block = chacha20_block(self.key.expose(), 0, &self.nonce);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&block[..32]);
        block.zeroize();
        self.counter = 1;
        poly_key
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        // key 는 Secret::Drop 으로 자동 소거
        self.nonce.zeroize();
        self.counter.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    /// ChaCha20 의 key (Secret 래핑), nonce, counter 가 Drop 시 모두 0 으로 소거되는지 검증.
    #[test]
    fn test_chacha20_zeroize_on_drop() {
        let key = [0xA5u8; 32];
        let nonce = [0x5Au8; 12];
        let mut storage: MaybeUninit<ChaCha20> = MaybeUninit::uninit();

        unsafe {
            storage.write(ChaCha20::new_with_counter(&key, &nonce, 42));
            let key_ptr = storage.assume_init_ref().key.expose().as_ptr();
            let nonce_ptr = storage.assume_init_ref().nonce.as_ptr();
            let ctr_ptr = &raw const (*storage.as_ptr()).counter;

            let pre_key = core::slice::from_raw_parts(key_ptr, 32);
            let pre_nonce = core::slice::from_raw_parts(nonce_ptr, 12);
            assert!(pre_key.iter().all(|&b| b == 0xA5), "key 초기 패턴 미반영");
            assert!(
                pre_nonce.iter().all(|&b| b == 0x5A),
                "nonce 초기 패턴 미반영"
            );
            assert_eq!(core::ptr::read(ctr_ptr), 42);

            storage.assume_init_drop();

            let post_key = core::slice::from_raw_parts(key_ptr, 32);
            let post_nonce = core::slice::from_raw_parts(nonce_ptr, 12);
            assert!(post_key.iter().all(|&b| b == 0), "ChaCha20 key 미소거");
            assert!(post_nonce.iter().all(|&b| b == 0), "ChaCha20 nonce 미소거");
            assert_eq!(core::ptr::read(ctr_ptr), 0, "ChaCha20 counter 미소거");
        }
    }

    #[test]
    fn test_chacha20_block_rfc8439_vector() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter: u32 = 1;

        let block = chacha20_block(&key, counter, &nonce);

        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];

        assert_eq!(block, expected);
    }

    #[test]
    fn test_chacha20_encryption_rfc8439() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_ciphertext: [u8; 114] = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        let mut chacha = ChaCha20::new_with_counter(&key, &nonce, 1);
        let mut output = [0u8; 114];
        output.copy_from_slice(plaintext);
        chacha.apply_keystream(&mut output);

        assert_eq!(output, expected_ciphertext);
    }
}
