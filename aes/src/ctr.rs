use crate::AES256;
use zeroize::Zeroize;

pub const CTR_NONCE_SIZE: usize = 12;
pub const CTR_IV_SIZE: usize = 16;

const CTR_MAX_INPUT_LEN: u64 = 1 << 36;

fn inc32(block: &mut [u8; 16]) {
    let mut carry = 1u16;
    for i in (12..16).rev() {
        let sum = block[i] as u16 + carry;
        block[i] = sum as u8;
        carry = sum >> 8;
    }
}

pub struct AES256CTR {
    cipher: AES256,
}

impl AES256CTR {
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: AES256::new(key),
        }
    }

    fn apply_internal(&self, counter: &mut [u8; 16], input: &[u8], output: &mut [u8]) {
        let mut offset = 0;

        while offset + 16 <= input.len() {
            let mut keystream = self.cipher.encrypt(counter);
            for i in 0..16 {
                output[offset + i] = input[offset + i] ^ keystream[i];
            }
            inc32(counter);
            keystream.zeroize();
            offset += 16;
        }

        if offset < input.len() {
            let mut keystream = self.cipher.encrypt(counter);
            for i in 0..(input.len() - offset) {
                output[offset + i] = input[offset + i] ^ keystream[i];
            }
            keystream.zeroize();
        }
    }

    pub fn apply_iv(&self, iv: &[u8; CTR_IV_SIZE], input: &[u8], output: &mut [u8]) {
        assert!(
            output.len() >= input.len(),
            "출력 버퍼가 입력보다 작아 무음 절단 발생"
        );
        assert!(
            input.len() as u64 <= CTR_MAX_INPUT_LEN,
            "입력 길이 한계(2^32 블록) 초과로 카운터 재사용 발생"
        );
        let mut counter = *iv;
        self.apply_internal(&mut counter, input, output);
        counter.zeroize();
    }

    pub fn apply(&self, nonce: &[u8; CTR_NONCE_SIZE], input: &[u8], output: &mut [u8]) {
        assert!(
            output.len() >= input.len(),
            "출력 버퍼가 입력보다 작아 무음 절단 발생"
        );
        assert!(
            input.len() as u64 <= CTR_MAX_INPUT_LEN,
            "입력 길이 한계(2^32 블록) 초과로 카운터 재사용 발생"
        );
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(nonce);
        counter[12..16].copy_from_slice(&1u32.to_be_bytes());
        self.apply_internal(&mut counter, input, output);
        counter.zeroize();
    }

    #[inline]
    pub fn encrypt(&self, nonce: &[u8; CTR_NONCE_SIZE], plaintext: &[u8], ciphertext: &mut [u8]) {
        self.apply(nonce, plaintext, ciphertext);
    }

    #[inline]
    pub fn decrypt(&self, nonce: &[u8; CTR_NONCE_SIZE], ciphertext: &[u8], plaintext: &mut [u8]) {
        self.apply(nonce, ciphertext, plaintext);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctr_nist_f_5_5() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ];
        let plaintext: [u8; 64] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected_ciphertext: [u8; 64] = [
            0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3,
            0xd2, 0x28, 0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90,
            0xca, 0xca, 0xf5, 0xc5, 0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70,
            0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d, 0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
            0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6,
        ];

        let ctr = AES256CTR::new(&key);
        let mut ciphertext = [0u8; 64];
        ctr.apply_iv(&iv, &plaintext, &mut ciphertext);
        assert_eq!(ciphertext, expected_ciphertext);

        let mut decrypted = [0u8; 64];
        ctr.apply_iv(&iv, &ciphertext, &mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn ctr_partial_block() {
        let key: [u8; 32] = [0x42u8; 32];
        let nonce: [u8; 12] = [0x01u8; 12];
        let plaintext: [u8; 20] = [0xAAu8; 20];

        let ctr = AES256CTR::new(&key);
        let mut ciphertext = [0u8; 20];
        ctr.encrypt(&nonce, &plaintext, &mut ciphertext);

        let mut decrypted = [0u8; 20];
        ctr.decrypt(&nonce, &ciphertext, &mut decrypted);
        assert_eq!(decrypted, plaintext);
    }
}
