use crate::AES256;
use crate::ghash::GHash;
use zeroize::Zeroize;

pub const GCM_TAG_SIZE: usize = 16;
pub const GCM_NONCE_SIZE: usize = 12;

fn inc32(block: &mut [u8; 16]) {
    let mut carry = 1u16;
    for i in (12..16).rev() {
        let sum = block[i] as u16 + carry;
        block[i] = sum as u8;
        carry = sum >> 8;
    }
}

pub struct AES256GCM {
    cipher: AES256,
    h: [u8; 16],
}

impl AES256GCM {
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = AES256::new(key);
        let h = cipher.encrypt(&[0u8; 16]);
        Self { cipher, h }
    }

    fn gctr(&self, icb: &[u8; 16], input: &[u8], output: &mut [u8]) {
        let mut cb = *icb;
        let mut offset = 0;

        while offset + 16 <= input.len() {
            let keystream = self.cipher.encrypt(&cb);
            for i in 0..16 {
                output[offset + i] = input[offset + i] ^ keystream[i];
            }
            inc32(&mut cb);
            offset += 16;
        }

        if offset < input.len() {
            let keystream = self.cipher.encrypt(&cb);
            for i in 0..(input.len() - offset) {
                output[offset + i] = input[offset + i] ^ keystream[i];
            }
        }
    }

    fn compute_j0(&self, nonce: &[u8; GCM_NONCE_SIZE]) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        j0
    }

    fn compute_tag(&self, aad: &[u8], ciphertext: &[u8], j0: &[u8; 16]) -> [u8; 16] {
        let mut ghash = GHash::new(&self.h);

        ghash.update_padded(aad);
        ghash.update_padded(ciphertext);

        let len_block = Self::len_block(aad.len(), ciphertext.len());
        ghash.update(&len_block);

        let s = ghash.finalize();
        let e_j0 = self.cipher.encrypt(j0);

        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = s[i] ^ e_j0[i];
        }
        tag
    }

    fn len_block(aad_len: usize, ct_len: usize) -> [u8; 16] {
        let mut block = [0u8; 16];
        let aad_bits = (aad_len as u64) * 8;
        let ct_bits = (ct_len as u64) * 8;
        block[..8].copy_from_slice(&aad_bits.to_be_bytes());
        block[8..].copy_from_slice(&ct_bits.to_be_bytes());
        block
    }

    pub fn encrypt(
        &self,
        nonce: &[u8; GCM_NONCE_SIZE],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; GCM_TAG_SIZE],
    ) {
        let j0 = self.compute_j0(nonce);
        let mut icb = j0;
        inc32(&mut icb);

        self.gctr(&icb, plaintext, ciphertext);

        *tag = self.compute_tag(aad, &ciphertext[..plaintext.len()], &j0);
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; GCM_NONCE_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; GCM_TAG_SIZE],
        plaintext: &mut [u8],
    ) -> bool {
        let j0 = self.compute_j0(nonce);

        let expected_tag = self.compute_tag(aad, ciphertext, &j0);

        let mut diff = 0u8;
        for i in 0..16 {
            diff |= tag[i] ^ expected_tag[i];
        }

        if diff != 0 {
            return false;
        }

        let mut icb = j0;
        inc32(&mut icb);
        self.gctr(&icb, ciphertext, plaintext);

        true
    }
}

impl Drop for AES256GCM {
    fn drop(&mut self) {
        self.h.zeroize();
        // cipher 필드의 round_keys 는 AES256 의 Drop 에서 Secret::Drop 으로 자동 소거됨
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    /// AES256GCM 의 h (해시 서브키 = AES_K(0^128)) 는 키 정보 누출 위험.
    /// Drop 후 h 와 내부 AES round_keys 가 0 으로 소거되는지 검증.
    #[test]
    fn test_aes256gcm_zeroize_on_drop() {
        let key = [0x5Au8; 32];
        let mut storage: MaybeUninit<AES256GCM> = MaybeUninit::uninit();

        unsafe {
            storage.write(AES256GCM::new(&key));
            let h_ptr = storage.assume_init_ref().h.as_ptr();
            let rk_ptr = storage
                .assume_init_ref()
                .cipher
                .round_keys
                .expose()
                .as_ptr() as *const u8;
            let rk_len = core::mem::size_of::<[u32; 60]>();

            let pre_h = core::slice::from_raw_parts(h_ptr, 16);
            assert!(pre_h.iter().any(|&b| b != 0), "GCM h 가 비어 있음");

            storage.assume_init_drop();

            let post_h = core::slice::from_raw_parts(h_ptr, 16);
            let post_rk = core::slice::from_raw_parts(rk_ptr, rk_len);
            assert!(
                post_h.iter().all(|&b| b == 0),
                "GCM h 가 Drop 후 소거되지 않음"
            );
            assert!(
                post_rk.iter().all(|&b| b == 0),
                "GCM 내부 AES256 round_keys 가 Drop 후 소거되지 않음"
            );
        }
    }

    #[test]
    fn gcm_test_case_14() {
        let key: [u8; 32] = [0u8; 32];
        let nonce: [u8; 12] = [0u8; 12];
        let plaintext: [u8; 0] = [];
        let aad: [u8; 0] = [];
        let expected_tag: [u8; 16] = [
            0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
            0x73, 0x8b,
        ];

        let gcm = AES256GCM::new(&key);
        let mut ciphertext = [0u8; 0];
        let mut tag = [0u8; 16];
        gcm.encrypt(&nonce, &aad, &plaintext, &mut ciphertext, &mut tag);
        assert_eq!(tag, expected_tag);
    }

    #[test]
    fn gcm_test_case_15() {
        let key: [u8; 32] = [0u8; 32];
        let nonce: [u8; 12] = [0u8; 12];
        let plaintext: [u8; 16] = [0u8; 16];
        let aad: [u8; 0] = [];
        let expected_ciphertext: [u8; 16] = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18,
        ];
        let expected_tag: [u8; 16] = [
            0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
            0xb9, 0x19,
        ];

        let gcm = AES256GCM::new(&key);
        let mut ciphertext = [0u8; 16];
        let mut tag = [0u8; 16];
        gcm.encrypt(&nonce, &aad, &plaintext, &mut ciphertext, &mut tag);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let mut decrypted = [0u8; 16];
        let result = gcm.decrypt(&nonce, &aad, &ciphertext, &tag, &mut decrypted);
        assert!(result);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn gcm_test_case_16() {
        let key: [u8; 32] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08,
        ];
        let nonce: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let plaintext: [u8; 64] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
        ];
        let aad: [u8; 0] = [];
        let expected_ciphertext: [u8; 64] = [
            0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84,
            0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd,
            0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0,
            0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
            0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad,
        ];
        let expected_tag: [u8; 16] = [
            0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd, 0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3,
            0xcc, 0x6c,
        ];

        let gcm = AES256GCM::new(&key);
        let mut ciphertext = [0u8; 64];
        let mut tag = [0u8; 16];
        gcm.encrypt(&nonce, &aad, &plaintext, &mut ciphertext, &mut tag);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let mut decrypted = [0u8; 64];
        let result = gcm.decrypt(&nonce, &aad, &ciphertext, &tag, &mut decrypted);
        assert!(result);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn gcm_auth_failure() {
        let key: [u8; 32] = [0u8; 32];
        let nonce: [u8; 12] = [0u8; 12];
        let plaintext: [u8; 16] = [0u8; 16];
        let aad: [u8; 0] = [];

        let gcm = AES256GCM::new(&key);
        let mut ciphertext = [0u8; 16];
        let mut tag = [0u8; 16];
        gcm.encrypt(&nonce, &aad, &plaintext, &mut ciphertext, &mut tag);

        tag[0] ^= 1;

        let mut decrypted = [0u8; 16];
        let result = gcm.decrypt(&nonce, &aad, &ciphertext, &tag, &mut decrypted);
        assert!(!result);
    }
}
