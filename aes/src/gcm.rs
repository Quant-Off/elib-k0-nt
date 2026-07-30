use crate::ghash::GHash;
use crate::{AES256, Error};
use constant_time::Choice;
use constant_time::traits::CtEqOps;
use zeroize::{Secret, Zeroize};

pub const GCM_TAG_SIZE: usize = 16;
pub const GCM_MIN_TAG_SIZE: usize = 12;
pub const GCM_NONCE_SIZE: usize = 12;

const GCM_MAX_INPUT_LEN: u64 = (1 << 36) - 32;
const GCM_MAX_AAD_LEN: u64 = (1 << 61) - 1;
const GCM_MAX_IV_LEN: u64 = (1 << 61) - 1;

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
    h: Secret<[u8; 16]>,
}

impl AES256GCM {
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = AES256::new(key);
        let h = Secret::new(cipher.encrypt(&[0u8; 16]));
        Self { cipher, h }
    }

    fn gctr(&self, icb: &[u8; 16], input: &[u8], output: &mut [u8]) {
        let mut cb = *icb;
        let mut offset = 0;

        while offset + 16 <= input.len() {
            let mut keystream = self.cipher.encrypt(&cb);
            for i in 0..16 {
                output[offset + i] = input[offset + i] ^ keystream[i];
            }
            inc32(&mut cb);
            keystream.zeroize();
            offset += 16;
        }

        if offset < input.len() {
            let mut keystream = self.cipher.encrypt(&cb);
            for i in 0..(input.len() - offset) {
                output[offset + i] = input[offset + i] ^ keystream[i];
            }
            keystream.zeroize();
        }
        cb.zeroize();
    }

    fn compute_j0(&self, nonce: &[u8; GCM_NONCE_SIZE]) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        j0
    }

    fn compute_j0_iv(&self, iv: &[u8]) -> [u8; 16] {
        if let Ok(nonce) = <&[u8; GCM_NONCE_SIZE]>::try_from(iv) {
            return self.compute_j0(nonce);
        }

        let mut ghash = GHash::new(self.h.expose());
        ghash.update_padded(iv);

        let mut len_block = [0u8; 16];
        let iv_bits = (iv.len() as u64) * 8;
        len_block[8..].copy_from_slice(&iv_bits.to_be_bytes());
        ghash.update(&len_block);

        let j0 = ghash.finalize();
        len_block.zeroize();
        j0
    }

    fn compute_tag(&self, aad: &[u8], ciphertext: &[u8], j0: &[u8; 16]) -> [u8; 16] {
        let mut ghash = GHash::new(self.h.expose());

        ghash.update_padded(aad);
        ghash.update_padded(ciphertext);

        let mut len_block = Self::len_block(aad.len(), ciphertext.len());
        ghash.update(&len_block);

        let mut s = ghash.finalize();
        let mut e_j0 = self.cipher.encrypt(j0);

        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = s[i] ^ e_j0[i];
        }
        s.zeroize();
        e_j0.zeroize();
        len_block.zeroize();
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
    ) -> Result<(), Error> {
        self.encrypt_with_iv(nonce, aad, plaintext, ciphertext, tag)
    }

    pub fn encrypt_with_iv(
        &self,
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), Error> {
        if iv.is_empty() || iv.len() as u64 > GCM_MAX_IV_LEN {
            return Err(Error::InvalidLength);
        }
        if tag.len() < GCM_MIN_TAG_SIZE || tag.len() > GCM_TAG_SIZE {
            return Err(Error::InvalidLength);
        }
        if ciphertext.len() < plaintext.len() {
            return Err(Error::BufferTooSmall);
        }
        if plaintext.len() as u64 > GCM_MAX_INPUT_LEN {
            return Err(Error::InputTooLong);
        }
        if aad.len() as u64 > GCM_MAX_AAD_LEN {
            return Err(Error::AadTooLong);
        }

        let mut j0 = self.compute_j0_iv(iv);
        let mut icb = j0;
        inc32(&mut icb);

        self.gctr(&icb, plaintext, ciphertext);

        let mut full_tag = self.compute_tag(aad, &ciphertext[..plaintext.len()], &j0);
        tag.copy_from_slice(&full_tag[..tag.len()]);

        full_tag.zeroize();
        icb.zeroize();
        j0.zeroize();

        Ok(())
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; GCM_NONCE_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; GCM_TAG_SIZE],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        self.decrypt_with_iv(nonce, aad, ciphertext, tag, plaintext)
    }

    pub fn decrypt_with_iv(
        &self,
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if iv.is_empty() || iv.len() as u64 > GCM_MAX_IV_LEN {
            return Err(Error::InvalidLength);
        }
        if tag.len() < GCM_MIN_TAG_SIZE || tag.len() > GCM_TAG_SIZE {
            return Err(Error::InvalidLength);
        }
        if plaintext.len() < ciphertext.len() {
            return Err(Error::BufferTooSmall);
        }
        if ciphertext.len() as u64 > GCM_MAX_INPUT_LEN {
            return Err(Error::InputTooLong);
        }
        if aad.len() as u64 > GCM_MAX_AAD_LEN {
            return Err(Error::AadTooLong);
        }

        let mut j0 = self.compute_j0_iv(iv);

        let mut expected_tag = self.compute_tag(aad, ciphertext, &j0);

        let mut eq = Choice::from_u8(1);
        for (given, expected) in tag.iter().zip(expected_tag.iter()) {
            eq &= CtEqOps::ct_eq(given, expected);
        }
        let authentic = eq.unwrap_u8() == 1;
        expected_tag.zeroize();

        if !authentic {
            j0.zeroize();
            return Err(Error::AuthenticationFailed);
        }

        let mut icb = j0;
        inc32(&mut icb);
        self.gctr(&icb, ciphertext, plaintext);

        icb.zeroize();
        j0.zeroize();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    // AES256GCM의 h(해시 서브키 = AES_K(0^128))는 키 정보 누출 위험
    // Drop 후 h와 내부 AES round_keys가 0으로 소거되는지 검증
    #[test]
    fn test_aes256gcm_zeroize_on_drop() {
        let key = [0x5Au8; 32];
        let mut storage: MaybeUninit<AES256GCM> = MaybeUninit::uninit();

        unsafe {
            storage.write(AES256GCM::new(&key));
            let h_ptr = storage.assume_init_ref().h.expose().as_ptr();
            let rk_ptr = storage
                .assume_init_ref()
                .cipher
                .round_keys
                .expose()
                .as_ptr() as *const u8;
            let rk_len = size_of::<[u32; 60]>();

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
        gcm.encrypt(&nonce, &aad, &plaintext, &mut ciphertext, &mut tag)
            .unwrap();
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
        gcm.encrypt(&nonce, &aad, &plaintext, &mut ciphertext, &mut tag)
            .unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let mut decrypted = [0u8; 16];
        let result = gcm.decrypt(&nonce, &aad, &ciphertext, &tag, &mut decrypted);
        assert!(result.is_ok());
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
        gcm.encrypt(&nonce, &aad, &plaintext, &mut ciphertext, &mut tag)
            .unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let mut decrypted = [0u8; 64];
        let result = gcm.decrypt(&nonce, &aad, &ciphertext, &tag, &mut decrypted);
        assert!(result.is_ok());
        assert_eq!(decrypted, plaintext);
    }

    // AAD가 비어있지 않은 경로(len_block 의 aad_bits)와 60바이트 평문의 GCTR 부분 블록 경로는 이 KAT 만이 커버합니다.
    #[test]
    fn gcm_test_case_17() {
        let key: [u8; 32] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08,
        ];
        let nonce: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let aad: [u8; 20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let plaintext: [u8; 60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let expected_ciphertext: [u8; 60] = [
            0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84,
            0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd,
            0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0,
            0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
            0xbc, 0xc9, 0xf6, 0x62,
        ];
        let expected_tag: [u8; 16] = [
            0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d,
            0x55, 0x1b,
        ];

        let gcm = AES256GCM::new(&key);
        let mut ciphertext = [0u8; 60];
        let mut tag = [0u8; 16];
        gcm.encrypt(&nonce, &aad, &plaintext, &mut ciphertext, &mut tag)
            .unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let mut decrypted = [0u8; 60];
        let result = gcm.decrypt(&nonce, &aad, &ciphertext, &tag, &mut decrypted);
        assert!(result.is_ok());
        assert_eq!(decrypted, plaintext);

        let mut tampered_aad = aad;
        tampered_aad[0] ^= 1;

        let mut tampered_out = [0u8; 60];
        let result = gcm.decrypt(&nonce, &tampered_aad, &ciphertext, &tag, &mut tampered_out);
        assert_eq!(result, Err(Error::AuthenticationFailed));
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
        gcm.encrypt(&nonce, &aad, &plaintext, &mut ciphertext, &mut tag)
            .unwrap();

        tag[0] ^= 1;

        let mut decrypted = [0u8; 16];
        let result = gcm.decrypt(&nonce, &aad, &ciphertext, &tag, &mut decrypted);
        assert_eq!(result, Err(Error::AuthenticationFailed));
    }

    #[test]
    fn gcm_buffer_too_small() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let aad: [u8; 0] = [];
        let plaintext = [0x33u8; 32];

        let gcm = AES256GCM::new(&key);
        let mut ciphertext = [0u8; 16];
        let mut tag = [0u8; 16];
        let result = gcm.encrypt(&nonce, &aad, &plaintext, &mut ciphertext, &mut tag);
        assert_eq!(result, Err(Error::BufferTooSmall));
    }

    fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        let mut out = [0u8; N];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = char::from(s.as_bytes()[2 * i]).to_digit(16).unwrap() as u8;
            let lo = char::from(s.as_bytes()[2 * i + 1]).to_digit(16).unwrap() as u8;
            *byte = (hi << 4) | lo;
        }
        out
    }

    // GCM 스펙 Test Case 17 64비트 IV로 GHASH 기반 J0 경로 커버
    #[test]
    fn gcm_test_case_18() {
        let key: [u8; 32] =
            hex_arr("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv: [u8; 8] = hex_arr("cafebabefacedbad");
        let aad: [u8; 20] = hex_arr("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext: [u8; 60] = hex_arr(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let expected_ciphertext: [u8; 60] = hex_arr(
            "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
        );
        let expected_tag: [u8; 16] = hex_arr("3a337dbf46a792c45e454913fe2ea8f2");

        let gcm = AES256GCM::new(&key);
        let mut ciphertext = [0u8; 60];
        let mut tag = [0u8; 16];
        gcm.encrypt_with_iv(&iv, &aad, &plaintext, &mut ciphertext, &mut tag)
            .unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let mut decrypted = [0u8; 60];
        gcm.decrypt_with_iv(&iv, &aad, &ciphertext, &tag, &mut decrypted)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // GCM 스펙 Test Case 18 60바이트 IV로 GHASH J0 패딩 경로 커버
    #[test]
    fn gcm_test_case_19() {
        let key: [u8; 32] =
            hex_arr("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv: [u8; 60] = hex_arr(
            "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
        );
        let aad: [u8; 20] = hex_arr("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext: [u8; 60] = hex_arr(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let expected_ciphertext: [u8; 60] = hex_arr(
            "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
        );
        let expected_tag: [u8; 16] = hex_arr("a44a8266ee1c8eb0c8b5d4cf5ae9f19a");

        let gcm = AES256GCM::new(&key);
        let mut ciphertext = [0u8; 60];
        let mut tag = [0u8; 16];
        gcm.encrypt_with_iv(&iv, &aad, &plaintext, &mut ciphertext, &mut tag)
            .unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let mut decrypted = [0u8; 60];
        gcm.decrypt_with_iv(&iv, &aad, &ciphertext, &tag, &mut decrypted)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // 절단 태그(96~120비트) 왕복과 파라미터 검증 오류 경로 커버
    #[test]
    fn gcm_truncated_tag_and_param_validation() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 12];
        let aad: [u8; 0] = [];
        let plaintext = [0x33u8; 24];

        let gcm = AES256GCM::new(&key);
        let mut ciphertext = [0u8; 24];
        let mut full_tag = [0u8; 16];
        gcm.encrypt(&iv, &aad, &plaintext, &mut ciphertext, &mut full_tag)
            .unwrap();

        for tag_len in GCM_MIN_TAG_SIZE..=GCM_TAG_SIZE {
            let mut ct = [0u8; 24];
            let mut tag = [0u8; 16];
            gcm.encrypt_with_iv(&iv, &aad, &plaintext, &mut ct, &mut tag[..tag_len])
                .unwrap();
            assert_eq!(ct, ciphertext);
            assert_eq!(tag[..tag_len], full_tag[..tag_len]);

            let mut pt = [0u8; 24];
            gcm.decrypt_with_iv(&iv, &aad, &ciphertext, &tag[..tag_len], &mut pt)
                .unwrap();
            assert_eq!(pt, plaintext);

            let mut bad = tag;
            bad[tag_len - 1] ^= 1;
            let mut pt2 = [0u8; 24];
            assert_eq!(
                gcm.decrypt_with_iv(&iv, &aad, &ciphertext, &bad[..tag_len], &mut pt2),
                Err(Error::AuthenticationFailed)
            );
        }

        let mut short_tag = [0u8; GCM_MIN_TAG_SIZE - 1];
        let mut ct = [0u8; 24];
        assert_eq!(
            gcm.encrypt_with_iv(&iv, &aad, &plaintext, &mut ct, &mut short_tag),
            Err(Error::InvalidLength)
        );
        let mut pt = [0u8; 24];
        assert_eq!(
            gcm.decrypt_with_iv(&[], &aad, &ciphertext, &full_tag, &mut pt),
            Err(Error::InvalidLength)
        );
    }
}
