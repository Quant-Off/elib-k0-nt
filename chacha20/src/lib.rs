#![cfg_attr(not(test), no_std)]
#![allow(clippy::manual_is_multiple_of)]

mod chacha20;
mod poly1305;

use chacha20::{ChaCha20, zeroize_u8_array};
use constant_time::{Choice, CtEqOps};
use core::hint::black_box;
use poly1305::{Poly1305, poly1305_verify};

pub use chacha20::ChaCha20 as ChaCha20Core;
pub use poly1305::Poly1305 as Poly1305Core;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidTagLength,
    AuthenticationFailed,
    BufferTooSmall,
}

pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Self { key: k }
    }

    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), Error> {
        if ciphertext.len() < plaintext.len() {
            return Err(Error::BufferTooSmall);
        }

        let mut chacha = ChaCha20::new(&self.key, nonce);
        let mut poly_key = chacha.generate_poly1305_key();

        ciphertext[..plaintext.len()].copy_from_slice(plaintext);
        chacha.apply_keystream(&mut ciphertext[..plaintext.len()]);

        let mut poly = Poly1305::new(&poly_key);

        poly.update(aad);
        if aad.len() % 16 != 0 {
            let padding = [0u8; 16];
            poly.update(&padding[..16 - (aad.len() % 16)]);
        }

        poly.update(&ciphertext[..plaintext.len()]);
        if plaintext.len() % 16 != 0 {
            let padding = [0u8; 16];
            poly.update(&padding[..16 - (plaintext.len() % 16)]);
        }

        let mut lengths = [0u8; 16];
        lengths[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lengths[8..16].copy_from_slice(&(plaintext.len() as u64).to_le_bytes());
        poly.update(&lengths);

        let computed_tag = poly.finalize();
        tag.copy_from_slice(&computed_tag);

        zeroize_u8_array(&mut poly_key);
        zeroize_u8_array(&mut lengths);

        Ok(())
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if plaintext.len() < ciphertext.len() {
            return Err(Error::BufferTooSmall);
        }

        let mut chacha = ChaCha20::new(&self.key, nonce);
        let mut poly_key = chacha.generate_poly1305_key();

        let mut poly = Poly1305::new(&poly_key);

        poly.update(aad);
        if aad.len() % 16 != 0 {
            let padding = [0u8; 16];
            poly.update(&padding[..16 - (aad.len() % 16)]);
        }

        poly.update(ciphertext);
        if ciphertext.len() % 16 != 0 {
            let padding = [0u8; 16];
            poly.update(&padding[..16 - (ciphertext.len() % 16)]);
        }

        let mut lengths = [0u8; 16];
        lengths[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lengths[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        poly.update(&lengths);

        let computed_tag = poly.finalize();

        if !poly1305_verify(&computed_tag, tag) {
            zeroize_u8_array(&mut poly_key);
            return Err(Error::AuthenticationFailed);
        }

        plaintext[..ciphertext.len()].copy_from_slice(ciphertext);
        chacha.apply_keystream(&mut plaintext[..ciphertext.len()]);

        zeroize_u8_array(&mut poly_key);
        zeroize_u8_array(&mut lengths);

        Ok(())
    }

    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<[u8; 16], Error> {
        if buffer.len() < plaintext_len {
            return Err(Error::BufferTooSmall);
        }

        let mut chacha = ChaCha20::new(&self.key, nonce);
        let mut poly_key = chacha.generate_poly1305_key();

        chacha.apply_keystream(&mut buffer[..plaintext_len]);

        let mut poly = Poly1305::new(&poly_key);

        poly.update(aad);
        if aad.len() % 16 != 0 {
            let padding = [0u8; 16];
            poly.update(&padding[..16 - (aad.len() % 16)]);
        }

        poly.update(&buffer[..plaintext_len]);
        if plaintext_len % 16 != 0 {
            let padding = [0u8; 16];
            poly.update(&padding[..16 - (plaintext_len % 16)]);
        }

        let mut lengths = [0u8; 16];
        lengths[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lengths[8..16].copy_from_slice(&(plaintext_len as u64).to_le_bytes());
        poly.update(&lengths);

        let tag = poly.finalize();

        zeroize_u8_array(&mut poly_key);
        zeroize_u8_array(&mut lengths);

        Ok(tag)
    }

    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        ciphertext_len: usize,
        tag: &[u8; 16],
    ) -> Result<(), Error> {
        if buffer.len() < ciphertext_len {
            return Err(Error::BufferTooSmall);
        }

        let mut chacha = ChaCha20::new(&self.key, nonce);
        let mut poly_key = chacha.generate_poly1305_key();

        let mut poly = Poly1305::new(&poly_key);

        poly.update(aad);
        if aad.len() % 16 != 0 {
            let padding = [0u8; 16];
            poly.update(&padding[..16 - (aad.len() % 16)]);
        }

        poly.update(&buffer[..ciphertext_len]);
        if ciphertext_len % 16 != 0 {
            let padding = [0u8; 16];
            poly.update(&padding[..16 - (ciphertext_len % 16)]);
        }

        let mut lengths = [0u8; 16];
        lengths[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lengths[8..16].copy_from_slice(&(ciphertext_len as u64).to_le_bytes());
        poly.update(&lengths);

        let computed_tag = poly.finalize();

        if !poly1305_verify(&computed_tag, tag) {
            zeroize_u8_array(&mut poly_key);
            return Err(Error::AuthenticationFailed);
        }

        chacha.apply_keystream(&mut buffer[..ciphertext_len]);

        zeroize_u8_array(&mut poly_key);
        zeroize_u8_array(&mut lengths);

        Ok(())
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        zeroize_u8_array(&mut self.key);
        let _ = black_box(&self.key);
    }
}

pub fn verify_tag(computed: &[u8; 16], expected: &[u8; 16]) -> bool {
    let mut eq = Choice::from_u8(1);
    for i in 0..16 {
        eq &= CtEqOps::eq(&computed[i], &expected[i]);
    }
    eq.unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_poly1305_rfc8439_vector() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];

        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];

        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_ciphertext: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];

        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let aead = ChaCha20Poly1305::new(&key);

        let mut ciphertext = [0u8; 114];
        let mut tag = [0u8; 16];
        aead.encrypt(&nonce, &aad, plaintext, &mut ciphertext, &mut tag)
            .unwrap();

        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let mut decrypted = [0u8; 114];
        aead.decrypt(&nonce, &aad, &ciphertext, &tag, &mut decrypted)
            .unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"additional data";
        let plaintext = b"Hello, World!";

        let aead = ChaCha20Poly1305::new(&key);

        let mut ciphertext = [0u8; 13];
        let mut tag = [0u8; 16];
        aead.encrypt(&nonce, aad, plaintext, &mut ciphertext, &mut tag)
            .unwrap();

        let mut decrypted = [0u8; 13];
        aead.decrypt(&nonce, aad, &ciphertext, &tag, &mut decrypted)
            .unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_chacha20_poly1305_tamper_detection() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"additional data";
        let plaintext = b"Hello, World!";

        let aead = ChaCha20Poly1305::new(&key);

        let mut ciphertext = [0u8; 13];
        let mut tag = [0u8; 16];
        aead.encrypt(&nonce, aad, plaintext, &mut ciphertext, &mut tag)
            .unwrap();

        ciphertext[0] ^= 0x01;

        let mut decrypted = [0u8; 13];
        let result = aead.decrypt(&nonce, aad, &ciphertext, &tag, &mut decrypted);
        assert_eq!(result, Err(Error::AuthenticationFailed));
    }

    #[test]
    fn test_chacha20_poly1305_in_place() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"additional data";
        let plaintext = b"Hello, World!";

        let aead = ChaCha20Poly1305::new(&key);

        let mut buffer = [0u8; 13];
        buffer.copy_from_slice(plaintext);

        let tag = aead
            .encrypt_in_place(&nonce, aad, &mut buffer, plaintext.len())
            .unwrap();

        aead.decrypt_in_place(&nonce, aad, &mut buffer, plaintext.len(), &tag)
            .unwrap();

        assert_eq!(&buffer[..], &plaintext[..]);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"only aad, no plaintext";
        let plaintext: &[u8] = b"";

        let aead = ChaCha20Poly1305::new(&key);

        let mut ciphertext = [0u8; 0];
        let mut tag = [0u8; 16];
        aead.encrypt(&nonce, aad, plaintext, &mut ciphertext, &mut tag)
            .unwrap();

        let mut decrypted = [0u8; 0];
        aead.decrypt(&nonce, aad, &ciphertext, &tag, &mut decrypted)
            .unwrap();
    }

    #[test]
    fn test_empty_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad: &[u8] = b"";
        let plaintext = b"plaintext only";

        let aead = ChaCha20Poly1305::new(&key);

        let mut ciphertext = [0u8; 14];
        let mut tag = [0u8; 16];
        aead.encrypt(&nonce, aad, plaintext, &mut ciphertext, &mut tag)
            .unwrap();

        let mut decrypted = [0u8; 14];
        aead.decrypt(&nonce, aad, &ciphertext, &tag, &mut decrypted)
            .unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }
}
