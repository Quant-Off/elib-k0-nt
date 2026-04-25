#[cfg(test)]
mod tests {
    use crate::{SHA3, SHA3_256, SHA3_512};

    #[test]
    fn sha3_256() {
        let mut s256_state = SHA3_256::new();
        s256_state.update(b"Hello, World!");
        let s256_digest = s256_state.finalize();

        let expected: &[u8; 32] = b"\x1a\xf1\x7a\x66\x4e\x3f\xa8\xe4\x19\xb8\xba\x05\xc2\xa1\x73\x16\x9d\xf7\x61\x62\xa5\xa2\x86\xe0\xc4\x05\xb4\x60\xd4\x78\xf7\xef";
        assert_eq!(s256_digest.as_bytes(), expected.as_ref());
    }

    #[test]
    fn sha3_512() {
        let mut s512_state = SHA3_512::new();
        s512_state.update(b"Hello, World!");
        let s512_digest = s512_state.finalize();

        let expected: &[u8; 64] = b"\x38\xe0\x5c\x33\xd7\xb0\x67\x12\x7f\x21\x7d\x8c\x85\x6e\x55\x4f\xcf\xf0\x9c\x93\x20\xb8\xa5\x97\x9c\xe2\xff\x5d\x95\xdd\x27\xba\x35\xd1\xfb\xa5\x0c\x56\x2d\xfd\x1d\x6c\xc4\x8b\xc9\xc5\xba\xa4\x39\x08\x94\x41\x8c\xc9\x42\xd9\x68\xf9\x7b\xcb\x65\x94\x19\xed";
        assert_eq!(s512_digest.as_bytes(), expected.as_ref());
    }
}
