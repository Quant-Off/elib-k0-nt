# None-Triple EntanglementLib Crypto Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)

The [Rust-based Entanglement Library native project](https.github.com/Quant-Off/entlib-native) supports `std` (and `no_std`) for the most widely used architectures and focuses on complying with high-security standards (such as international regulations). This module is reasonable in that regard.

This module runs as a daemon in the Ring 3 user space on an Isolation Lightweight Microkernel (ISO-Light-K0) and communicates for encryption via TUI and IPC messages. The daemon operates by sending data to an IPC endpoint router in the Ring 0 kernel space.

Targeting the NT of the `entlib-native` crypto module, it is written 100% in Rust, and despite being lightweight, it still offers strong security.

> [!IMPORTANT]
> This project does not create complex formal documentation (or technical specifications) for each cryptographic function like in `entlib-native`. Instead, the API signatures and usage of the functions are primarily described in Rust documentation comments, and a summary of this will be posted as a `README.md` in the module (or crate) where the functionality is provided.

You can always refer to the [INTRODUCTION_EN.md](INTRODUCTION_EN.md) file for a detailed project introduction!

# `1.0.0` Release

The following features are implemented in this release:

- [Constant-time Ops](./constant-time)
- Hash([SHA2](./sha2), [SHA3](./sha3), [SHAKE](./sha3), [BLAKE2](./blake))
- RNG([Hash DRBG](./rng))
- Digital Signature([Ed25519](./ed25519), [Ed448](./ed448))
- Key Establishment Protocol([X25519](./x25519), [X448](./x448))
- AEAD, BlockCipher([AES](./aes), [ChaCha20-Poly1305](./chacha20))
- Post-Quantum Cryptography([ML-DSA](./mldsa), [ML-KEM](./mlkem))

The primary goal of this release was to implement cryptographic functions and verify their operation through testing. Detailed implementation and testing regarding interaction with the kernel will be released in the next alpha version.

# 라이선스

This project is under the [MIT LICENSE](LICENSE).