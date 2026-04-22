# None-Triple EntanglementLib Crypto Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)

The [Rust-based Entanglement Library native project](https.github.com/Quant-Off/entlib-native) supports `std` (and `no_std`) for the most widely used architectures and focuses on complying with high-security standards (such as international regulations). This module is reasonable in that regard.

This module runs as a daemon in the Ring 3 user space on an Isolation Lightweight Microkernel (ISO-Light-K0) and communicates for encryption via TUI and IPC messages. The daemon operates by sending data to an IPC endpoint router in the Ring 0 kernel space.

Targeting the NT of the `entlib-native` crypto module, it is written 100% in Rust, and despite being lightweight, it still offers strong security.

> [!IMPORTANT]
> This project does not create complex formal documentation (or technical specifications) for each cryptographic function like in `entlib-native`. Instead, the API signatures and usage of the functions are primarily described in Rust documentation comments, and a summary of this will be posted as a `README.md` in the module (or crate) where the functionality is provided.

# Release Implementation and Goals

This includes an implementation that brings back the lifecycle control of `SecureBuffer`, a single bottleneck management structure that was a mainstay in the Entanglement Library. During the initial version, I tried to include individual functions in a single module, but I found it easier to manage them on a crate-by-crate basis, so I chose a virtual manifest structure for the root.

The implementation goals for this release `1.0.0` are as follows:

- Post-Quantum Cryptography(ML-DSA, ML-KEM)

The following features are currently implemented:

- [Constant-time Ops](./constant-time)
- Hash([SHA2](./sha2), [SHA3](./sha3), [SHAKE](./sha3), [BLAKE2](./blake))
- RNG([Hash DRBG](./rng))
- Digital Signature([Ed25519](./ed25519), [Ed448](./ed448))
- Key Establishment Protocol([X25519](./x25519), [X448](./x448))
- AEAD, BlockCipher([AES](./aes), [ChaCha20-Poly1305](./chacha20))

Once all the above features are implemented, I plan to focus on clearly documenting the usage of each feature through `README.md` files in their respective crates.

In this release, the primary goal is to implement the cryptographic functions and verify their correct operation through testing. Detailed implementation and testing regarding normal interaction with the kernel will be released in the next alpha version.

# 라이선스

This project is under the [MIT LICENSE](LICENSE).