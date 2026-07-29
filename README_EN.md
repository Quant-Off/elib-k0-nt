# None-Triple EntanglementLib Crypto Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.com/invite/9utg4hp3m8)

> [!IMPORTANT]
> This cryptographic module has not gone through the official CMVP (Cryptographic Module Validation Program). Please use it for research purposes.
> The `1.1.0` release covers the implementation and validation of each cryptographic algorithm, along with the writing of formal documentation.

The [Rust-based Entanglement Library native project](https://github.com/Quant-Off/entlib-native) supports `std` (and `no_std`) for the most widely used architectures and focuses on complying with high-security standards (such as international regulations and compliance). This module is reasonable in that regard.

This module runs as a daemon in the Ring 3 user space on an Isolation Lightweight Microkernel K0 (ISO-LIGHT-K0) and communicates for encryption via TUI and IPC messages. The daemon operates by sending data to an IPC endpoint router in the Ring 0 kernel space.

Targeting the NT of the `entlib-native` crypto module, it is written 100% in Rust, and despite being lightweight, it still offers strong security.

You can always refer to the [INTRODUCTION_EN.md](INTRODUCTION_EN.md) file for a detailed project introduction.

Additionally, information about what scope AI agents are used for in this project, what parts they actually modify, and the skills and prompts used is documented in [AI_SCOPE_EN.md](AI_SCOPE_EN.md).

# Release `1.1.0`

We have corrected several issues and compliance-related implementation errors that went unnoticed in the previous `1.0.0` release. This work is performed based on meticulous and systematic cross-validation, and the records can be found in [this document (Korean)](cross-confirm.md). That document will be removed once the `1.1.0` release is published.

For this release, we focused on cross-validation between the developer, Fable 5, and outside experts for each cryptographic algorithm, along with the writing of formal documentation. A significant number of security issues were resolved in that process. To confirm that every implemented cryptographic algorithm is correctly implemented and works as intended, we are proceeding with CAVP (Cryptographic Algorithm Validation Program) validation under KCMVP.

# License

This project is dual-licensed under either the [MIT LICENSE](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option.
