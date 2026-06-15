# None-Triple EntanglementLib Crypto Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.com/invite/9utg4hp3m8)

The [Rust-based Entanglement Library native project](https://github.com/Quant-Off/entlib-native) supports `std` (and `no_std`) for the most widely used architectures and focuses on complying with high-security standards (such as international regulations and compliance). This module is reasonable in that regard.

This module runs as a daemon in the Ring 3 user space on an Isolation Lightweight Microkernel K0 (ISO-LIGHT-K0) and communicates for encryption via TUI and IPC messages. The daemon operates by sending data to an IPC endpoint router in the Ring 0 kernel space.

Targeting the NT of the `entlib-native` crypto module, it is written 100% in Rust, and despite being lightweight, it still offers strong security.

> [!IMPORTANT]
> This project does not create complex formal documentation (or technical specifications) for each cryptographic function like in `entlib-native`. Instead, the API signatures and usage of the functions are primarily described in Rust documentation comments, and a summary of this will be posted as a `README.md` in the module (or crate) where the functionality is provided.

You can always refer to the [INTRODUCTION_EN.md](INTRODUCTION_EN.md) file for a detailed project introduction.

Additionally, information about what scope AI agents are used for in this project, what parts they actually modify, and the skills and prompts used is documented in [AI_SCOPE_EN.md](AI_SCOPE_EN.md).

# Release `1.1.0`

We are preparing a release to correct several issues and compliance-related implementation errors that were not discovered in the previous `1.0.0` release. This work is performed based on meticulous and systematic cross-validation, and the records can be found in [this document (Korean)](cross-confirm.md). That document will be removed once the `1.1.0` release is published.

# License

This project is under the [MIT LICENSE](LICENSE).
