# ELIB-K0-NT

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.com/invite/9utg4hp3m8)

> [!IMPORTANT]
> This cryptographic module has not gone through a formal CMVP (Cryptographic Module Validation Program). Please use it for research purposes only.
> The 1.1.0 release focuses on implementing and verifying each cryptographic algorithm, along with writing formal documentation.

This module runs as a daemon in Ring 3 user space on the Isolation Lightweight Microkernel K0 (ISO-LIGHT-K0), communicating cryptographically through a TUI and IPC messages. The daemon works by forwarding data to the IPC endpoint router inside Ring 0 (kernel space).

Please refer to [INTRODUCTION.md](INTRODUCTION.md) for the project introduction. We've also documented the scope in which AI agents are used in this project, including what they actually modify and which skills and prompts are used, in [AI_SCOPE.md](AI_SCOPE.md).

# Release `1.1.0`

We've fixed a number of issues that went unnoticed in the previous `1.0.0` release, along with implementation errors on the compliance side. A more detailed record can be found in [this document](release1.1.0-confirm.md). That document will be removed once the `1.1.0` release is published.

This release focused mainly on resolving issues in individual cryptographic algorithms, cross-verification, and writing formal documentation. In the process, we resolved a significant number of security issues. To confirm that every implemented cryptographic algorithm is correctly implemented and functioning, we scheduled KCMVP's CAVP (Cryptographic Algorithm Validation Program) verification work, and have now completed all of it.

# License

This project is dual-licensed under [MIT LICENSE](LICENSE-MIT) or [Apache License 2.0](LICENSE-APACHE), at your option.
