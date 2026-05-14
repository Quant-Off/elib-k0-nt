# None-Triple EntanglementLib Crypto Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://github.com/Quant-Off/)

The [Rust-based Entanglement Library native project](https.github.com/Quant-Off/entlib-native) supports `std` (and `no_std`) for the most widely used architectures and focuses on complying with high-security standards (such as international regulations). This module is reasonable in that regard.

This module runs as a daemon in the Ring 3 user space on an Isolation Lightweight Microkernel K0 (ISO-LIGHT-K0) and communicates for encryption via TUI and IPC messages. The daemon operates by sending data to an IPC endpoint router in the Ring 0 kernel space.

Targeting the NT of the `entlib-native` crypto module, it is written 100% in Rust, and despite being lightweight, it still offers strong security.

> [!IMPORTANT]
> This project does not create complex formal documentation (or technical specifications) for each cryptographic function like in `entlib-native`. Instead, the API signatures and usage of the functions are primarily described in Rust documentation comments, and a summary of this will be posted as a `README.md` in the module (or crate) where the functionality is provided.

You can always refer to the [INTRODUCTION_EN.md](INTRODUCTION_EN.md) file for a detailed project introduction!

# AI Agent Scope

I try to organize the specifications detailing the various cryptographic functions and technical workings of this crypto module 'to the best of my knowledge,' but for making the written results 'easy to understand' (generating Mermaid diagrams, simplifying context and descriptive style for improved readability of specifications, English translation, etc.) and for adding Docstrings and general comments, I use the Sonnet 4.6 model of [Claude Code](http://claude.ai/). Additionally, I use the Opus 4.7 model of Claude Code to check what functional aspects are needed for integration with the [ISO-LIGHT-K0](https://github.com/Quant-Off/iso-light-k0) microkernel and to receive feedback (review) on missing or improvable parts. It is also used to review NIST FIPS 140-2 or 3 PDF documents to verify that cryptographic algorithms comply with international standards. Cross-verification through domain experts is never omitted.

Since this project is (arguably) a solo development, agents are applied only to the above 'documentation work' as a baseline. It is certain that Claude Code modifies only `.md` files in this project, and access to **sensitive functionality** (such as the implementation of cryptographic algorithms) is absolutely restricted. I am not a vibe coder, but merely a somewhat old-fashioned developer. This statement was not written to mock those who use AI for various automation tasks, development, or security audits. It simply defines the scope of AI use for human purposes in line with the advancing AI era.

Each cryptographic algorithm crate, `README.md` (this file!), and `INTRODUCTION.md` have been written with direct and rigorous human review since the development of the Rust native version of [EntanglementLib](https://github.com/Quant-Off/entanglementlib). It is clearly noted that the English translations of the normal (introductory) documents (`*_EN.md`) were written by the Sonnet 4.6 model of Claude Code.

# License

This project is under the [MIT LICENSE](LICENSE).