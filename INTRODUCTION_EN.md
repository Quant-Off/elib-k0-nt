# What Is This Project?

[![Language](https://img.shields.io/badge/INTRODUCTION-Korean_Ver-blue?style=for-the-badge)](INTRODUCTION.md)

> [!TIP]
> In the project name ELIB-K0-NT, "ELIB" is a shorthand for the [entlib-native](https://github.com/Quant-Off/entlib-native) project. It is unrelated to that project.

This project (ELIB-K0-NT) was created **for the purpose of providing cryptographic algorithm functionality** on the [K0 (ISO-LIGHT-K0) microkernel](https://github.com/Quant-Off/iso-light-k0). In short, K0 is an ultra-lightweight `no_std` security microkernel targeting high-security edge gateways, aviation and defense embedded terminals, and air-gapped data diodes. Accordingly, it differs from a general cryptographic module in the following ways.

- Communication via a Ring 3 (user space) daemon and IPC (Inter-Process Communication) (an architectural constraint unique to the K0 kernel)
- Lightweightness in a `no_std` environment

# This Project Is Not a New Cryptographic Algorithm

This fact matters. ELIB-K0-NT does not propose a new cryptographic scheme. AES, ChaCha20, SHA-2/3, BLAKE, Ed25519/448, X25519/448, ML-KEM, and ML-DSA are all **implementations** that follow existing standards (FIPS, RFC, etc.), and what this project does is re-implement them under the constraints of the K0 kernel (`no_std`, Ring 3 isolation, IPC-based communication). The safety of the algorithms themselves rests on already-verified standards, and the only thing this project technically needs to have newly verified is the **correctness of the algorithm implementations and their resistance to side-channel attacks**.

This distinction matters because what we're asking of reviewers is not "is this new approach secure?" but "does this standard implementation have a problem?" The former is cryptographic research; the latter is software engineering. What this project needs is the latter.

# Development Approach and Current Verification Status

Much of this project was written using AI agents. The specific scope of use and the prompts are recorded in [AI_SCOPE.md](AI_SCOPE.md). The mere fact that AI was used is neither a guarantee of code quality nor evidence of a defect. It does mean, however, that **there are still many parts that have not yet undergone human cryptographic verification**, and this document aims to state that gap explicitly rather than hide it.

What has and has not been confirmed so far is as follows (for per-module detail, please refer to each crate's README.md).

| Verification Item                                                | Status                                  |
|------------------------------------------------------------------|-----------------------------------------|
| Passing standard test vectors (NIST/KCMVP KAT, RFC test vectors) | In progress, only some modules complete |
| Constant-time verification (tool-based, e.g. dudect)             | Not complete                            |
| Side-channel resistance (timing, cache, etc.)                    | Not reviewed                            |
| Memory zeroization (zeroize) correctness                         | Not reviewed                            |
| Fuzzing coverage                                                 | Not complete                            |
| Misuse-resistance of the API design                              | Not reviewed                            |

This table is updated as progress is made. Items marked "Not reviewed" are also the basis for why this project does not currently claim to be production-ready.

# Design Direction

This project separates the CLI binary out into a Ring 3 user-space service of the microkernel and communicates with it over IPC. This is because it aligns with the microkernel's core philosophy of privilege separation and fault isolation. Even if a panic or defect occurs in the cryptographic module, Ring 0 (kernel space; EL1) is unaffected, which is a requirement for satisfying the "physical/logical isolation of security functions" demanded at high security levels.

## Why We Avoid Shared Dependencies Between Crates

In a typical Rust project, it would be a reasonable design to extract trait implementations that repeat across several crates into a shared crate like `core` or `base`. This project, however, does not do that. Under the **Zero-Trust principle** specified in [CONTRIBUTING.md](CONTRIBUTING.md), each crate's `[dependencies]` only permits workspace path references, because this prioritizes limiting the propagation of faults/defects to a per-crate scope over convenience. If a shared core has a defect, every crate that uses it is affected at once, whereas in independent implementations a defect stays confined to that one crate. It's a trade-off we accept, paying the cost of code duplication in exchange.

There are exceptions to this principle. For example, Ed448's context signatures require SHAKE128/256 as defined in FIPS 202, so the `ed448` crate uses the `sha3` crate as an internal workspace dependency. This is a dependency the specification requires, not one adopted for convenience.

## Why We Use Our Own Implementation Instead of RustCrypto's zeroize

`zeroize` is a validated, stable crate provided by [RustCrypto](https://github.com/RustCrypto/). The reason ELIB-K0-NT does not use it is not a quality issue but the Zero-Trust principle described above (no external crate dependencies). This does, however, also mean that this project's zeroization logic has not undergone as much verification as RustCrypto's. The `zeroize` implementation is one of the spots in this project most prone to the subtlest bugs (compiler-optimization removal of zeroization code, correctness of `volatile` writes, etc.), and it's also why it's marked "Not reviewed" in the [verification status table above](#development-approach-and-current-verification-status). **We especially welcome review of this part.**

# Included Features

- [Constant-time Ops](./constant-time)
- Hash([SHA2](./sha2), [SHA3](./sha3), [SHAKE](./sha3), [BLAKE2](./blake))
- RNG([Hash DRBG](./rng))
- Digital Signature([Ed25519](./ed25519), [Ed448](./ed448))
- Key Establishment Protocol([X25519](./x25519), [X448](./x448))
- AEAD, BlockCipher([AES](./aes), [ChaCha20-Poly1305](./chacha20))
- Post-Quantum Cryptography([ML-DSA](./mldsa), [ML-KEM](./mlkem))
