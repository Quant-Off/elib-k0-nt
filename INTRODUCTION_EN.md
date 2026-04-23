# Design Goals and Philosophy

In this project, we aim for a design that decouples the enhanced [Entlib-Native](https://github.com/Quant-Off/entlib-native) CLI binary into a Microkernel Ring 3 user space service, communicating via IPC. This aligns with the core philosophy of microkernels: privilege separation and fault isolation. Such a design ensures that even if a panic or fault occurs within the cryptographic module, the Ring 0 kernel space / EL1 remains protected. Furthermore, it satisfies the "physical/logical isolation of security functions," a fundamental requirement for high-security standards.

We strictly adhere to the principles of Zero-Trust and Air-Gapped Ready. From a development perspective, we believe that "convenience" must sometimes be sacrificed for "security." When implementing cryptographic algorithms, one might provide convenient tools through a middle ground (e.g., core dependencies named `core` or `base`). Implementing highly redundant `traits` by pulling them from such a core crate is a typical example of this. While this approach is excellent and often recommended, we view it as a somewhat aggressive programming style when considering compliance requirements or the critical principles each individual unit crate must uphold. We simply refer to this as "convenience." We choose to discard this convenience, designing each crate to be implemented independently.

What if a "dependency" is absolutely necessary? For instance, using the SHAKE hash algorithm to implement context signatures in the `Ed448` signature algorithm. Such usage is common for compliance. To discard "convenience," this implementation must be established through "closed and defensive programming." In other words, to implement the Ed448 digital signature algorithm, the implementation of `SHAKE128` and `SHAKE256` according to [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) becomes mandatory within that scope. The same applies to `zeroize`, which is used systematically throughout this project. While [RustCrypto](https://github.com/RustCrypto) provides an excellent crate for zeroing memory, we do not use it as-is. Instead, we implement it purely in "our own way." (RustCrypto is an amazing Rust security team!!!!)

What our team wants to emphasize is "our own way." Before designing, we do not ask, "Does this feature already exist in the market?" This seemingly foolish philosophy serves as the backbone of our code design. From an information security perspective, this can be quite useful. The most significant advantage is that issues or data flows within a completely independent unit crate's codebase do not leak externally.

Nevertheless, if you still think our design approach looks truly stupid... we have no particular rebuttal. We simply respect individual code design philosophies—even if it's "1000% Spaghetti-Code."

# Features Included

This binary is equipped with memory-zeroing capabilities that fully cover multiple architectural platforms. Within almost all cryptographic (or information security) functions, logic and volatile operations are included to immediately erase sensitive data as soon as it leaves its scope. This functionality is provided by our internal `zeroize` implementation.

Based on robust zeroing logic, we provide the following cryptographic features:

- [Constant-time Ops](./constant-time)
- Hash([SHA2](./sha2), [SHA3](./sha3), [SHAKE](./sha3), [BLAKE2](./blake))
- RNG([Hash DRBG](./rng))
- Digital Signature([Ed25519](./ed25519), [Ed448](./ed448))
- Key Establishment Protocol([X25519](./x25519), [X448](./x448))
- AEAD, BlockCipher([AES](./aes), [ChaCha20-Poly1305](./chacha20))
- Post-Quantum Cryptography([ML-DSA](./mldsa), [ML-KEM](./mlkem))