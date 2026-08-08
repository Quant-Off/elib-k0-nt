# ML-DSA Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)

`mldsa` is a pure Rust implementation of the Module Lattice-based Digital Signature Algorithm (ML-DSA) as specified in [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). This crate supports three parameter sets (ML-DSA-44/65/87) and defends against side-channel attacks through secret key memory protection, hedged signing, and constant-time field arithmetic. The implementation scope is pure ML-DSA; the pre-hash variant (HashML-DSA) and the external-mu interface are not provided.

## Security Threat Model

Classical signature algorithms such as RSA and ECDSA are broken in polynomial time by a quantum computer running Shor's algorithm. ML-DSA grounds its security in the computational hardness of the LWE (Learning With Errors) problem and the SIS (Short Integer Solution) problem over module lattices, both of which require exponential time even under known quantum algorithms.

The implementation-level attack surface consists of three areas.

1. Secret key memory exposure
   - Secret components such as `s1`, `s2`, `t0`, and `K` (signing seed) may leak into swap files or core dumps. This is mitigated by automatic zeroization on Drop via the `Secret<T>` wrapper and by explicit `zeroize()` calls (see the "Sensitive Data Zeroization" section below).
2. Timing attacks during signing
   - Branches that depend on secret components can expose the signing key. Finite-field operations (`Fq::add`, `Fq::sub`, `Fq::mul`, `power2round`, etc.) are implemented using constant-time select operations from the [`constant-time`](../constant-time) crate.
3. Nonce reuse
   - If the masking vector `y` is reused or exposed, the secret key can be recovered from the relation $z = y + c s_1$. Hedged signing mode (`rnd <- RNG`) also guards against the reduced fault-attack resistance of the deterministic mode.

## Parameter Sets

Three parameter sets defined in NIST FIPS 204 Section 4 are supported.

| Parameter Set | NIST Security Category  |  pk size |  sk size |  sig size | λ (collision strength) |
|---------------|:-----------------------:|--------:|--------:|--------:|:---------------------:|
| ML-DSA-44     | 2 (AES-128 equivalent) | 1312 B  | 2560 B  | 2420 B  |  128-bit               |
| ML-DSA-65     | 3 (AES-192 equivalent) | 1952 B  | 4032 B  | 3309 B  |  192-bit               |
| ML-DSA-87     | 5 (AES-256 equivalent) | 2592 B  | 4896 B  | 4627 B  |  256-bit               |

Each parameter set varies the matrix dimensions $(k, l)$, secret coefficient range $\eta$, challenge polynomial weight $\tau$, masking range $\gamma_1$, decomposition range $\gamma_2$, and maximum hint weight $\omega$. Monomorphization via compile-time const generics eliminates all runtime overhead.

---

## Algorithm Implementation

All operations are performed over $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$, $q = 8380417$, and polynomial multiplication is carried out in the NTT (Number-Theoretic Transform) domain. The module structure follows the algorithm roles defined in FIPS 204.

| Module        | FIPS 204 Correspondence                                      | Responsibility                                         |
|---------------|--------------------------------------------------------------|--------------------------------------------------------|
| `keys.rs`     | Algorithm 1/6 (KeyGen), Algorithm 35 (Power2Round)           | Key generation, sk/pk encoding and decoding            |
| `sign.rs`     | Algorithm 2/7 (Sign), Algorithm 3/8 (Verify)                 | Signing/verification, Decompose/Hint operations        |
| `sample.rs`   | Algorithm 29~34 (Sampling)                                   | ExpandA, ExpandS, ExpandMask, SampleInBall             |
| `pack.rs`     | Algorithm 16~23 (Encoding)                                   | BitPack/BitUnpack, HintBitPack/Unpack                  |
| `ntt.rs`      | Algorithm 41/42 (NTT/NTT^-1)                                 | 256-point NTT, $\zeta$ table                           |
| `field.rs`    | -                                                            | $\mathbb{Z}_q$ constant-time arithmetic (Montgomery multiplication) |

### Key Generation (Algorithm 6, `ML-DSA.KeyGen_internal`)

A key pair is derived deterministically from a 32-byte seed $\xi$.

1. Expand to 128 bytes via $(\rho, \rho', K) \leftarrow \text{SHAKE256}(\xi \| k \| l)$. Including the domain-separation bytes $k, l$ prevents seed-reuse attacks across parameter sets.
2. Generate the public matrix $\hat{A} \in R_q^{k \times l}$ from $\rho$ via SHAKE128 rejection sampling (`RejNTTPoly`). The matrix is sampled directly in the NTT domain, eliminating transform overhead.
3. Generate secret vectors $s_1 \in R_q^l$ and $s_2 \in R_q^k$ from $\rho'$ via SHAKE256 rejection sampling (`RejBoundedPoly`, coefficient range $[-\eta, \eta]$).
4. Compute $t = \text{NTT}^{-1}(\hat{A} \circ \text{NTT}(s_1)) + s_2$ and decompose with `Power2Round` ($d = 13$) into the high bits $t_1$ (public) and low bits $t_0$ (secret).
5. The public key is $(\rho, t_1)$ and the secret key is $(\rho, K, tr, s_1, s_2, t_0)$, where $tr = \text{SHAKE256}(pk)$.

### Signing (Algorithm 7, `ML-DSA.Sign_internal`)

A rejection-sampling loop with Fiat-Shamir with Aborts structure.

1. Derive the message representative $\mu = \text{SHAKE256}(tr \| M')$ and masking seed $\rho'' = \text{SHAKE256}(K \| rnd \| \mu)$. When `rnd` is RNG output the mode is hedged; when it is zero the mode is deterministic.
2. Each loop iteration generates a masking vector $y \leftarrow \text{ExpandMask}(\rho'', \kappa)$, then computes $w = \text{NTT}^{-1}(\hat{A} \circ \text{NTT}(y))$ and $w_1 = \text{HighBits}(w)$.
3. From the challenge $\tilde{c} = \text{SHAKE256}(\mu \| w_1)$, `SampleInBall` constructs a sparse polynomial $c$ with $\tau$ coefficients in $\pm 1$, then computes $z = y + c s_1$.
4. If $\lVert z \rVert_\infty \ge \gamma_1 - \beta$ or $\lVert \text{LowBits}(w - c s_2) \rVert_\infty \ge \gamma_2 - \beta$, all secret intermediates of that iteration are zeroized and $\kappa$ is incremented for a retry. This rejection test is the key mechanism that removes secret key dependency from the signature distribution.
5. Construct the verifier correction hint $h = \text{MakeHint}(-c t_0,\ w - c s_2 + c t_0)$; if $\lVert c t_0 \rVert_\infty \ge \gamma_2$ or the hint count exceeds $\omega$, retry as well.
6. The signature is $(\tilde{c}, z, h)$. The loop is capped at 1,000 iterations (expected iteration counts per FIPS 204 Table 2 are 4.25/5.1/3.85) and returns `Error::SigningFailed` on overflow.

### Verification (Algorithm 8, `ML-DSA.Verify_internal`)

1. `sigDecode` validates the signature structure. In particular, `HintBitUnpack` (Algorithm 21) checks that hint indices are strictly increasing, the cumulative limit is respected, and trailing bytes are zero-padded, blocking signature malleability. Any format violation immediately fails verification.
2. Compute $w'_{approx} = \hat{A} \circ \text{NTT}(z) - \text{NTT}(c) \circ \text{NTT}(t_1 \cdot 2^d)$ and recover the signer's $w_1$ via $w'_1 = \text{UseHint}(h, \text{NTT}^{-1}(w'_{approx}))$.
3. After the $\lVert z \rVert_\infty < \gamma_1 - \beta$ check, recompute $\tilde{c}' = \text{SHAKE256}(\mu \| w'_1)$ and compare against $\tilde{c}$. The comparison uses a constant-time byte comparison (`ct_eq_bytes`) based on XOR accumulation.

The public API (`MLDSA44::sign/verify`, etc.) binds context (up to 255 bytes) in the format $M' = 0x00 \| |ctx| \| ctx \| M$ per FIPS 204 Algorithms 2/3. Fixed-length inputs (pk, sk, signature, seed) are accepted as fixed-size array references (`&[u8; N]`), so incorrect lengths are rejected by the type system at compile time.

---

## Low-Level (Assembly) Perspective

`mldsa` itself contains no inline assembly. Instead, secret-dependent operations are delegated to the verified low-level primitives in [`constant-time`](../constant-time) and [`zeroize`](../zeroize), inheriting their guarantees directly. Both crates reject architectures without verified inline assembly support via compile-time gates, so `mldsa`'s supported targets are likewise limited to x86_64 and aarch64.

### Machine-Level Behavior of Constant-Time Field Arithmetic

Conditional reduction in $\mathbb{Z}_q$ arithmetic is the sole point that can introduce branches dependent on secret values. This implementation handles all reductions via `i32::select` (internally `ct_sel32`), a primitive that uses only data-independent latency instructions.

| Operation                          | x86_64            | aarch64        |
|------------------------------------|-------------------|----------------|
| Conditional select (`Fq::add/sub` reduction) | `test` + `cmovnz` | `cmp` + `csel` |
| Sign determination (`is_negative_ct`)       | `sar` arithmetic shift | `asr` arithmetic shift |

- `Fq::add` unconditionally computes $a + b - q$, then selects one of the two candidates using the sign bit (`(v >> 31) & 1`) via `cmov`/`csel`. No conditional branch (`jcc`, `b.cc`) is emitted.
- `Fq::mul` is implemented with $R = 2^{32}$ Montgomery REDC. The 64-bit multiply instruction (x86_64 `imul`, aarch64 `mul`/`smulh`) has fixed latency independent of operand values on both targets. ISA-level guarantees (aarch64 DIT, x86 DOITM) remain a future hardening task, consistent with the `constant-time` crate.
- NTT butterfly memory access indices are derived only from public loop variables and precomputed $\zeta$ table indices, so no secret-dependent cache timing can arise.
- Serialization of secret coefficients (`BitPack`) uses `fq_to_signed_ct`, which performs sign conversion using only `wrapping_sub` and a sign-bit mask, keeping the packing path branch-free.

The norm check and accept/reject branch in the rejection sampling loop are derived from secret values, but rejected candidates are immediately zeroized and never exposed externally; the accept decision itself is public information (the point of signature output). This is the intended behavior of FIPS 204's Fiat-Shamir with Aborts design.

### Machine-Level Behavior of Zeroization

A plain assignment (`buf = [0; N]`) may be eliminated by the compiler as a dead store. `zeroize` performs all zeroization via `write_volatile` and forces the stores to survive and complete using architecture-specific barriers.

| Step               | x86_64                               | aarch64                              |
|--------------------|--------------------------------------|--------------------------------------|
| Volatile store     | `write_volatile` (non-eliminatable)  | `write_volatile` (non-eliminatable)  |
| Compiler barrier   | empty `asm!` + `compiler_fence(SeqCst)` | empty `asm!` + `compiler_fence(SeqCst)` |
| CPU memory barrier | `mfence`                             | `dsb sy`                             |

The survival of zero-stores and barrier instructions (e.g. `strb wzr` + `dsb sy` on aarch64) through LTO in release binaries is verified by a separate probe build in the zeroize crate.

---

## Sensitive Data Zeroization

All secret components in this crate are zeroized in two layers. Long-lived values are automatically zeroized on Drop by the `Secret<T>` RAII wrapper, and stack copies that escape the wrapper due to `Copy` semantics of `Poly`/`PolyVec` are immediately zeroized by explicit `zeroize()` calls.

| Secret Value                              | Location                | Zeroization Method                                    |
|-------------------------------------------|-------------------------|-------------------------------------------------------|
| $s_1, s_2, t_0$, $K$                     | `PrivateKey` fields     | Automatic `Secret<T>` Drop zeroization                |
| $\mu, \rho''$                             | Stack during signing    | Automatic `Secret<T>` Drop zeroization                |
| $\xi$ expansion buffer, $\rho'$, $K$ local copy | Stack during keygen | Explicit `zeroize()` before return                   |
| NTT-transformed $s_1$ copy, $t = A s_1 + s_2$ | Stack during keygen | Explicit `zeroize()` before return                   |
| $y, \hat{y}, w, c s_1, z, c s_2, r_0$   | Signing rejection loop  | Explicit `zeroize()` before each iteration ends, on all paths |
| $c t_0$, hint computation intermediates  | Signing rejection loop  | Explicit `zeroize()` before each iteration ends, on all paths |
| $\hat{s}_1, \hat{s}_2, \hat{t}_0$        | Signing function scope  | Explicit `zeroize()` on both success and failure paths |

The design principles are as follows.

- **Zeroize on every exit path of the rejection loop.** Both paths that `continue` on norm check failure and the path that returns after signature acceptance zeroize the iteration's secret intermediates. Rejected $y$ and $z$ pairs are the most sensitive values: a single exposed pair directly enables recovery of the secret key via $z - y = c s_1$.
- **Directly zeroize `Copy` residual copies.** `Secret::new(v)` protects only the copy held inside the wrapper; it does not zeroize the original stack slot. Keygen explicitly zeroizes originals (e.g. `s2pv`, `t0pv`, NTT-transformed `s1`) immediately after wrapping them in `Secret`.
- **Do not zeroize public values.** $\rho$, $t_1$, $tr$ (hash of the public key), $w_1$, and $\tilde{c}$ are public components and are not zeroization targets.

The verification path processes only public inputs (pk, signature, message) and therefore contains no secrets that require zeroization.

---

## KAT Verification

Self-consistency tests (sign-then-verify with the same implementation) cannot detect encoding bugs, because a non-standard serialization will still pass roundtrip as long as pack and unpack are mutual inverses. This crate therefore verifies byte-exact agreement against official external vectors.

| Verification Item              | Source                                                          | Result                                                      |
|--------------------------------|-----------------------------------------------------------------|-------------------------------------------------------------|
| keyGen (44/65/87)              | [NIST ACVP](https://github.com/usnistgov/ACVP-Server) FIPS204  | 75/75 (pk and sk byte-exact match)                          |
| verify valid signatures (44/65/87) | [Wycheproof](https://github.com/C2SP/wycheproof) testvectors_v1 | 226/226 accepted                                        |
| verify invalid signatures (44/65/87) | Wycheproof testvectors_v1                                 | 391/391 rejected (includes malleability, boundary, context tampering) |
| sigGen deterministic (44)      | Wycheproof testvectors_v1                                       | 73/73 (signature bytes exact match)                         |

The first ACVP keyGen vector for each parameter set resides as a regression test in `tests/mldsa_test.rs`.

## Bugs Found and Fixed

This section describes issues discovered and corrected during the KAT verification process (2026-06-10). Both bugs passed self-consistency tests while leaving the implementation in a non-conformant state -- they would not have been found without external vector verification.

### CoeffFromHalfByte eta=2 Path Misimplemented (Resolved)

The half-byte conversion in `RejBoundedPoly` (Algorithm 31) differed from FIPS 204 Algorithm 14. The original code accepted `z <= 2η` and returned `η - z` regardless of the η value, but the standard requires `2 - (b mod 5)` for η=2 when `b < 15`. Both the acceptance condition and the coefficient formula differed, causing the secret vectors $s_1$ and $s_2$ of ML-DSA-44/87 (η=2) to follow a distribution inconsistent with the standard. The η=4 path coincidentally matched both definitions, so only ML-DSA-65's public key agreed with the ACVP vectors -- this was the decisive clue for isolating the root cause.

#### Resolution

`coeff_from_half_byte::<const ETA: i32>` was replaced with a direct implementation of Algorithm 14. Because the rejection condition (for η=2: `b >= 15`) is applied before the mod-5 reduction, the output distribution is restored to uniform over $[-2, 2]$.

### BitPack Sign Convention Violation (Resolved)

`BitPack`/`BitUnpack` (Algorithm 16/18) must encode a coefficient $w$ in the range $[-a, b]$ as `b - w`, but the original implementation used `a + w`. Because pack and unpack were exact inverses of each other, self-roundtrip and self-verification tests all passed, but the serialization of $s_1$, $s_2$, $t_0$ (secret key) and $z$ (signature) was non-standard, causing a complete failure when exchanging keys or signatures with a conformant implementation. In practice, all 226 valid Wycheproof signatures were rejected and all 75 ACVP keyGen vectors mismatched.

#### Resolution

Encoding was corrected to `b - w` and decoding to `b - encoded`. The bit-width calculation (`bitlen(a + b)`) was unaffected, so signature and key lengths are unchanged. After the fix, all entries in the KAT table above passed. The rejection loop zeroization reinforcement and wrapping `K` seed in `Secret` were applied in the same patch.

---

## Error Types

All error variants are `Copy` with no allocation or string messages.

| Variant          | Condition                                                            |
|------------------|----------------------------------------------------------------------|
| `ContextTooLong` | Context string exceeds 255 bytes                                     |
| `InvalidLength`  | Combined message and context exceeds the internal buffer (1024 bytes) |
| `SigningFailed`  | Rejection sampling exceeded 1,000 iterations (probabilistically unreachable in practice) |
| `InternalError`  | Internal sampling failure such as XOF output exhaustion (unreachable on valid input) |

Verification failure is returned as `Ok(false)`, not an error. Malformed signatures (including hint malleability) and cryptographic mismatches are treated identically so that callers need not distinguish between them.

## Usage

```rust
use mldsa::MLDSA65;

// Key generation (xi is a 32-byte seed; must be generated by a cryptographic RNG)
let xi: [u8; 32] = /* RNG */;
let (pk, sk) = MLDSA65::keygen(&xi)?;

// Hedged signing (rnd should also be RNG output; use [0u8; 32] for deterministic signing)
let rnd: [u8; 32] = /* RNG */;
let ctx = b"";
let sig = MLDSA65::sign(&sk, b"message", ctx, &rnd)?;

// Verification
assert!(MLDSA65::verify(&pk, b"message", &sig, ctx)?);
```

The seeds `xi` and `rnd` can be generated using the workspace [`rng`](../rng) crate (NIST SP 800-90A Hash_DRBG). The caller is responsible for explicitly calling `zeroize()` on the `sk` byte array after use. The crate internally zeroizes all secret intermediates on a per-transaction basis but does not take responsibility for key copies held by the caller.
