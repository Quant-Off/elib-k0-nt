# SHA-3 Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)

A crate implementing the FIPS 202 SHA3-224 / SHA3-256 / SHA3-384 / SHA3-512 hash functions and the SHAKE128 / SHAKE256 extendable-output functions (XOFs) in pure `no_std` Rust with no external dependencies. All variants share a single Keccak-f[1600] sponge as their core. This document describes the functional specification, the security design rationale, the standards-conformance basis, and the issues found with their mitigations.

---

## Implemented Features

All six variants are built as a sponge construction over the width-$b = 1600$ Keccak permutation, following the relation $r + c = 1600$ (rate $r$, capacity $c$).

| Type       | Standard        | Output            | rate $r$            | capacity $c$ | Domain Suffix |
|------------|-----------------|-------------------|---------------------|--------------|---------------|
| `SHA3_224` | FIPS 202 §6.1   | 28 bytes (224 bit) | 1152 bit (144 byte) | 448 bit      | `0x06`        |
| `SHA3_256` | FIPS 202 §6.1   | 32 bytes (256 bit) | 1088 bit (136 byte) | 512 bit      | `0x06`        |
| `SHA3_384` | FIPS 202 §6.1   | 48 bytes (384 bit) | 832 bit (104 byte)  | 768 bit      | `0x06`        |
| `SHA3_512` | FIPS 202 §6.1   | 64 bytes (512 bit) | 576 bit (72 byte)   | 1024 bit     | `0x06`        |
| `SHAKE128` | FIPS 202 §6.2   | variable (XOF)    | 1344 bit (168 byte) | 256 bit      | `0x1f`        |
| `SHAKE256` | FIPS 202 §6.2   | variable (XOF)    | 1088 bit (136 byte) | 512 bit      | `0x1f`        |

The capacity of the fixed-output variants is twice the output length ($c = 2d$), so collision resistance is $d/2$ bits and preimage resistance is $d$ bits. The security strength of the XOFs is $\min(d/2,\ c/2)$ bits, up to 128 bits for SHAKE128 and up to 256 bits for SHAKE256.

The public API consists of two traits and the `Digest` type.

- `SHA3` trait: a streaming interface of `new()` -> `update(&[u8])` (any number of times) -> `finalize(self) -> Digest`. `finalize` consumes `self`, so instance reuse is blocked at the type level.
- `XOF` trait: `new()` -> `update(&[u8])` -> `finalize_into(self, &mut [u8])`. The output length is given by the caller's buffer size, and output beyond the rate is squeezed to arbitrary length by re-applying the permutation.
- `Digest`: a return container holding a fixed 64-byte buffer and a length field. It exposes a slice of the relevant length via `as_bytes()` and zeroizes itself on drop.

Design decisions are as follows.

- The six variants share a single internal `KeccakState` (the sponge state $[u64; 25]$, the input buffer, the rate, and the domain suffix). The only differences among the variants are three values: rate, output length, and domain suffix.
- The input buffer is a fixed-size `[u8; 168]` sized to the largest rate, SHAKE128's 168 bytes. No `alloc` is used, and the crate is unconditionally `#![no_std]`.
- Digests are returned only as the self-zeroizing `Digest`, never as a raw `[u8; N]`. Returning a raw array is an anti-pattern the project forbids.
- The fixed-output variants always fit their output within a single rate block ($d \le r$ holds for all four), so they complete in a single squeeze. The multi-block squeeze path is needed only for the XOFs.

## Security Processing Rationale

The Keccak permutation is applied to secret state (ML-DSA / ML-KEM seeds, the SHAKE256 nonce of Ed448, etc.), so execution time must not depend on input values. This crate guarantees data independence in both the permutation and the sponge buffering.

### 1. The Keccak-f[1600] Permutation Uses Only Data-Independent Operations

The five step mappings of the 24-round permutation ($n_r = 12 + 2\ell$, $\ell = 6$) are all compositions of rotation, shift, and logical operations, with no secret-dependent branches and no secret-dependent memory accesses (lookup tables).

- $\theta$: builds the column parity $C[x] = \bigoplus_{y} a[x,y]$ and XORs $D[x] = C[x{-}1] \oplus \mathrm{ROT}(C[x{+}1],\ 1)$ into each lane.
- $\rho$: rotates each lane by a **fixed constant** offset (`RHO_OFFSETS`). Because the rotation amount is a compile-time constant rather than data, there is no variable-shift side channel.
- $\pi$: relocates lanes by **fixed indices** (`PI_INDICES`). There is no secret-dependent address computation.
- $\chi$: the only nonlinear step, $a'[x] = a[x] \oplus (\lnot\, a[x{+}1] \wedge a[x{+}2])$ (indices mod 5), which uses only NOT/AND/XOR without any table lookup like the AES S-box.
- $\iota$: XORs the round constant $RC_i$ into lane 0. The constants are accessed only at fixed indices.

In other words, Keccak is an **inherently constant-time** permutation that uses no multiplication, division, conditional branch, secret-dependent lookup, or variable shift whatsoever. Because the round constants and rotation offsets are fixed tables independent of the message, cache and TLB timing side channels are eliminated at the source.

### 2. Constant-Time Sponge Buffering

The message length is public information in SHA-3, but length comparisons are performed with constant-time operations for implementation consistency (the same pattern as the sha2 crate) and to keep the block count predictable.

- The chunk-length computation in `update` builds `is_ge` with `CtGreeter::gt` and `CtEqOps::eq`, then selects $\min(\text{remain},\ \text{fill})$ branch-free via `usize::select`.
- The XOF `squeeze_into` likewise decides the per-word extraction amount branch-free as $\min(\text{remain},\ 8)$ via `usize::select`.
- For byte-aligned input, the pad10\*1 padding always fits in exactly one additional sponge call, so the extra-block branch does not depend on the secret.

These select / eq / gt operations are delegated to the inline-assembly primitives of the `constant-time` crate. The restriction that builds are permitted only on x86_64 and aarch64 — which have verified constant-time implementations — is shared with the `constant-time` README.

## Secret Zeroization (zeroize)

Following the transaction-scoped full-erasure principle, the following are guaranteed.

| Secret                                          | Protection                                            |
|-------------------------------------------------|-------------------------------------------------------|
| Sponge state (`[u64; 25]`)                      | `Secret`, volatile erase on drop + `Zeroize`          |
| Input buffer (`[u8; 168]`)                      | `Secret`, volatile erase on drop + `Zeroize`          |
| Permutation intermediates `tmp`·`c`·`d`         | explicit `zeroize` at end of `keccak_f1600`           |
| Absorbed message word `word`                    | explicit `zeroize` at end of `absorb_block`           |
| Padding block `block`                           | `Secret`, drop-erased at end of `pad` scope           |
| Squeeze word copy `word_bytes`                  | explicit `zeroize` at end of the fixed / XOF squeeze  |
| Digest stack copy `bytes` in `finalize_fixed`   | `volatile_write(0)` + `atomic_compiler_fence` + `memory_barrier` |
| Output bytes of `Digest`                        | `Secret<[u8; 64]>`, erased on drop + `Zeroize`        |

The `Zeroize` of `KeccakState` volatile-erases its `Secret` fields — the sponge state and the input buffer — and is invoked automatically when `self` is dropped. `pad` wraps a separate stack block in `Secret` so that the domain suffix and padding bits do not linger in memory.

Residual limitation: the registers and stack spills where each lane value transiently resides within a single permutation round are not explicit erasure targets. What is erased are the stack arrays such as `tmp`·`c`·`d`; the register residue (CWE-316) that the next round immediately overwrites is a known limitation of the zeroize model.

## Standards-Conformance Basis

| Element                                  | FIPS 202 Section          |
|------------------------------------------|---------------------------|
| Keccak-f[1600] 24-round permutation      | §3.4                      |
| $\theta$·$\rho$·$\pi$·$\chi$·$\iota$ step mappings | §3.2.1 ~ §3.2.5  |
| $\rho$ rotation-offset table             | §3.2.2 (Table 2)          |
| Round constants $RC_i$ (24 of them)      | §3.2.5 (Algorithm 5)      |
| Sponge construction                      | §4                        |
| pad10\*1 multi-rate padding              | §5.1                      |
| `KECCAK[c]` definition                   | §5.2                      |
| SHA3-224/256/384/512 (suffix `01`)       | §6.1                      |
| SHAKE128/256 (suffix `1111`)             | §6.2                      |
| Domain-suffix byte encoding (`0x06`·`0x1f`) | §B.1 (bit/byte conversion) |

The domain-suffix byte is the value obtained by combining the FIPS 202 domain-separation bit string with the first `1` bit of pad10\*1 in little-endian bit order. SHA-3 adds the padding start bit to the `01` suffix to get `0x06`, and SHAKE adds it to the `1111` suffix to get `0x1f`; neither pattern overlaps in bits with `0x80` (the end-of-padding bit) — the high bit of both $\texttt{0x06}\ |\ \texttt{0x1f}$ is 0.

KAT verification is performed with the following vectors, all of which pass.

- **FIPS 202 official empty-message vectors:** verify the domain suffix and padding of all six variants.
- **FIPS 202 1600-bit message (`0xA3` × 200) vectors:** verify the multi-block absorption path.
- **Rate-boundary padding:** for each fixed-output variant, verify the three boundaries $L = r{-}1$ (domain suffix merged with `0x80`), $L = r$ (a full padding block), and $L = r{+}1$.
- **XOF multi-block squeeze:** verify the re-permutation path for SHAKE128/256 output beyond the rate (over 168 bytes), partial-word output, and prefix consistency ($\text{out}[..k]$ matching the prefix of a longer output).
- **Incremental-input equivalence:** verify that splitting into 1·7·64·135·136·137·299-byte chunks produces the same result as a single batched input (including crossing the buffer boundary).
- **Erasure on drop:** verify that the state and buffer of `KeccakState` and the `Digest` bytes are erased to 0 after drop.

`cargo fmt -p sha3 -- --check`, `cargo clippy -p sha3 --all-targets --all-features -- -D warnings`, `cargo build -p sha3 --target x86_64-unknown-none`, and `cargo build -p sha3 --target aarch64-unknown-none` all pass with no warnings.

## Caller Contract

Because this crate is stateless, the caller must guarantee or be aware of the following.

1. **Single-use finalize:** `finalize` and `finalize_into` consume `self`. Re-hashing the same input requires a new instance.
2. **Use the digest immediately:** `Digest` is erased on drop. To retain the result of `as_bytes()` on the caller side, it must be copied right away; if the digest is secret, the caller must also erase the copy.
3. **XOF output buffer:** `finalize_into` outputs exactly as many bytes as the length of the slice the caller passes. An output length sufficient for security (recommended $\ge 32$ bytes for SHAKE128 and $\ge 64$ bytes for SHAKE256) is the caller's responsibility.

---

## Issues Found and Mitigations

This section describes issues identified during verification and their resolutions (commit `e073d17`).

### Missing Erasure of Keccak-f Permutation Intermediates (Resolved)

The column-parity arrays `c`·`d` and the $\rho$/$\pi$ temporary array `tmp` of the permutation — despite being values derived from the secret state — were declared anew on each pass inside the round loop and lingered on the stack after the function returned. This violates the "one request, one datum, immediate erasure" charter.

#### Resolution

`c`·`d`·`tmp` were hoisted out of the round loop so that the 24 rounds reuse the same buffers, and all three arrays are explicitly `zeroize()`d immediately after the permutation ends. The table in the zeroize section above reflects the post-fix state.

### absorb_block Self-Borrow and Stack Residue (Resolved)

In the structure where the absorption function took `&mut self`, `update` could not borrow the input buffer (`self.buffer`) and the state (`self.state`) at the same time, so it had to make a copy of the buffer, and that copy was left behind unerased. The absorption loop also did not erase the `word` local that held the message word.

#### Resolution

The signature of `absorb_block` was changed to two disjoint borrows, `state: &mut [u64; 25]` and `block: &[u8]`, so that `update` passes `&mut self.state` and `&self.buffer[..rate]` directly as borrows of different fields. The buffer copy is gone, and the last message word `word` is also `zeroize()`d right after absorption.

### Residue of the finalize Digest Stack Copy (Resolved)

`finalize_fixed` writes the squeeze result into the stack array `bytes: [u8; 64]` and then builds the `Digest` with `Secret::new(bytes)`; because `[u8; 64]: Copy`, `Secret::new` **copies** the value, leaving the stack original holding the secret digest.

#### Resolution

Immediately after constructing the `Secret`, each byte of the stack original `bytes` is overwritten with `volatile_write(0)` and sealed with `atomic_compiler_fence` + `memory_barrier`, so the optimizer cannot remove the erasure. This pattern is shared with the digest assembly of the sha2 crate.

### Remaining Work

- Register and spill residue of lane values inside a single permutation round (the residual limitation in the zeroize section above)
- aarch64 DIT and x86 DOITM hardening is a joint task with the `constant-time` crate
- Arbitrary bit-length (non-byte-aligned) input is unsupported — the current implementation handles only byte-aligned messages
