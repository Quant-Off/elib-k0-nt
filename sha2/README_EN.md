# SHA-2 Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)

A crate implementing the FIPS 180-4 SHA-224 / SHA-256 / SHA-384 / SHA-512 hash functions in pure `no_std` Rust with no external dependencies. This document describes the functional specification, the security design rationale, the standards-conformance basis, and the issues found with their mitigations.

---

## Implemented Features

| Type     | Standard          | Output   | Block Size | Internal Word | Rounds | State Struct  |
|----------|-------------------|----------|------------|---------------|--------|---------------|
| `SHA224` | FIPS 180-4 §5.3.2 | 28 bytes | 512 bits   | `u32`         | 64     | `SHA256State` |
| `SHA256` | FIPS 180-4 §5.3.3 | 32 bytes | 512 bits   | `u32`         | 64     | `SHA256State` |
| `SHA384` | FIPS 180-4 §5.3.5 | 48 bytes | 1024 bits  | `u64`         | 80     | `SHA512State` |
| `SHA512` | FIPS 180-4 §5.3.4 | 64 bytes | 1024 bits  | `u64`         | 80     | `SHA512State` |

The public API consists of the `SHA2` trait and the `Digest` type.

- `SHA2` trait: a streaming interface of `new()` -> `update(&[u8])` (any number of times) -> `finalize(self) -> Digest`. `finalize` consumes `self`, so instance reuse is blocked at the type level.
- `Digest`: a return container holding a fixed 64-byte buffer and a length field. It exposes a slice of the relevant length via `as_bytes()` and zeroizes itself on drop.

Design decisions are as follows.

- SHA-224 shares its internal state struct and compression function with SHA-256, and SHA-384 with SHA-512. The only differences are the initial hash values and the output truncation length.
- Digests are returned only as the self-zeroizing `Digest`, never as a raw `[u8; N]`. Returning a raw array is an anti-pattern the project forbids.
- All buffers are fixed-size stack arrays. No `alloc` is used, and the crate is unconditionally `#![no_std]`.
- The message-length counter (`total_len`) is a bit-count `u64`. The SHA-256 family maps it directly onto the 64-bit length field (FIPS 180-4 §5.1.1); the SHA-512 family's 128-bit length field (§5.1.2) always keeps the upper 64 bits zero and fills only the lower 64 bits. The effective input limit is therefore $2^{64}-1$ bits (about 2 EiB) for both families, unreachable in a fixed-stack environment.

## Security Processing Rationale

SHA-2 may be applied to secret messages (HMAC keys, Ed25519 nonces, etc.), so execution time must not depend on input values. This crate guarantees data independence in both the compression function and the padding path.

### 1. The Compression Function Uses Only Data-Independent Operations

The message schedule and round function are composed solely of `rotate_right`, `wrapping_add`, `^`, `&`, and `!`. $\mathrm{Ch}$, $\mathrm{Maj}$, $\Sigma_0$, $\Sigma_1$, $\sigma_0$, and $\sigma_1$ are all compositions of rotation, shift, and logical operations, with no secret-dependent branches and no secret-dependent memory accesses (lookup tables). The round constant `K` is accessed only at fixed indices, so cache and TLB timing side channels are eliminated at the source.

### 2. Constant-Time Buffering and Padding

The message length is public information in SHA-2, but length comparisons are performed with constant-time operations for implementation consistency and to keep the block count predictable.

- The chunk-length computation in `update` builds `is_ge` with `CtGreeter::gt` and `CtEqOps::eq`, then selects $\min(\text{remain}, \text{fill})$ branch-free via `usize::select`.
- The padding in `finalize` decides whether the length field fits in the current block using a `Choice` (`buffer_len > 56` for the SHA-256 family, `buffer_len > 112` for the SHA-512 family). The length-field injection is done byte by byte with `u8::select`, the second block is processed unconditionally regardless of necessity, and the final hash state is chosen with `u32::select` / `u64::select`.
- As a result, `finalize` always compresses exactly two blocks regardless of `needs_extra`. Whether the message length affects padding never leaks through the compression count.

These select / eq / gt operations are delegated to the inline-assembly primitives of the `constant-time` crate. The restriction that builds are permitted only on x86_64 and aarch64 — which have verified constant-time implementations — is shared with the `constant-time` README.

## Secret Zeroization (zeroize)

Following the transaction-scoped full-erasure principle, the following are guaranteed.

| Secret                                          | Protection                                            |
|-------------------------------------------------|-------------------------------------------------------|
| Hash state (`[u32; 8]` / `[u64; 8]`)            | `Secret`, volatile erase on drop + `Zeroize`          |
| Input buffer (`[u8; 64]` / `[u8; 128]`)         | `Secret`, `zeroize` immediately after block processing |
| Message schedule `w` (`[u32; 64]` / `[u64; 80]`) | `Secret`, drop-erased at end of `process_block`       |
| Working variables `a`..`h`                      | explicit `zeroize` at end of `process_block`          |
| Round temporaries `s0`·`s1`·`ch`·`maj`·`temp1`·`temp2` | declared outside the loop, then explicit `zeroize` |
| Block copy passed to `process_block`            | `Secret`, drop-erased at end of scope                 |
| `block1`·`block2`·`state_b1` in `finalize`      | `Secret`, drop-erased at end of scope                 |
| `total_len` (bit counter)                       | `volatile_write(0)` + `compiler_fence` in `Drop`      |
| Output bytes of `Digest`                        | `Secret<[u8; 64]>`, erased on drop + `Zeroize`        |
| Unused digest words (SHA-224 `[28..32]`, SHA-384 `[48..64]`) | `zeroize` during digest assembly         |

The `Drop` of the state structs (`SHA256State`·`SHA512State`) clears the non-`Secret` field `total_len` to 0 with `volatile_write` and seals it with `compiler_fence(SeqCst)`; the `Secret` fields are volatile-erased in their own drops.

Residual limitation: the $\sigma$ temporaries inside the message-schedule loops (`for i in 16..64` / `16..80`) and the intermediate values of `from_be_bytes` and rotations reside briefly in registers and are not explicit erasure targets. Register and spill residue (CWE-316) is a known limitation of the zeroize model and relies on the short lifetime before subsequent operations overwrite them.

## Standards-Conformance Basis

| Element                            | FIPS 180-4 Section                                        |
|------------------------------------|----------------------------------------------------------|
| Initial hash values                | §5.3.2(224) / §5.3.3(256) / §5.3.4(512) / §5.3.5(384)    |
| Round constants `K`                | §4.2.2(SHA-256, 64) / §4.2.3(SHA-512, 80)                |
| $\mathrm{Ch}$·$\mathrm{Maj}$·$\Sigma$·$\sigma$ | §4.1.2(SHA-256) / §4.1.3(SHA-512)            |
| Padding and length field           | §5.1.1(512-bit block, 64-bit length) / §5.1.2(1024-bit block, 128-bit length) |
| Message schedule and compression   | §6.2.2(SHA-256) / §6.4.2(SHA-512)                        |

This crate ships no KAT tests of its own, but it is verified indirectly through two paths.

- `ed25519` uses `sha2::SHA512` for signing and verification and is validated against the RFC 8032 test vectors.
- The Hash_DRBG in `rng` uses all of `SHA224`/`SHA256`/`SHA384`/`SHA512` and is validated by the NIST SP 800-90A procedures.

`cargo fmt -p sha2 -- --check`, `cargo clippy -p sha2 --all-targets --all-features -- -D warnings`, `cargo build -p sha2 --target x86_64-unknown-none`, and `cargo build -p sha2 --target aarch64-unknown-none` all pass with no warnings.

## Caller Contract

Because this crate is stateless, the caller must guarantee or be aware of the following.

1. **Single-use finalize:** `finalize` consumes `self`. Re-hashing the same input requires a new instance.
2. **Use the digest immediately:** `Digest` is erased on drop. To retain the result of `as_bytes()` on the caller side, it must be copied right away; if the digest is secret, the caller must also erase the copy.
3. **Length limit:** the input must be under $2^{64}-1$ bits (a design limit, effectively unreachable). Beyond that the bit counter wraps and the padding length becomes inconsistent.

---

## Issues Found and Mitigations

This section describes issues identified during verification and their resolutions.

### Missing Erasure of Compression Working and Temporary Variables (Resolved)

The hash state, buffer, and message schedule were protected with `Secret`, but the compression function's working variables `a`..`h` and round temporaries `s0`·`s1`·`ch`·`maj`·`temp1`·`temp2` — despite being values derived from the secret state — lingered on the stack after the function returned. This violates the "one request, one datum, immediate erasure" charter.

#### Resolution

The round temporaries were hoisted out of the loop and explicitly `zeroize()`d together with the working variables after compression. The table in the zeroize section above reflects the post-fix state.

### Residue of Unused Digest Words in SHA-224 and SHA-384 (Resolved)

Digest assembly always serializes eight words into the 64-byte buffer, but SHA-224 does not include the bytes after the seventh word (`[28..32]`), and SHA-384 does not include those after the sixth word (`[48..64]`). These regions are not exposed via `as_bytes()`, yet values derived from the secret state remained in memory.

#### Resolution

On the `is_224` / `is_384` paths, the unused word regions are `zeroize()`d before they are read, limiting their residence time in memory.

### Remaining Work

- Residue of register-resident intermediates such as the $\sigma$ temporaries inside the message-schedule loop (the residual limitation in the zeroize section above)
- The upper 64 bits of the SHA-512 family's 128-bit length field are unsupported (an effective $2^{64}-1$-bit limit)
- No direct KAT inside the crate (currently only indirect verification via `ed25519` and `rng`)
- aarch64 DIT and x86 DOITM hardening is a joint task with the `constant-time` crate
