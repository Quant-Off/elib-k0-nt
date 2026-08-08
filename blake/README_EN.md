# BLAKE Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)

A crate implementing the RFC 7693 BLAKE2b hash and MAC, the BLAKE3 hash / keyed-hash / XOF, and the RFC 9106 variable-length hash `H'` in pure `no_std` Rust with no external dependencies. This document describes the functional specification, the security design rationale, the standards-conformance basis, and the issues found with their mitigations.

---

## Implemented Features

| Algorithm     | Standard      | Output           | Block Size       | Internal Word | Rounds | Keyed Mode               |
|---------------|---------------|------------------|------------------|---------------|--------|--------------------------|
| `Blake2b`     | RFC 7693      | 1..=64 bytes     | 128 bytes        | `u64`         | 12     | `new_keyed` (1..=64 B key) |
| `Blake3`      | BLAKE3 spec   | 32 bytes / XOF   | 64 B (1024 B chunk) | `u32`      | 7      | `new_keyed` (32 B key)   |
| `blake2b_long` | RFC 9106 §3.3 | 1..=1024 bytes   | (BLAKE2b core)   | `u64`         | 12     | none                     |

The public API consists of the `Blake2b` and `Blake3` types, the free function `blake2b_long`, the `SecureBuffer` container, and the `ct_eq_slice` comparison helper.

- `Blake2b`: a streaming interface of `new(hash_len)` / `new_keyed(hash_len, key)` -> `update(&[u8])` (any number of times) -> `finalize(self) -> Result<SecureBuffer, HashError>`. `finalize` consumes `self`, so instance reuse is blocked at the type level. The keyed constructor processes the key as a single 128-byte zero-padded first block, providing a BLAKE2b MAC.
- `Blake3`: a streaming interface of `new()` / `new_keyed(&[u8; 32])` -> `update(&[u8])` -> `finalize(self)` (32-byte output) or `finalize_xof(self, out_len)` (arbitrary length up to `MAX_OUTPUT_LEN`). The internal Merkle tree is driven by a chaining-value stack of fixed depth 54.
- `blake2b_long`: the RFC 9106 `H'` construction used for Argon2id block initialization and final-tag generation. For `out_len <= 64` it is a single `BLAKE2b(LE32(out_len) || input)`; for larger outputs it chains 64-byte digests and emits 32-byte prefixes plus a final `(out_len - 32r)`-byte block.
- `SecureBuffer`: a fixed-capacity (`MAX_OUTPUT_LEN` = 1024 bytes) stack-backed buffer whose payload is held inside a `Secret`, with a separate length field. It is the only digest return type; raw `[u8; N]` is never returned.
- `ct_eq_slice` / `CtEqOps for SecureBuffer`: constant-time equality for comparing MAC tags and digests against attacker-controlled values.

Design decisions are as follows.

- All buffers are fixed-size stack arrays. No `alloc` is used, and the crate is `#![cfg_attr(not(test), no_std)]`.
- Digests are returned only as the self-zeroizing `SecureBuffer`, never as a raw array. Returning a raw array is an anti-pattern the project forbids.
- `Blake2b::finalize` and `Blake3::finalize` / `finalize_xof` consume `self`, so the entire hashing state is volatile-erased the moment the output is produced.
- The BLAKE2b and BLAKE3 cores both use a lazy-compression strategy: the last full block (BLAKE2b) and the last full chunk (BLAKE3) are held back so that the final-block flag (`f0`) and the `CHUNK_END` / `ROOT` flags can be applied correctly. A buffered block is compressed only once it is known that more input follows.
- BLAKE2b runs in sequential mode only (fanout 1, depth 1, no salt and no personalization), which is exactly the scope standardized by RFC 7693. BLAKE3 implements the hash and keyed-hash modes; the context-based derive-key mode is not provided.

## Security Processing Rationale

Both hashes may be applied to secret messages (BLAKE2b MAC keys, BLAKE3 keyed-hash material), so execution time must not depend on secret values. Data independence is guaranteed at the following levels.

### 1. The Compression Functions Use Only Data-Independent Operations

The BLAKE2b mixing function `g` and the BLAKE3 mixing function `g3` are composed solely of `wrapping_add`, `^`, and `rotate_right` (rotations 32/24/16/63 for BLAKE2b, 16/12/8/7 for BLAKE3). There are no secret-dependent branches and no secret-dependent memory accesses. The round permutations `SIGMA` (BLAKE2b) and `MSG_PERMUTATION` (BLAKE3) are indexed only by the round number, which is public, so they never form a secret-indexed table lookup. Cache and TLB timing side channels are therefore eliminated at the source.

### 2. Message Length Is Public

In both standards the message length is public information. The length-driven control flow in `update` and `finalize` (buffer fill, `.min()`, block and chunk counting, the chaining-value-stack `popcount` merge) depends only on the input length, never on the input bytes. The 128-bit BLAKE2b byte counter is advanced with a branchless carry (`overflowing_add` -> `wrapping_add(carry as u64)`).

### 3. Constant-Time Tag and Digest Comparison

`ct_eq_slice` and the `CtEqOps` implementation for `SecureBuffer` compare two byte regions in constant time, delegating each byte comparison to the inline-assembly primitives of the `constant-time` crate. The guarantee assumes that the two lengths are public, which holds for MAC tags, digests, and keys whose lengths are standard parameters. On a length mismatch the result is masked to `Choice(0)` after comparing the shorter prefix, so no branch outcome is leaked to the caller. Because the crate depends on `constant-time`, the restriction that builds are permitted only on x86_64 and aarch64 — which have verified constant-time implementations — applies transitively.

## Secret Zeroization (zeroize)

Following the transaction-scoped full-erasure principle, the following are guaranteed.

| Secret                                                | Protection                                                   |
|-------------------------------------------------------|--------------------------------------------------------------|
| BLAKE2b chaining value `h` (`[u64; 8]`)               | `Secret`, volatile erase on drop + `Zeroize`                 |
| BLAKE2b counter `t` (`[u64; 2]`)                      | `Secret`, volatile erase on drop                             |
| BLAKE2b / BLAKE3 input buffer                          | `SecureBuffer` / `Secret`, `zeroize` immediately after each block compression |
| BLAKE2b work vector `v` (`[u64; 16]`)                 | `Secret`, drop-erased at end of `compress`                   |
| BLAKE2b loaded block `m` (`[u64; 16]`)                | `Secret`, drop-erased (explicit `drop`)                      |
| BLAKE3 key words (`[u32; 8]`)                         | `Secret`, wrapped at construction with no plaintext copy left |
| BLAKE3 chaining-value stack (`[[u32; 8]; 54]`)        | `Secret`, volatile erase on drop                             |
| BLAKE3 chunk chaining value / block words / new CV    | `Secret`, drop-erased                                        |
| BLAKE3 compression state, `m`, permuted words         | `Secret`, drop-erased per iteration / at scope end           |
| BLAKE3 parent and merged CVs (`Output`, `parent_cv`)  | `Secret`, drop-erased at scope end                           |
| Output serialization temporary (`word.to_le_bytes()`) | explicit `zeroize` after each word in `finalize` / `root_output_bytes` |
| Whole hashing state on finalize                       | `finalize` consumes `self`, so `Drop` volatile-erases every field |

`Secret<T>::drop` writes the full byte extent with `ptr::write_volatile` and seals it with compiler and memory barriers, independent of whether `T: Zeroize`; this covers every `Secret`-wrapped intermediate listed above. `Blake2b` and `Blake3` additionally implement `Zeroize` + `Drop`, clearing the non-secret length and flag fields with volatile writes as well.

Residual limitation: the per-round working values inside `g` / `g3`, and the register copies produced by `to_le_bytes` / `from_le_bytes`, reside briefly in registers and are not explicit erasure targets. Register and spill residue (CWE-316) is a known limitation of the zeroize model and relies on the short lifetime before subsequent operations overwrite them.

## Standards-Conformance Basis

| Element                                                  | Reference                  |
|----------------------------------------------------------|----------------------------|
| BLAKE2b constants (IV, `SIGMA`), parameter block, keyed init | RFC 7693 §2             |
| BLAKE2b mixing function `G` and compression `F` (12 rounds, rot 32/24/16/63) | RFC 7693 §3.2 |
| BLAKE2b worked example and `"abc"` test vector           | RFC 7693 Appendix A        |
| Variable-length hash `H'`                                | RFC 9106 §3.3              |
| BLAKE3 IV, message permutation, domain flags, Merkle tree | BLAKE3 specification      |

Unlike crates that are only verified indirectly, this crate ships its own known-answer tests (KATs) for every mode.

- BLAKE2b: the RFC 7693 empty-input and `"abc"` vectors; the official `blake2-kat` keyed vectors for the 64-byte key `00..3f` (empty input and single-byte input); and a reference-derived multi-block keyed vector that crosses the key-block boundary.
- `blake2b_long`: byte-exact vectors derived from an RFC 9106 `H'` reference implementation for `out_len` 80 (`r = 1`) and 128 (`r = 2`).
- BLAKE3: the official unkeyed empty / `"hello"` vectors, and the official keyed vectors at lengths 0, 1, 64, 1024, 1025, and 8192, which exercise the single-block, block-boundary, single-chunk, multi-chunk, and three-level Merkle-merge paths respectively.
- `tests/threat_inputs.rs`: boundary-length and asymmetric-length regression coverage, plus streaming-equivalence checks confirming that split `update` calls produce byte-identical output to a single call.

`cargo fmt -p blake -- --check`, `cargo clippy -p blake --all-targets --all-features -- -D warnings`, `cargo build -p blake --target x86_64-unknown-none`, and `cargo build -p blake --target aarch64-unknown-none` all pass with no warnings.

## Caller Contract

Because this crate is stateless, the caller must guarantee or be aware of the following.

1. **Single-use finalize:** `finalize` / `finalize_xof` consume `self`. Re-hashing the same input requires a new instance.
2. **Use the digest immediately:** `SecureBuffer` is erased on drop. To retain the result of `as_slice()` on the caller side, it must be copied right away; if the digest is a secret (a MAC tag, for example), the caller must also erase the copy.
3. **Constant-time comparison is for public-length data:** use `ct_eq_slice` / `CtEqOps::eq` to compare tags and digests; the constant-time guarantee assumes the compared lengths are public.
4. **Length preconditions:** `Blake2b::new` and `new_keyed` assert a 1..=64 output length (and a 1..=64 key length), and panic (under `panic = "abort"`) on violation; the caller must pass valid lengths. `blake2b_long` returns `Err(HashError)` for `out_len == 0` or `out_len > MAX_OUTPUT_LEN`. The BLAKE3 key length is fixed to 32 bytes by the `&[u8; 32]` type.

---

## Issues Found and Mitigations

This section describes issues identified during verification and their resolutions.

### Plaintext Key-Word Residue in BLAKE3 `new_keyed` (Resolved)

`new_keyed` converted the 32-byte key into a `[u32; 8]` plaintext local before wrapping it in `Secret`. Because `[u32; 8]` is `Copy`, `Secret::new` copied the array rather than moving it, leaving a non-erased plaintext copy of the key (trivially reversible to the key bytes) on the function's stack frame after it returned. The struct-level docstring also overclaimed that the key was never exposed on the stack.

#### Resolution

The helper `words_from_le_bytes_32` now returns `Secret<[u32; 8]>`, mirroring the existing `words_from_le_bytes_64` pattern, so the converted key is wrapped at the point of creation and no named plaintext copy persists. The docstrings were corrected to describe the actual behavior.

### Residue of Unused Output Bytes in Digest Serialization (Resolved)

When the requested output length is not a multiple of the word size, the last `word.to_le_bytes()` produced a full 8-byte (BLAKE2b) or 4-byte (BLAKE3) array of which only the leading bytes were written to the output. The trailing bytes — derived from the final internal chaining state and not part of the output — remained on the stack.

#### Resolution

The serialization temporary is now `zeroize()`d after each word in `Blake2b::finalize` and `Output::root_output_bytes`, limiting its residence time in memory.

### Untested Keyed BLAKE2b and Unverified `blake2b_long` Output (Resolved)

`Blake2b::new_keyed` (the MAC path) had no test coverage at all, and the sole `blake2b_long` test asserted only the output length, not its value — a silent-error risk for a function that feeds Argon2id.

#### Resolution

Official and reference-derived keyed BLAKE2b KATs (empty, single-byte, multi-block) and byte-exact RFC 9106 `H'` value KATs were added; all pass, confirming the keyed counter logic and the `H'` chaining are byte-correct.

### Documentation Corrections (Resolved)

The `Blake2b::new` / `new_keyed` constructors documented their panic conditions under `# Errors` despite returning `Self` rather than `Result`; these were changed to `# Panics`. The `blake2b_long` docstring cited "RFC 9106 §3.2" for `H'`, which is defined in §3.3.

### Remaining Work

- Register and spill residue (CWE-316) of the `g` / `g3` working values and the `to_le_bytes` / `from_le_bytes` intermediates is a known limitation shared with the other algorithm crates.
- `Blake2b::new` / `new_keyed` enforce their length preconditions with `assert!` (panic = abort) rather than a `Result`; this is the documented enforcement boundary for a total constructor, but a fallible constructor would avoid a caller-triggered abort.
- BLAKE2b salt and personalization, and the BLAKE3 derive-key mode, are intentionally out of scope.
- aarch64 DIT and x86 DOITM hardening is a joint task with the `constant-time` crate.
