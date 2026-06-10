# AES-256 Module

A `no_std` pure-Rust crate implementing FIPS 197 AES-256 block cipher and NIST SP 800-38A (CBC, CTR) and SP 800-38D (GCM) modes of operation with zero external dependencies. This document covers the feature specification, security design rationale, and the issues found — along with their resolutions — during the 1.1.0 cross-validation pass.

---

## Implemented Primitives

| Type          | Standard     | Description                                                            |
|---------------|--------------|------------------------------------------------------------------------|
| `AES256`      | FIPS 197     | Single 16-byte block encrypt/decrypt. Round keys protected by `Secret` |
| `AES256CBC`   | SP 800-38A   | CBC mode without padding. Input must be a multiple of 16 bytes         |
| `AES256CTR`   | SP 800-38A   | Counter mode. Initialised with a 96-bit nonce or a 128-bit IV          |
| `AES256GCM`   | SP 800-38D   | Authenticated encryption (AEAD). 96-bit nonce, 128-bit tag             |
| `GHash`       | SP 800-38D   | GF(2^128) authentication hash. Used internally by GCM                  |

Size constants are fixed: `KEY_SIZE = 32`, `BLOCK_SIZE = 16`, `CBC_IV_SIZE = 16`, `CTR_NONCE_SIZE = 12`, `CTR_IV_SIZE = 16`, `GCM_NONCE_SIZE = 12`, `GCM_TAG_SIZE = 16`. Key, nonce, and tag lengths are enforced by type (`&[u8; N]`), so length errors are caught at compile time.

Design decisions:

- Only AES-256 (256-bit keys) is supported. AES-128/192 are intentionally omitted.
- GCM nonce is fixed at 96 bits. GHASH-based J0 derivation for non-96-bit IVs is not implemented (the SP 800-38D recommended configuration).
- GCM tag length is fixed at 128 bits. Truncated tags are not supported, preserving the upper bound on forgery probability.
- GCM decryption does not write a single byte of plaintext to the output buffer until tag verification succeeds (SP 800-38D Section 7.2).
- CTR `apply` initialises the counter block as `nonce || 0x00000001` and increments only the low 32 bits via `inc32`.
- Input length limits are enforced in code. GCM plaintext: 2^39-256 bits; GCM AAD: 2^64-1 bits; CTR input: 2^32 blocks. Violations trigger `assert!` and abort immediately (`panic = "abort"`).
- All buffers are fixed-size stack arrays. `alloc` is not used.

## Constant-Time Guarantees

### 1. Bitsliced Boyar-Peralta S-box

The S-box is computed as a circuit of approximately 115 AND/XOR/NOT gates without any lookup table. A 16-byte block is converted into `[u32; 8]` bit-planes and processed in a single circuit pass for SubBytes. There are no secret-dependent branches and no secret-dependent memory accesses, entirely eliminating cache and TLB timing side channels. The circuit originates from Boyar & Peralta (2010) and is identical to the one used in BearSSL `aes_ct.c`.

The inverse S-box reuses the forward circuit via the identity `InvSBox(y) = Affine^-1(SBox(Affine^-1(y)))`. The key schedule's `sub_word` uses the same circuit, so key expansion is also table-free.

### 2. GHASH Carryless Multiplication

GF(2^128) multiplication is computed using only integer arithmetic, with no lookup tables. Following the BearSSL `bmul32` approach, each operand is split into four parts using 4-bit-spaced masks; partial products within each lane accumulate without carry, extracting the GF(2)[X] polynomial product exactly from ordinary integer multiplication. 64-bit and 128-bit products are composed via Karatsuba 3-multiplication, and reduction modulo `p(X) = X^128 + X^7 + X^2 + X + 1` is performed with shift-and-XOR, branch-free.

This path assumes that integer multiplication on AMD64 and AArch64 runs in data-independent time. The `compile_error!` gate in the `constant-time` crate rejects builds for any other architecture, so this assumption holds across all supported targets. DIT (AArch64) and DOITM (x86) hardening is a shared open item with the `constant-time` crate.

### 3. Tag Comparison

GCM tag verification accumulates byte-level equality using `CtEqOps` from the `constant-time` crate (inline-assembly `cmp + sete` / `cset`), with no branches or early exits during the comparison. Branching occurs only on the public accept/reject result after all 16 bytes have been compared.

### 4. Remaining Operations

- `xtime` / `gf_mul` (MixColumns): uses `(b & 1).wrapping_neg()` masks and multiply-mask forms instead of secret-dependent branches
- ShiftRows and state transposition: fixed-index accesses only
- `inc32`: branchless via u16 carry arithmetic

## Secret Zeroization

Following the "one request, one datum, immediate erase" principle, the following guarantees are provided:

| Secret                                           | Protection                                                |
|--------------------------------------------------|-----------------------------------------------------------|
| Round keys (60 words)                            | `Secret<[u32; 60]>`, volatile-erased on Drop             |
| GCM hash subkey `h`                              | Zeroized in `Drop`                                        |
| `GHash` fields `h_n` and `state_n`               | Zeroized in `Drop`; `reset` also goes through `zeroize`  |
| Keystream blocks (CTR, GCM)                      | Zeroized immediately after each block is consumed         |
| AES state matrix and bitslice planes             | Zeroized before the function returns                      |
| Key schedule `temp`                              | Zeroized after each iteration                             |
| `E(J0)`, GHASH output, `expected_tag`            | Zeroized immediately after tag synthesis and comparison   |

Drop-time erasure is regression-tested by `test_aes256_zeroize_on_drop`, `test_aes256gcm_zeroize_on_drop`, and `test_ghash_zeroize_on_drop`, which inspect memory directly after deallocation using `MaybeUninit`.

Remaining limitation: sub-word temporaries residing in registers (MixColumns column variables, bytes in `sub_word`, u128 intermediates in GHASH) are not zeroized. Register and spill residue (CWE-316) is a known limitation of the zeroize model; correctness relies on the short lifetime of these values being overwritten by immediately following operations.

## Standards Compliance Verification

Key expansion matches the FIPS 197 KeyExpansion specification (Nk=8, Nr=14, 7 RCON values, the additional SubWord branch at `i mod 8 = 4`). GCM has been verified to match the specification for `J0 = IV || 0^31 || 1`, GCTR start counter `inc32(J0)`, and GHASH input ordering `A || pad || C || pad || [len(A)]64 || [len(C)]64`.

| Test                             | Source                                             |
|----------------------------------|----------------------------------------------------|
| `fips197_c3_test_vector`         | FIPS 197 Appendix C.3 (AES-256)                    |
| `cbc_nist_f_2_5`                 | SP 800-38A F.2.5 (CBC-AES256)                      |
| `ctr_nist_f_5_5`                 | SP 800-38A F.5.5 (CTR-AES256)                      |
| `gcm_test_case_14/15/16`         | GCM spec (McGrew & Viega) AES-256 test cases       |
| `ghash_basic` / `gf128_mul_test` | GCM spec GHASH intermediate values                  |
| `sub_byte_matches_reference`     | Exhaustive comparison of all 256 FIPS 197 S-box entries |
| `bmul32_against_bitserial`       | Carryless multiply vs. bit-serial reference        |
| `gcm_auth_failure`               | Tampered tag rejected, no plaintext released       |

`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test -p aes --target <host-triple>`, and `cargo build -p aes --target x86_64-unknown-none` (bare-metal) all pass with no warnings.

## Caller Contract

This crate is stateless; the following invariants must be upheld by the caller:

1. **Nonce/IV uniqueness:** Reusing a GCM or CTR nonce under the same key immediately collapses confidentiality and, for GCM, integrity. The library holds no state across calls and cannot detect reuse.
2. **CBC IV unpredictability:** Per SP 800-38A Appendix C, CBC IVs must be unpredictable.
3. **Key separation across modes:** The CTR `apply` first counter block (`nonce || 1`) has the same format as GCM's J0. Using the same key and nonce in both CTR and GCM makes the first CTR keystream block identical to the GCM tag mask `E_K(J0)`, enabling tag forgery and plaintext recovery. One key must be used with exactly one mode.
4. **No raw ECB composition:** `AES256::encrypt` is a single-block primitive. Concatenating multiple blocks without a mode is forbidden.
5. **CBC provides no integrity:** Nor does it provide padding. Use GCM when integrity is required.

---

## Issues Found and Resolved

Issues discovered during the cross-validation pass and their resolutions.

### Keystream and Intermediate State Zeroization Missing (Resolved)

Round keys (`Secret`) were protected, but CTR/GCM keystream blocks, CBC plaintext XOR blocks, the AES state matrix, bitslice planes, the key schedule `temp`, `E(J0)`, and GHASH output were left on the stack. This violated the "one request, one datum, immediate erase" charter.

#### Resolution

`zeroize()` was added immediately after each secret intermediate value is used. The table in the zeroization section above reflects the state after this fix.

### Buffer Validation Silently Dropped in Release Builds (Resolved)

Length checks in CBC and CTR were `debug_assert!`, causing them to be eliminated in release builds. When the output buffer is smaller than the input, CBC's `zip` terminates early, silently truncating output (CWE-1284); non-multiple-of-16 input has its tail silently ignored. CTR and GCM would abort with an index panic, but without a meaningful diagnostic.

#### Resolution

Assertions were promoted to `assert!` to enforce them in release as well. Buffer size checks that were absent from `GCM encrypt`/`decrypt` were added. Violations abort immediately with a diagnostic message.

### GCM Tag Comparison Open to Compiler Reordering (Resolved)

The previous tag comparison used XOR accumulation (`diff |= tag[i] ^ expected[i]`). While branch-free at the source level, pure Rust arithmetic offers no language-level guarantee that the optimizer cannot reconstruct a branching pattern — the same issue discussed in the `constant-time` crate README regarding `black_box`. The project charter requires using the `constant-time` crate for all cryptographic comparisons.

#### Resolution

Replaced with byte-wise `CtEqOps` accumulation backed by inline assembly. The assembly is emitted as-is, eliminating the risk of compiler reordering.

### SP 800-38D and 38A Input Length Limits Not Enforced (Resolved)

Both GCM and CTR increment only the low 32 bits of the counter via `inc32`. Exceeding 2^32 blocks in a single call wraps the counter and reuses the keystream. In GCM, a wrap that reaches J0 leaks the tag mask and enables forgery. Additionally, the AAD bit-length computation in `len_block` (`aad_len * 8`) silently overflowed for inputs larger than 2^61 bytes. SP 800-38D Section 5.2.1.1 requires `len(P) <= 2^39-256` bits and `len(A) <= 2^64-1` bits, but neither limit was checked.

#### Resolution

`GCM_MAX_INPUT_LEN = 2^36 - 32` bytes (= 2^39-256 bits), `GCM_MAX_AAD_LEN = 2^61 - 1` bytes (= 2^64-8 bits), and `CTR_MAX_INPUT_LEN = 2^36` bytes (= 2^32 blocks) are now enforced at the entry of `encrypt`, `decrypt`, and `apply` via `assert!`. The GCM limit is the exact value at which the counter stops before wrapping back to J0. Inputs of 64 GiB scale are unreachable in a fixed stack-array environment, but encoding the standard's requirement in code turns it from an assumption into a guarantee.

### GHash::reset Using Plain Zero Assignment (Resolved)

`reset` used the plain assignment `self.state_n = 0`. This is the anti-pattern the project prohibits (DCE-eligible erasure). Although functionally harmless given that the field is overwritten before the next use, it broke consistency in the erasure path.

#### Resolution

Replaced with a `zeroize()` call, unifying the erasure path through the volatile-write guarantee.

### Open Items

- Register-resident temporaries (see the remaining limitation in the zeroization section above)
- AArch64 DIT and x86 DOITM hardening — shared open item with the `constant-time` crate
- `inc32` is defined identically in both `ctr.rs` and `gcm.rs`; consolidation is deferred to a follow-up cleanup
- TODO annotations in `sbox.rs` and `ghash.rs` module comments to be cleaned up
