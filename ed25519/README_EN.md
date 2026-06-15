# Ed25519 Signature Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)

Ed25519 is a digital signature scheme whose security rests on two things: the math of the edwards25519 curve, and the guarantee that no secret ever influences the timing or memory-access pattern of the code that handles it. This document gives a technical account of both — the protocol the crate implements, and the assembly-level reasons the implementation does not leak the signing key.

---

## Cryptographic Surface

The public API is intentionally small. Every entry point is stateless: one request, one datum, immediate erase.

- `sign(message: &[u8], &SecretKey) -> Signature`
- `verify(message: &[u8], &Signature, &PublicKey) -> Result<(), Ed25519Error>`
- `SecretKey` — wraps `Secret<[u8; 32]>` (the 32-byte seed); zeroized on drop.
- `PublicKey` — 32-byte compressed curve point.
- `Signature` — 64 bytes, `R (32) || s (32)`.
- `Keypair` — `{ secret, public }` convenience bundle.

Internally the crate is split into three arithmetic layers, each in its own module:

| Module      | Domain                                  | Representation                              |
|-------------|-----------------------------------------|---------------------------------------------|
| `field`     | `Fp`, `p = 2^255 - 19`                  | 5 × 51-bit limbs (radix-2^51), little-endian |
| `scalar`    | `Z/L`, `L = 2^252 + 27742317...648493`  | 32 bytes; 12 × 21-bit signed limbs for reduction |
| `point`     | twisted Edwards `-x^2 + y^2 = 1 + d x^2 y^2` | extended coordinates `(X, Y, Z, T)`, `x = X/Z`, `y = Y/Z`, `xy = T/Z` |

There are no external dependencies (`sha2` and `zeroize` are internal workspace crates), no allocator, and no `std` outside tests. The crate builds for the default bare-metal target `x86_64-unknown-none`.

## Standard Conformance

The implementation follows **RFC 8032** PureEdDSA (Ed25519, SHA-512). It is validated byte-for-byte against the RFC 8032 Section 7.1 known-answer vectors (TEST 1 through 3): for each, the derived public key and the produced signature match the published bytes exactly, and verification of the published signature succeeds.

Two canonicality checks bring the crate in line with the stricter reading of RFC 8032 and FIPS 186-5 (the "cofactored vs cofactorless" and "non-canonical encoding" cases catalogued in *Taming the many EdDSAs*):

- **Scalar range.** Verification rejects any `s >= L`. The check subtracts `L` from `s` byte by byte while tracking a borrow, with no early return, so it is itself data-independent.
- **Point encoding.** Point decoding rejects any `y >= p`. A `y` field element is re-serialized to its canonical form and compared with the input; a mismatch means the encoding was non-canonical and is refused. This closes a signature-malleability avenue on both `R` and the public key `A`.

Verification uses the cofactorless group equation `[s]B = R + [k]A`, comparing curve points directly in extended coordinates.

## The Signing Protocol

A signature is a transaction over secret material. The flow below is exactly what `sign` and `verify` execute; the right-hand annotations mark which quantities are secret.

### Key expansion (RFC 8032 5.1.5)

```text
h          = SHA512(seed)                         seed, h  : secret
a_bytes    = h[0..32]                             clamp:
               a_bytes[0]  &= 248                 (clear low 3 bits)
               a_bytes[31] &= 127                 (clear top bit)
               a_bytes[31] |= 64                  (set bit 254)
a          = a_bytes as scalar                    a        : secret  (signing scalar)
prefix     = h[32..64]                            prefix   : secret  (nonce key)
A          = [a]B                                 A        : public  (public key)
```

Clamping forces the scalar into the prime-order subgroup and fixes its top bit, which is what makes the fixed-length ladder in the next step safe to run in constant time.

### Sign (RFC 8032 5.1.6)

```text
1.  r = SHA512(prefix || M)  mod L               r : secret nonce
2.  R = [r]B                                      R : public
3.  k = SHA512(R || A || M)  mod L                k : public (derived from public inputs)
4.  s = (r + k·a)  mod L                          s : public, but binds the secret a
5.  signature = R || s
```

Step 4 is a single fused multiply-add modulo `L` (`sc_muladd(k, a, r)`). Because `r` is a deterministic hash of `prefix` and the message, signing needs no random number generator — there is no nonce-reuse failure mode.

### Verify (RFC 8032 5.1.7)

```text
1.  decode R           (reject non-canonical y)            -> MalformedSignature
2.  parse  s, require s < L                                -> NonCanonicalScalar
3.  decode A           (reject non-canonical / off-curve)  -> InvalidPublicKey
4.  k = SHA512(R || A || M) mod L
5.  accept iff  [s]B == R + [k]A                           else InvalidSignature
```

Verification touches only public data, so it is written for correctness and strictness rather than for timing-independence.

## Constant-Time Guarantee Rationale

Only two secrets ever flow through value-dependent arithmetic: the signing scalar `a` and the per-message nonce `r`. Both are consumed in exactly two places — the scalar multiplications `[a]B` and `[r]B`, and the multiply-add `r + k·a`. The constant-time argument therefore reduces to showing that *scalar multiplication and scalar arithmetic contain no secret-dependent branch, no secret-dependent memory access, and no variable-latency instruction.* The guarantee holds at four levels.

### 1. No secret-dependent branch — branchless scalar multiplication

The scalar multiply is a fixed 256-iteration double-and-add. Every iteration performs one doubling **and** one addition unconditionally, then chooses between the "added" and "not-added" accumulator with a branchless masked select, never with an `if`:

```rust
for i in (0..256).rev() {
    result = result.double_internal();
    let bit = (s[i / 8] >> (i % 8)) & 1;      // i, i/8 are public loop indices
    let sum = result.add_internal(self);       // addition always computed
    result = EdwardsPoint::conditional_select(&result, &sum, bit);
}
```

`conditional_select` builds a full-width mask from the choice bit and merges the two inputs limb by limb — `a ^ (mask & (a ^ b))`, using only `neg`, `and`, `xor`. There is no comparison of, or jump on, any secret. Compiled for the host (aarch64, release), the five-limb field select lowers to straight-line bitwise logic and returns with no conditional branch:

```text
<_probe_fe_cselect>:
    mov   x9,  #0x0
    mov   w10, w2
    sub   x9,  x9, w2, uxtw      ; x9  =  mask  = -(choice)
    ldp   x11, x12, [x1]         ; b limbs
    and   x11, x11, x9           ; b & mask
    sub   x10, x10, #0x1         ; x10 = ~mask  =  choice - 1
    ldp   x13, x14, [x0]         ; a limbs
    and   x13, x13, x10          ; a & ~mask
    orr   x11, x11, x13          ; (b & mask) | (a & ~mask)
    ...                          ; same pattern for the remaining limbs
    ret
```

The instruction class is the same on both supported architectures:

| Step           | x86_64        | aarch64        |
|----------------|---------------|----------------|
| Mask from bit  | `neg`         | `sub`/`neg`    |
| Merge          | `and` + `or`  | `and` + `orr`  |

No `cmov`/`csel` is even required, and crucially no `jcc`/`b.cc` ever reads the bit. The earlier implementation used `if bit == 1 { add }`, which emitted exactly such a secret-dependent conditional branch — observable through branch prediction and instruction-cache timing, and sufficient to recover the scalar one bit at a time. That branch has been removed; the disassembly above is the regression check.

### 2. No secret-dependent memory access

The multiply is variable-base and table-free: there is no precomputed multiple of the base point indexed by secret bits, so no load address depends on a secret and no cache or TLB timing can vary with the key. The only indices in the hot loop — `i`, `i / 8` — are the public loop counter. Any bounds check the compiler inserts is therefore a check on a public index, not on secret data.

### 3. Data-independent field and scalar arithmetic

- **Inversion** uses Fermat's little theorem, `a^(-1) = a^(p-2)`, evaluated by a fixed addition chain of squarings and multiplications. The sequence of operations is identical for every input. The crate never uses the extended Euclidean algorithm, whose iteration count depends on operand magnitude.
- **Square root** (point decompression) is likewise a fixed exponentiation chain `a^((p+3)/8)` followed by a candidate check — and it only ever runs on public encodings.
- **Multiplication** accumulates `64 × 64 -> 128`-bit partial products (`u128`). On x86_64 and aarch64 the integer multiply latency is independent of operand values; these are the only two architectures the workspace supports, so the assumption is sound by construction rather than by hope. There is no `div` anywhere in the field or scalar code.
- **Reduction** — both the `Fp` carry chain and the `mod L` reduction (`sc_reduce`) — is straight-line code with a compile-time-fixed number of carry passes. No loop trip count depends on a value.

### 4. Erasure is delegated to a barrier-backed primitive

Where an optimizer barrier is genuinely required — wiping a secret so the compiler cannot elide the store — this crate does not rely on portable Rust. It defers to the `zeroize` crate, whose per-architecture `barrier/{x86_64,aarch64}.rs` issue real memory/compiler fences and volatile writes in inline assembly. Constant-time *selection* is achieved with arithmetic masking (Levels 1-3); constant-time *erasure* is achieved with those barriers (below). The two concerns use the tool appropriate to each.

## Secret Lifecycle and Zeroization

The daemon's core invariant is that a secret never outlives the transaction that used it. The crate enforces this structurally:

- `SecretKey` holds the seed in `Secret<[u8; 32]>`; its `Drop` performs a volatile, barrier-fenced wipe.
- `expand` keeps both hash halves in `Secret` containers; the clamped scalar lives in `ExpandedSecretKey`, whose `Drop` explicitly zeroizes the scalar (a `Copy` type that `Drop` alone would not clear), while the nonce prefix is wiped by its own `Secret`.
- `sign` explicitly zeroizes the nonce `r`, the challenge `k`, the output scalar `s`, and the intermediate point `R` before returning; the 64-byte wide-hash buffers are `Secret`-wrapped and wiped automatically on scope exit.
- The scalar reduction routines (`sc_muladd`, `from_bytes_mod_order_wide`) zeroize their internal limb arrays — the decomposed forms of the secret scalars — before they return, so no secret survives on the stack past the call.

Together these make signing stateless in the strongest sense: after `sign` returns, the only secret-derived bytes still in memory are the seed inside the caller's `SecretKey`, and the signature itself, which is public by design.

---

## Verification Summary

| Property                          | How it is checked                                              |
|-----------------------------------|---------------------------------------------------------------|
| RFC 8032 correctness              | Byte-exact KAT against Section 7.1 TEST 1-3                    |
| Non-canonical point rejected      | Decode of `y = p` is refused (`MalformedSignature`)           |
| Non-canonical scalar rejected     | `s = L` is refused (`NonCanonicalScalar`)                     |
| Branchless secret scalar multiply | `llvm-objdump` of the select shows no conditional branch      |
| Lint gate                         | `cargo clippy --all-targets --all-features -- -D warnings` clean |
| Bare-metal posture                | Builds for `x86_64-unknown-none`, `no_std`, no `alloc`        |

As remaining hardening, explicitly enabling the aarch64 DIT bit and the x86 DOITM mode — which pin data-independent timing at the ISA level for the masked-select instructions — is left for future work, mirroring the same open item tracked in the `constant-time` crate.
