# X25519 Key-Agreement Module

X25519 is an Elliptic-Curve Diffie-Hellman (ECDH) function whose security rests on two things: the math of the Curve25519 Montgomery curve, and the guarantee that no secret ever influences the timing or memory-access pattern of the code that handles it. This document gives a technical account of both — the protocol the crate implements, and the assembly-level reasons the implementation does not leak the private scalar.

---

## Cryptographic Surface

The public API is intentionally small. Every entry point is stateless: one request, one datum, immediate erase.

- `SecretKey::from_bytes([u8; 32]) -> SecretKey`
- `SecretKey::public_key(&self) -> PublicKey`
- `SecretKey::diffie_hellman(&self, &PublicKey) -> Result<SharedSecret, X25519Error>`
- `PublicKey::from_bytes([u8; 32]) -> PublicKey` — normalizes the high bit on construction.
- `generate_keypair<R: FnMut(&mut [u8])>(rng) -> (SecretKey, PublicKey)`
- `is_contributory(&SharedSecret) -> Choice`
- `SecretKey` / `SharedSecret` — each wraps `Secret<[u8; 32]>`; zeroized on drop.
- `PublicKey` — 32-byte little-endian u-coordinate.
- `X25519Error::LowOrderPoint` — returned when the agreement collapses to the all-zero secret.

X25519 operates entirely on the **u-coordinate** (the x-coordinate of the Montgomery form), so the crate needs only two arithmetic layers:

| Layer            | Domain                                     | Representation                                       |
|------------------|--------------------------------------------|-----------------------------------------------------|
| `field`          | `Fp`, `p = 2^255 - 19`                     | 5 × 51-bit limbs (radix-2^51), little-endian        |
| ladder (`lib.rs`)| Curve25519, `v^2 = u^3 + 486662 u^2 + u`   | projective `(X : Z)` per rung, `u = X/Z`; 32-byte scalar |

There are no external dependencies (`constant-time` and `zeroize` are internal workspace crates), no allocator, and no `std` outside tests. The crate builds for the default bare-metal target `x86_64-unknown-none`.

## Standard Conformance

The implementation follows **RFC 7748** (X25519 over Curve25519). It is validated byte-for-byte against the RFC 7748 known-answer vectors: the two Section 5.2 single-call scalar/u-coordinate pairs, the Section 5.2 iterated test (after 1 and after 1000 rounds of folding the output back into the scalar and base), the base-point scalar multiplication, and the Section 6.1 Alice/Bob Diffie-Hellman example.

Three validity rules bring the crate in line with the stricter reading of RFC 7748 Sections 5–6.1 and NIST SP 800-56A:

- **Scalar clamping (RFC 7748 §5).** Before the ladder the 32-byte scalar is clamped: `k[0] &= 248` (clear the low 3 bits — cofactor), `k[31] &= 127` (clear the top bit), `k[31] |= 64` (set bit 254). Clamping fixes the bit length, which is what makes the fixed-length ladder safe to run in constant time.
- **u-coordinate masking (RFC 7748 §5).** The most-significant bit of the input u-coordinate is ignored. Field decoding drops bit 255 structurally (`limbs[4] = (hi >> 12) & MASK51`), and `PublicKey::from_bytes` additionally masks `bytes[31] &= 0x7f`, so the stored key is canonical and a peer's encoding has no byte-level malleability.
- **Contributory behaviour (RFC 7748 §6.1, SP 800-56A).** A low-order public key drives the agreement to the all-zero shared secret — a value the peer could have predicted. `diffie_hellman` detects this and returns `Err(X25519Error::LowOrderPoint)` rather than handing back a non-contributory secret. The all-zero test (`SharedSecret::is_zero`) accumulates every output byte with `OR` and compares once, with no early return, so the test itself is data-independent. `is_contributory` exposes the same check as a `Choice` for callers that prefer to branch on it themselves.

## The Key-Agreement Protocol

X25519 is `x25519(k, u)` — multiply the curve point whose u-coordinate is `u` by the clamped scalar `k`, and return the resulting u-coordinate. Both public-key derivation and shared-secret agreement are this one operation:

```text
public_key()      ->  X25519(k, 9)          base point u = 9   ->  public key   (public)
diffie_hellman()  ->  X25519(k, u_peer)      peer public key    ->  shared secret (secret)
```

### The Montgomery ladder (RFC 7748 §5)

```text
k          = clamp(scalar)                        k   : secret
x_1        = u
(x_2, z_2) = (1, 0)                               identity rung
(x_3, z_3) = (u, 1)
swap       = 0
for pos in 254 .. 0:                              fixed 255 iterations
    k_t        = bit `pos` of k                   k_t : secret
    swap      ^= k_t
    cswap((x_2, z_2), (x_3, z_3), swap)           constant-time conditional swap
    swap       = k_t
    ... fixed ladder step: 5 mul, 4 square, mul_by_a24 (a24 = 121665), 8 add/sub ...
cswap((x_2, z_2), (x_3, z_3), swap)
return x_2 * z_2^(p - 2)                          z_2^(p-2) = z_2^{-1}  (Fermat)
```

Because there is no random nonce, X25519 has no randomness-failure mode. The only secret is the scalar `k`, and it is consumed in exactly one place — the ladder.

## Constant-Time Guarantee Rationale

The single secret that flows through value-dependent code is the scalar `k`. It is consumed only inside the ladder, and only through the per-iteration conditional swap. The constant-time argument therefore reduces to showing that *the ladder contains no secret-dependent branch, no secret-dependent memory access, and no variable-latency instruction.* The guarantee holds at four levels.

### 1. No secret-dependent branch — branchless conditional swap

The ladder is a fixed 255-iteration loop. Every iteration performs the same two `cswap`s and the same fixed sequence of field operations, unconditionally; the scalar bit only ever decides *whether two already-computed rungs are exchanged*, and that decision is a branchless masked move, never an `if`:

```rust
for pos in (0..255).rev() {
    let k_t = (k[pos / 8] >> (pos % 8)) & 1;     // pos, pos/8 are public loop indices
    swap ^= k_t;
    let choice = Choice::from_u8(swap);
    FieldElement::conditional_swap(&mut x_2, &mut x_3, choice);   // exchange or not
    FieldElement::conditional_swap(&mut z_2, &mut z_3, choice);
    swap = k_t;
    // ... fixed ladder-step field ops, identical every iteration ...
}
```

`conditional_swap` swaps the five limbs of two field elements through `u64::swap`, the `CtSelOps::swap` primitive of the `constant-time` crate. Unlike the Ed25519 point select — which uses portable arithmetic masking, `a ^ (mask & (a ^ b))` — X25519's swap bottoms out in a hand-written inline-assembly conditional move, `ct_sel64`. The choice byte selects with a single data-independent-latency instruction and no jump:

x86_64:
```asm
test   {c:e}, {c:e}        ; set ZF from the choice byte
cmovnz {r}, {a}            ; conditional move — no branch
```

aarch64:
```asm
cmp  {c:w}, #0
csel {r}, {a}, {b}, ne     ; conditional select — no branch
```

Both `asm!` blocks carry `options(nomem, nostack)`: the operands are register-only, so the move touches no memory and emits no `jcc` / `b.cc` that could read the scalar bit. A naive `if bit == 1 { swap }` would emit exactly such a secret-dependent conditional branch — observable through branch prediction and instruction-cache timing, and sufficient to recover the scalar one bit at a time. The crate never does this, and the running `swap ^= k_t; ... ; swap = k_t` idiom means the conditional move is the *only* place a scalar bit is ever consumed.

### 2. No secret-dependent memory access

The multiply is variable-base and table-free: the only point fed to the ladder is the caller's u-coordinate, and there is no precomputed table of base-point multiples indexed by secret bits. No load address depends on a secret, so no cache or TLB timing can vary with the key. The only indices in the hot loop — `pos`, `pos / 8`, `pos % 8` — are the public loop counter, so any bounds check the compiler inserts is a check on a public index, not on secret data.

### 3. Data-independent field arithmetic

- **Inversion** — the final `z_2^{-1}` — uses Fermat's little theorem, `z^(-1) = z^(p-2)`, evaluated by a fixed addition chain of squarings and multiplications (`invert`). The operation sequence is identical for every input; the crate never uses the extended Euclidean algorithm, whose iteration count depends on operand magnitude.
- **Multiplication** accumulates `64 × 64 -> 128`-bit partial products (`u128`) with the `2^255 ≡ 19` reduction fold (`mul_inner`). On x86_64 and aarch64 — the only two architectures the workspace supports — integer-multiply latency is independent of operand values, so the assumption is sound by construction rather than by hope. There is no `div` anywhere in the field code.
- **Reduction** — both the radix-2^51 carry chain (`carry_propagate`) and the final canonical reduction (`reduce`) — is straight-line code with a compile-time-fixed number of carry passes. `reduce`'s conditional subtraction of `p` is selected with an arithmetic mask derived from the borrow sign bit (`(s[4] >> 63)`), not a branch. No loop trip count depends on a value.
- **Equality** on field elements (`PartialEq`) reduces both operands and `OR`-accumulates the limb differences before a single comparison — no short-circuit — so even an internal field comparison is data-independent.

### 4. Erasure is delegated to a barrier-backed primitive

Where an optimizer barrier is genuinely required — wiping a secret so the compiler cannot elide the store — this crate does not rely on portable Rust. Constant-time *selection* is achieved with the `cmov` / `csel` primitives above; constant-time *erasure* is delegated to the `zeroize` crate, whose per-architecture `barrier/{x86_64,aarch64}.rs` issue real memory/compiler fences and volatile writes in inline assembly. The same discipline reaches inside the swap itself: `CtSelOps::swap` holds a one-limb plaintext copy in a stack temporary, then volatile-zeroes the whole slot, raises a `compiler_fence(SeqCst)` against store reordering, and routes the slot through `black_box` so the scratch copy cannot be left alive in a register (CWE-316).

## Secret Lifecycle and Zeroization

The daemon's core invariant is that a secret never outlives the transaction that used it. The crate enforces this structurally:

- `SecretKey` holds the scalar in `Secret<[u8; 32]>`; its `Drop` performs a volatile, barrier-fenced wipe. `SharedSecret` is wrapped identically.
- `x25519` copies the scalar into a `Secret` before clamping, so the clamped form is wiped on scope exit and the caller's key is never mutated in place.
- `montgomery_ladder` explicitly zeroizes every working field element before returning — the two rungs `(x_2, z_2)` and `(x_3, z_3)`, the base `x_1`, the inverse `z_2_inv`, the result, the `swap` byte, and all twelve per-iteration intermediates (`a, aa, b, bb, e, c, d, da, cb, sum, diff, a24_e`). The intermediates are declared once outside the loop and reassigned each round, so only the final round's values reach the wipe and none survive on the stack.
- `diffie_hellman` zeroizes the raw output buffer the instant it has been copied into the `Secret`-backed `SharedSecret`.

Together these make agreement stateless in the strongest sense: after `diffie_hellman` returns, the only secret-derived bytes still in memory are the scalar inside the caller's `SecretKey` and the secret inside the returned `SharedSecret`, both barrier-wiped on drop.

---

## Verification Summary

| Property                          | How it is checked                                                          |
|-----------------------------------|----------------------------------------------------------------------------|
| RFC 7748 correctness              | Byte-exact KAT: §5.2 vectors, §5.2 iterated test (1 and 1000), §6.1 example |
| Low-order point rejected          | All-zero shared secret returns `Err(X25519Error::LowOrderPoint)`           |
| u-coordinate canonicalized        | Bit 255 masked on field decode and in `PublicKey::from_bytes`              |
| Branchless secret scalar multiply | `cswap` lowers to `cmovnz` (x86_64) / `csel` (aarch64) via `ct_sel64`, no conditional branch |
| Data-independent inversion        | Fixed Fermat addition chain — no extended-Euclid, no `div`                 |
| Lint gate                         | `cargo clippy --all-targets --all-features -- -D warnings` clean           |
| Bare-metal posture                | Builds for `x86_64-unknown-none`, `no_std`, no `alloc`                     |

As remaining hardening, explicitly enabling the aarch64 DIT bit and the x86 DOITM mode — which pin data-independent timing at the ISA level for the `cmov` / `csel` instructions — is left for future work, mirroring the same open item tracked in the `constant-time` crate.
