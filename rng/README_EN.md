# Random Number Generation (RNG) Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)

Every secret in a cryptographic system ultimately converges to a single source of randomness. The moment a key, IV, nonce, or capability token becomes predictable, all the standards compliance built on top of it becomes meaningless. This document technically describes how the `rng` crate implements [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) Hash_DRBG and the OS entropy adapter, and where the security rationale is rooted at the machine-instruction level.

---

## Provided Functionality

The crate is organized into two layers: a Deterministic Random Bit Generator (DRBG) and the OS entropy adapter that feeds it seeds.

### Hash_DRBG (`hash_drbg.rs`)

Instantiates Hash_DRBG from NIST SP 800-90A Rev. 1, Section 10.1 with four SHA-2 variants. The `impl_hash_drbg!` macro generates identical logic varying only the standard Table 2 parameters, so there is no behavioral difference between variants.

| Type               | Hash    | Security Strength | outlen | seedlen | Min Entropy   |
|------------------|---------|----------|--------|---------|-----------|
| `HashDRBGSHA224` | SHA-224 | 112 bits | 28 B   | 55 B    | 14 B      |
| `HashDRBGSHA256` | SHA-256 | 128 bits | 32 B   | 55 B    | 16 B      |
| `HashDRBGSHA384` | SHA-384 | 192 bits | 48 B   | 111 B   | 24 B      |
| `HashDRBGSHA512` | SHA-512 | 256 bits | 64 B   | 111 B   | 32 B (recommended) |

The three standard algorithms are exposed as-is.

- `Instantiate` (10.1.1.2): `V = Hash_df(entropy || nonce || personalization, seedlen)`, `C = Hash_df(0x00 || V, seedlen)`, `reseed_counter = 1`.
- `Reseed` (10.1.1.3): `V = Hash_df(0x01 || V || entropy || additional_input, seedlen)`, re-derive `C`, reset counter to 1.
- `Generate` (10.1.1.4): apply `additional_input` (`w` path) -> `Hashgen` -> `V = (V + H + C + reseed_counter) mod 2^seedlen`.

The public API is split into two pairs depending on the entropy source.

| Path       | Initialization                | Reseed             | Entropy Source                   |
|------|-------------------------------|------------------|--------------------------|
| Recommended | `new_from_os`              | `reseed_from_os` | OS CSPRNG (collected internally) |
| Bare-metal  | `new_from_entropy` (`unsafe`) | `reseed`        | Caller-injected (RDSEED, TRNG, etc.) |

The `new_from_os` family blocks the caller from touching entropy directly, eliminating any predictable seed injection path at the source. `new_from_entropy` is an escape hatch for environments without an OS, marked `unsafe` to explicitly transfer the responsibility for entropy quality, independence, and non-reuse to the caller.

```rust,ignore
use rng::{HashDRBGSHA256, DrbgError};

// Host side: seed with OS CSPRNG (recommended)
let mut drbg = HashDRBGSHA256::new_from_os(Some(b"host-boot-id"))?;
let mut out = [0u8; 128];
drbg.generate(&mut out, None)?;

// On receiving ReseedRequired, safely reseed with OS entropy
drbg.reseed_from_os(None)?;
```

### OS Entropy Adapter (`os_entropy.rs`)

A thin adapter that directly calls platform-specific CSPRNGs. Connects directly to syscalls or libc symbols without external crates (`getrandom`, `rand`) — Zero-Trust. Provides three entry points: `fill_bytes`, `get_bytes::<N>`, and `extract_os_entropy` (crate-internal).

### SecureBuffer (`lib.rs`)

A fixed 128-byte stack buffer that holds DRBG internal state (V, C) and collected entropy. Operates without `alloc` (`no_std`), and on Drop/`zeroize` performs a volatile write wipe across the entire backing storage, not just the active region.

---

## Assembly-Level Rationale for Entropy Collection

The point where "machine-instruction level" security is most directly visible in this crate is the entropy syscall. It enters the kernel directly via inline assembly without going through the standard library or external crates, so what gets clobbered and what gets preserved is spelled out directly in the source.

### 1. Direct Syscall — No Intermediate Layer

The `getrandom(2)` call on Linux x86_64 is as follows.

```rust
core::arch::asm!(
    "syscall",
    inlateout("rax") SYS_GETRANDOM => ret, // 318
    in("rdi") ptr,
    in("rsi") len,
    in("rdx") 0u32,        // flags = 0 (blocking)
    lateout("rcx") _,      // syscall saves return RIP -> clobbered
    lateout("r11") _,      // syscall saves RFLAGS -> clobbered
    options(nostack),
);
```

This follows the Linux x86_64 syscall ABI exactly: number in `rax`, arguments in `rdi`/`rsi`/`rdx`, return in `rax`. The `syscall` instruction overwrites `rcx` with the return address and `r11` with flags, so both registers are declared as `lateout(_)` clobbers to prevent the compiler from placing live values there. aarch64 expresses the same structure with `svc #0` + `x8` (number) + `x0..x2` (arguments), with the return value in `x0`.

| Platform               | Mechanism     | Instruction/Symbol               | Number         |
|------------------------|-------------|--------------------------------------|----------------|
| Linux x86_64           | raw syscall | `syscall`                            | rax = 318      |
| Linux aarch64          | raw syscall | `svc #0`                             | x8 = 278       |
| FreeBSD x86_64/aarch64 | raw syscall | `syscall`/`svc #0`                   | 563            |
| OpenBSD x86_64/aarch64 | raw syscall | `syscall`/`svc #0`                   | getentropy = 7 |
| macOS x86_64/aarch64   | libc        | `getentropy`                         | (symbol link)  |
| NetBSD x86_64          | libc        | `getentropy`                         | (symbol link)  |
| Windows x86_64         | advapi32    | `RtlGenRandom` (`SystemFunction036`) | (symbol link)  |

Only macOS/NetBSD use the libc `getentropy` symbol instead of a raw syscall. These two platforms have unstable syscall number ABIs where direct calls can break, and this is noted as an unavoidable exception. The remaining Linux/BSD platforms use raw syscalls since their numbers are stable.

### 2. Why `options(nomem)` Is Not Used (Correctness Is Security)

The asm blocks in the constant-time primitives (`constant-time` crate) declare `options(nomem, nostack)` to indicate no memory access. However, the entropy syscall deliberately omits `nomem` and only declares `nostack`.

This is because the kernel writes random bytes into the user buffer pointed to by `ptr` — this asm modifies memory through a pointer. Adding `nomem` here would be a lie to the compiler: "this asm does not read or write memory." The optimizer could then eliminate the buffer fill as dead code or reorder it with adjacent memory operations, resulting in undefined behavior. Omitting `nomem` is not an oversight — it is a correctness guarantee that forces the compiler to trust that the buffer has actually been filled.

### 3. Blocking Mode and Partial Read Handling

`flags = 0` sets neither `GRND_NONBLOCK` nor `GRND_RANDOM`.

- No `GRND_RANDOM`: draws from the CSPRNG (`/dev/urandom` semantics) that never exhausts once initialized, rather than the easily-depleted blocking `/dev/random` pool.
- No `GRND_NONBLOCK`: if the pool has not been seeded yet immediately after boot, it blocks until seeding is complete. Waiting is preferred over silently proceeding with weak entropy.

Return value handling is also defensive, matching the machine ABI.

- `ret < 0` and `-4` (EINTR): interrupted by a signal — retry in loop.
- `ret < 0` otherwise: return `OsEntropyFailed`.
- `ret == 0`: should not appear on the normal path per the getrandom contract, but treated as failure to prevent infinite loops or under-seeding.
- `0 < ret < len`: partial read. Retry the remainder with `offset += ret`.

The `getentropy` path (macOS/BSD) has a 256-byte cap per call, so it slices requests with `min(remaining, 256)` and loops.

### 4. Absent on Bare-Metal Default Target

The workspace default build target is `x86_64-unknown-none`. On this target, none of the above `cfg` conditions are satisfied, so `mod sys` always compiles to a fallback that returns `Err(OsEntropyFailed)`. This means OS entropy is unavailable in the actual microkernel Ring-3 daemon deployment, and seeds must be injected via `new_from_entropy` from the kernel or hardware TRNG. The platform-specific syscall paths above are primarily for host-side builds and testing.

---

## Assembly-Level Rationale for Memory Zeroization

The core value proposition of the DRBG is "one request, one datum, immediate wipe." If internal state V/C and intermediate computed values remain in memory after use, a memory dump or remanence analysis could reverse-engineer the entire output. This crate blocks remanence with two tools.

### 1. SecureBuffer Full-Region Wipe

`SecureBuffer::zeroize` wipes the entire backing `[u8; 128]`, not just the active length `len`.

```rust
fn zeroize(&mut self) {
    self.data.zeroize(); // covers bytes beyond the active region too
    self.len.zeroize();
}
```

This removes residual bytes that remain in the inactive region when the buffer was previously used with a larger `len` that has since shrunk. The actual wipe is handled by the `zeroize` crate, whose core mechanism is a volatile write (`volatile_write`) followed by an architecture-specific memory/compiler barrier (x86_64/aarch64 inline assembly, otherwise `compiler_fence`) to prevent the compiler from eliminating it. A plain `self.data = [0; 128]` assignment could be removed by LLVM's Dead Store Elimination (DSE), but a volatile write forces the store to be emitted at the machine level.

`Drop` calls this `zeroize`, so the backing storage is zeroed on every path that exits the scope — whether normal exit or panic (`panic = "abort"` environment).

### 2. Stack Intermediates as Secret

`hash_df`/`hashgen`/`generate`/`reseed` copy V to a stack array for processing. This copy is wrapped in `zeroize::Secret`.

```rust
let mut data = Secret::new([0u8; $seedlen]);
data.expose_mut().copy_from_slice(self.v.as_slice());
// ... use ...
// automatic wipe via volatile write + barrier on Drop
```

The importance of `Secret` is the `?` early-return and panic paths. Even if `hash_df` exits early with `InvalidArgument`, `Secret`'s `Drop` is guaranteed, so partially-computed `new_v`/`new_c` do not remain on the stack in plaintext. All of `w_padded`/`h_padded`/`c_copy`/`data` inside `generate` are protected the same way.

### 3. `reseed_counter` and Field Drop Order

The DRBG's `Drop` body explicitly wipes only `reseed_counter`.

```rust
impl Drop for $struct_name {
    fn drop(&mut self) {
        self.reseed_counter.zeroize();
    }
}
```

V and C are wiped by `SecureBuffer`'s own `Drop`, and Rust drops fields in declaration order (`v`, `c`, `reseed_counter`) after the `Drop::drop` body executes — so both are wiped without an explicit call. The counter is an integer with no own `Drop`, so it is handled directly in the body.

Note that OS page locking (`mlock`) is absent here. There is no OS to lock against on bare-metal/`no_std`. Therefore, memory protection relies on "volatile wipe immediately after use" to minimize the remanence exposure window, rather than page locking.

---

## Constant-Time Invariants

In the DRBG threat model, the protected secret is **internal state V/C**, and the return value of `generate` is public. Therefore, timing protection of the output itself is unnecessary, but if the arithmetic that handles internal state branches on its value, state could leak. The two arithmetic operations that touch state are value-independent.

### add_mod / add_u64_mod: Value-Independent Modular Addition

Updates like `V = (V + w) mod 2^seedlen` are implemented as big-endian modular addition.

```rust
fn add_mod(dst: &mut [u8], src: &[u8]) {
    let mut carry: u16 = 0;
    for (d, s) in dst.iter_mut().rev().zip(src.iter().rev()) {
        let sum = *d as u16 + *s as u16 + carry;
        *d = sum as u8;
        carry = sum >> 8; // branchless carry propagation
    }
}
```

- The iteration count is always `dst.len()` (= seedlen, a public constant). It does not grow or shrink based on secret values.
- Carry propagation uses `u16` arithmetic and `>> 8` masking rather than a branch like `if carry > 0`. No conditional branch (`jcc`/`b.cc`) is generated at the machine level.
- Memory accesses are linearly indexed only, so there are no secret-dependent cache/TLB timing effects.

The `if i < 8` branch in `add_u64_mod` depends on an **index** (a public constant), not a secret value, and the `val` being added is the monotonically increasing `reseed_counter`, which is not a secret. Observing the timing of this branch is therefore not a threat.

### Hashgen: Depends Only on Public Length

The loop count in `hashgen` is `ceil(requested_bytes / outlen)`, which depends only on the request length (public) and is independent of the secret value of V. The hash input size is fixed, so hash operation timing is also independent of V's value.

> Note: the constant-time property of this arithmetic relies on the absence of branches in ordinary Rust arithmetic, not on the verified inline-assembly primitives of the `constant-time` crate. There is no guarantee as strong as the `constant-time` asm path that the optimizer will not reconstruct this pattern into a branch. **The current rationale is that any branch is only conditioned on a counter or public length, not a secret, so the threat surface is narrow.**

---

## Standards Compliance and Boundary Values

The boundary values from NIST SP 800-90A Rev. 1 Table 2 are enforced in code.

| Parameter        | Value                            | On Violation                                    |
|-----------|----------------------------------|------------------------------------------------|
| Minimum entropy   | security_strength bytes          | `EntropyTooShort`                              |
| Maximum input length | 2^32 bytes (2^35 bits)        | `EntropyTooLong`/`InputTooLong`/`NonceTooLong` |
| Minimum nonce     | security_strength / 2 bytes      | `NonceTooShort`                                |
| Max output per request | 65536 bytes (2^16 B = 2^19 bits) | `RequestTooLarge`                         |
| Reseed interval   | 2^48                             | `ReseedRequired`                               |

Additional properties:

- **2x entropy collection**: `new_from_os`/`reseed_from_os` collect `2 * security_strength` bytes (Section 8.6.7).
- **Nonce independence**: entropy and nonce are collected via **separate calls** to the OS to eliminate correlation.
- **Hash_df counter wrap guard**: `Hash_df` rejects inputs where the 1-byte counter would overflow (`m > 255`) with `InvalidArgument`. This cannot occur in current business logic, but forms a strict defensive barrier at the input stage.
- **`additional_input` null distinction**: per the standard, if `additional_input != Null`, even a length-0 value should update V via the `w` path. `Some(&[])` and `None` are distinguished: the former triggers an update, only the latter is skipped.

---

## Design Limitations and Caveats

Known weaknesses are stated explicitly.

### OS CSPRNG Is Not an SP 800-90B Validated Entropy Source

What this module exposes is OS CSPRNG output (`getrandom`/`getentropy`/`RtlGenRandom`). This is not an SP 800-90B validated entropy source (with health tests) — it is an RBG seed source from the SP 800-90C perspective. For FIPS certification, entropy assessment depends on the platform RBG assurances.

### OS Entropy Is Unavailable on Bare-Metal

On the default target, the OS path is not compiled. Seeds must be injected externally via `new_from_entropy`, and weak entropy injection makes DRBG output predictable, collapsing the entire upper layer (keys/tokens/IVs). That is why this path is `unsafe`.

### Prediction Resistance Not Implemented

`generate` does not pull new entropy on every call. If prediction resistance is required, `reseed_from_os` must be called explicitly before generating.

### libc Dependency on macOS/NetBSD

These two platforms link to libc `getentropy` instead of a raw syscall. This is unavoidable because their syscall numbers are not stable ABIs. It is a limited exception to the Zero-Trust "zero external dependencies" principle, confined to a single OS standard C runtime symbol.
