# Constant-Time (CT) Module

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)

Constant-time logic is critical in cryptography. This document provides a technical description of how constant-time operations work in this project.

---

## Implemented Primitives

This crate provides integer operations that work without branching on secret values or performing data-dependent memory accesses. The public API consists of the `Choice` type and four traits.

- `Choice`: A constant-time bool that always holds 0 or 1. Bitwise operations `&`, `|`, `^`, `!` preserve the 0/1 invariant without normalization. `Debug` is intentionally not derived to prevent sensitive value leakage (CWE-532).
- `CtSelOps`: Conditional select (`select`), conditional assign (`assign`), conditional swap (`swap`).
- `CtEqOps`: Equality comparison (`eq`, `ne`).
- `CtGreeter`: Greater-than comparison (`gt`).
- `CtLess`: Less-than comparison (`lt`). Automatically provided as `!gt & !eq` for any type satisfying `CtEqOps + CtGreeter`.

The four traits are implemented for fixed-width integers from `u8` through `i128`, and are sealed so that external types cannot be inserted. Each implementation delegates to low-level primitives in the `internal` module.

- Select: `ct_sel32`, `ct_sel64`
- Equality: `ct_eq32`, `ct_eq64`, `ct_eq128`
- Comparison: `ct_gt_u32`, `ct_gt_u64`, `ct_gt_i64`, `ct_gt_u128`, `ct_gt_i128`

Smaller types are zero-extended or sign-extended to 32 or 64 bits before the call. 128-bit operations are composed on top of 64-bit primitives by combining the upper and lower halves.

## Constant-Time Guarantee Rationale

The constant-time property is guaranteed at three levels.

### 1. Only Data-Independent Instructions Are Used

On x86_64 and aarch64, each primitive is written directly in inline assembly, using only instructions that execute in a fixed number of cycles regardless of operand values.

| Operation           | x86_64            | aarch64           |
|---------------------|-------------------|-------------------|
| Select              | `test` + `cmovnz` | `cmp` + `csel`    |
| Equality            | `cmp` + `sete`    | `cmp` + `cset eq` |
| Greater (unsigned)  | `cmp` + `seta`    | `cmp` + `cset hi` |
| Greater (signed)    | `cmp` + `setg`    | `cmp` + `cset gt` |

Classic variable-time instructions such as `mul`, `div`, and conditional branches are never used. `cmov`, `csel`, `setcc`, and `cset` read the flags register to produce a result; their latency does not depend on data.

### 2. Register-Only, No Memory or Stack Access

All asm blocks take operands exclusively in registers and specify `options(nomem, nostack)`. No memory accesses means no secret-dependent cache or TLB timing, no stack spills, and no secret-dependent branches. There is therefore no execution path whose timing can vary with a secret value.

### 3. Choice 0/1 Invariant

`Choice` is normalized to 0/1 without branching via the mask `(v | v.wrapping_neg()) >> 7`, and bitwise operations preserve this invariant. As a result, higher-level compositions such as `lt = !gt & !eq` also remain branch-free.

Additionally, architectures without verified inline assembly are rejected at compile time via a compile gate (`compile_error!`), preventing a best-effort `black_box` fallback from silently mixing into high-security builds (see the "Issues Found and Mitigations" section below). The zeroing loop in `swap` has a termination condition equal to the compile-time constant `size_of::<Self>()`, so that branch does not depend on any secret.

## Optimizer Verification (llvm-objdump)

Even when source code is written without branches, the optimizer (LLVM) could theoretically recognize a pattern as a `select` idiom and reconstruct a `cmov` or, in the worst case, a branch. The inline assembly path emits assembly verbatim and is not subject to this risk, but to prevent regressions and to verify surrounding glue code as well, the produced binary is validated statically.

`scripts/check_ct_asm.sh` automates this process.

1. Build `examples/ct_asm_probes.rs` as a release binary for the host target. Each probe is emitted as an independent symbol via `#[unsafe(no_mangle)] extern "C"` + `#[inline(never)]`.
2. Disassemble with `llvm-objdump -d`. On macOS the binary is located at `/Library/Developer/CommandLineTools/usr/bin/llvm-objdump`.
3. Grep each CT probe symbol for conditional branch instructions (x86_64 `jcc`, `loop`; aarch64 `b.cc`, `cbz`, `cbnz`, `tbz`, `tbnz`). Detection of even one is a FAIL. Unconditional `jmp` and `b` (tail calls) are permitted.
4. The `swap` probe skips the branch check because the zeroing loop's branch is not secret-dependent. Instead it verifies that the volatile zeroing store survived (CWE-316 regression check).

For example, on aarch64, `u64::select` selects a value with a single `csel` — no branches — and ends with `ret`.

```text
<_probe_sel_u64>:
	cmp	w0, #0x0
	cset	w8, ne
	cmp	w8, #0x0
	csel	x0, x2, x1, ne
	ret
```

A full run reports all probes passing with no conditional branches.

```text
>> CT primitive probe (no conditional branches)
    PASS probe_sel_u64
    PASS probe_eq_u64
    PASS probe_gt_u64
    ...
>> swap probe (volatile zero store survival check only)
    PASS probe_swap_u64 — 1 zero store survived
RESULT: PASS — all probes: no conditional branches + zeroing preserved
```

To inspect a single symbol directly, disassemble as follows.

```bash
llvm-objdump -d --no-show-raw-insn target/<host-triple>/release/examples/ct_asm_probes
```

---

## Issues Found and Mitigations

This section describes issues identified in the implemented constant-time logic and their resolutions.

### `black_box` Dependency in the Fallback Path (Resolved)

Rust officially states that [`black_box` does not guarantee an optimization barrier](https://internals.rust-lang.org/t/optimization-barriers-suitable-for-cryptographic-use/21047). The compiler is free to ignore `black_box` entirely. Even if `ct_sel64`, `ct_eq64`, and `ct_mask` ([internal.rs](src/internal.rs)) are written branch-free using patterns like `(m & a) | (!m & b)`, there is no language-level way to prevent the optimizer from recognizing the pattern as a `select` idiom and reconstructing a `cmov` — or, in the worst case, a branch. This is an inherent uncertainty that stems from the design of `black_box` itself and cannot be fixed by writing better code.

Fortunately, the arithmetic itself uses only AND/OR/shift/sub without classic variable-time instructions such as mul/div/branch, so the residual risk narrows to a single scenario: the optimizer reconstructing a branch.

As the `#[deprecated]` const trick and the `# Security Note` on each function make clear, the weakness in the code was already explicitly recognized. The issue is that this is a warning-level concern. The alternative considered at that point was: "for targets without inline assembly support, return a `compiler_fence` fallback or an explicit `Err(Unsupported)`," and to restrict supported targets to AMD64 and AArch64.

#### Resolution

This issue was resolved in [PR #7](https://github.com/Quant-Off/elib-k0-nt/pull/7) via a compile gate.

Only x86_64 and aarch64 — which have verified constant-time implementations via inline assembly — are designated as supported targets. Non-miri builds on any other architecture are rejected at compile time with `compile_error!`.

```rust
#[cfg(all(not(miri), not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
compile_error!("constant-time verified constant-time implementation is only available on x86_64 and aarch64 ...");
```

This promotes the former `#[deprecated]` warning (soft) to a hard gate, ensuring that best-effort `black_box` fallbacks can never silently mix into high-security builds. `miri` cannot execute inline assembly, so it is exempted to allow validation of fallback logic. The gate message was confirmed in practice when an `riscv64gc-unknown-none-elf` build was rejected.

As a remaining task, hardening to explicitly enable the aarch64 DIT bit and x86 DOITM — which are required for ISA-level data-independent timing guarantees on `cmov`/`csel` — is left for future work.

---

### UB (Undefined Behavior) Risk in `swap` Memory Zeroing (Resolved)

This issue was high in severity. `CtSelOps` is a `pub` trait with only a `: Copy` bound. The `Copy` bound blocks only `Drop` types (Copy and Drop are mutually exclusive), but it does not block `Copy` types that carry a niche. Therefore, an external implementation such as:

```rust
impl CtSelOps for SomeCopyTypeWithNiche { ... }
```

where `SomeCopyTypeWithNiche` is `&'static T`, `NonZeroU32`, `fn()`, `NonNull<T>`, or a struct containing one of these as a field, would produce an invalid value (null reference, zero NonZero, null function pointer) the moment all-zero bytes are written. In Rust, **a typed place holding an invalid value is UB in itself.** "We don't read it anyway" is not acceptable under strict validity rules. The `Copy` bound already blocked the `Drop`-based variant, providing one guard rail — but it was insufficient to block niche types.

Additionally, in a prior [commit](https://github.com/Quant-Off/elib-k0-nt/tree/db229a365efdd4327b74b7c01c563820b566ae57), the `swap` [Safety docstring](https://github.com/Quant-Off/elib-k0-nt/blob/db229a365efdd4327b74b7c01c563820b566ae57/constant-time/src/lib.rs#L170-L182) argued soundness based solely on `Self: Copy + Sized` without stating the required precondition that "all-zero must be a valid value for Self," which was a slight overclaim.

#### Resolution

This issue was resolved in [PR #6](https://github.com/Quant-Off/elib-k0-nt/pull/6) via approach (A): trait sealing.

A `Sealed` marker trait in a private module was designated as a supertrait of `CtSelOps`, and `Sealed` was implemented only for fixed-width integers (`u8..i128`) internal to the crate.

```rust
mod private {
    pub trait Sealed {}
}

pub trait CtSelOps: Copy + private::Sealed { /* ... */ }
```

External crates can no longer implement `CtSelOps` on their own types. The `Self` that `swap` zeroes is therefore restricted to fixed-width integers for which all-zero is always a valid value. There is no longer any way for a niche type to be introduced, making invalid-value UB structurally impossible — without changing a single line of the zeroing hot path. The `# Safety` documentation for `swap` was also updated to state this sealing invariant explicitly, correcting the prior overclaim.
