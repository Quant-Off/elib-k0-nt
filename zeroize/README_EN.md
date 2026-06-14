# zeroize

A crate for securely wiping sensitive data from memory.

## The Core Problem: Dead Store Elimination

A typical memory wipe (`*ptr = 0`) can be eliminated by the compiler. If the value is not read again after the write, the compiler may consider it an unnecessary operation and omit it during optimization (Dead Store Elimination, DSE). This means cryptographic keys, passwords, and intermediate signature values could remain in memory and be exposed to attackers.

This crate guarantees that the wipe operation is always executed by combining the following three mechanisms.

## Mechanism 1: Volatile Write

```
src/volatile.rs
```

`ptr::write_volatile` is an operation designated as "cannot be elided" in Rust and LLVM. Since the compiler treats volatile accesses as observable side effects, it does not apply DSE to them.

- `volatile_write<T>`: A volatile write to a single value
- `volatile_set`: Iterates over the entire byte array and performs volatile writes byte by byte
- `secure_zero`: A wrapper that calls `volatile_set` with 0

The `Zeroize` implementations for all primitive integer types (`u8`~`u128`, `i8`~`i128`, `usize`, `isize`), as well as `[T; N]` and `&mut [T]` slices, go through this path.

## Mechanism 2: Compiler Barrier

```
src/barrier/{x86_64, aarch64, fallback}.rs
```

A volatile write alone might not prevent the compiler from reordering write operations or caching the value in a register. A compiler barrier forces the compiler not to reorder memory operations before or after that point.

| Architecture | Implementation                                                                         |
|--------------|----------------------------------------------------------------------------------------|
| x86_64       | `asm!("")` — Establishes a compiler reordering boundary using an empty inline assembly |
| AArch64      | Same as above                                                                          |
| fallback     | `core::sync::atomic::compiler_fence(SeqCst)`                                           |

`compiler_barrier()` is inserted both before and after the wipe operation to ensure that the wipe code is not moved outside of the wipe boundary.

## Mechanism 3: Memory Barrier + `black_box`

```
src/barrier/{x86_64, aarch64, fallback}.rs
```

Modern CPUs can execute instructions Out-of-Order independently of the compiler or delay writes to the cache hierarchy. A memory barrier ensures at the hardware level that all writes prior to this point are completed and become visible.

| Architecture | Instruction     | Meaning                                       |
|--------------|-----------------|-----------------------------------------------|
| x86_64       | `mfence`        | Guarantees global ordering of all Load/Stores |
| AArch64      | `dsb sy`        | Full system barrier for all memory accesses   |
| fallback     | `fence(SeqCst)` | Atomic fence with `SeqCst` ordering           |

`atomic_compiler_fence()` additionally prevents compiler-level reordering after the wipe is complete.

`black_box(ptr)` forces the pointer to be wiped to be loaded into a CPU register, preventing the compiler from considering the pointer an "unused value".

| Architecture | Implementation                                 |
|--------------|------------------------------------------------|
| x86_64       | `asm!("", in("rax") &value)` + `read_volatile` |
| AArch64      | `asm!("", in("x0") &value)` + `read_volatile`  |
| fallback     | `read_volatile(ptr)`                           |

## Execution Order of Wipe

`zeroize_flat`, `Secret::drop`, and `volatile_set` all follow the same order.

```text
1. compiler_barrier()          — Compiler: Do not move pre-wipe operations after the wipe block
2. write_volatile(ptr+i, 0)    — Actual wipe, cannot be eliminated by the compiler
   (Byte-by-byte iteration)
3. compiler_barrier()          — Compiler: Do not move post-wipe operations before the wipe block
4. atomic_compiler_fence()     — Additional SeqCst compiler-level prevention
5. memory_barrier()            — CPU: Flush Out-of-Order execution and delayed cache writes
6. black_box(ptr)              — Final prevention of optimization by loading the pointer into a register
```

## Formal Model

Let a buffer occupy the bytes $p, p{+}1, \dots, p{+}n{-}1$. A wipe is the family of stores

$$ W = \bigl\{\, \mathrm{mem}[p{+}i] \leftarrow 0 \;\bigm|\; 0 \le i < n \,\bigr\}. $$

**Dead Store Elimination.** A store $s \in W$ to address $a$ is *dead* when no load of $a$ is reachable from $s$ before $a$ is overwritten or its storage is released:

$$ \mathrm{dead}(s) \iff \nexists\, \ell \in \mathrm{Loads}(a) \ \text{such that}\ s \prec \ell . $$

A correct optimizer may delete any dead store, since deleting it leaves the program's observable behavior $\mathcal{O}$ unchanged. For a secret that is no longer used after the wipe, *every* $s \in W$ is dead, so $W$ is exactly the set DSE is permitted to remove. This is the worst case for cryptographic code: the more "useless" the wipe looks, the more eligible it is for elimination.

**Volatile defeats DSE.** A volatile access is, by definition, an element of $\mathcal{O}$. Writing $w^{\mathrm{vol}}_i$ for the volatile store of byte $i$,

$$ w^{\mathrm{vol}}_i \in \mathcal{O} \quad\Longrightarrow\quad \forall\,\text{sound } \mathcal{T}:\; w^{\mathrm{vol}}_i \in \mathcal{T}(\mathcal{O}) . $$

The deadness premise becomes irrelevant: an observable side effect is preserved whether or not its result is ever read. This converts "may be removed" into "must be emitted."

**Ordering.** The barriers impose a total order on the wipe's operations,

$$ \mathrm{cb}_1 \;\prec\; w^{\mathrm{vol}}_0 \prec \dots \prec w^{\mathrm{vol}}_{n-1} \;\prec\; \mathrm{cb}_2 \;\prec\; \mathrm{acf} \;\prec\; \mathrm{mb} \;\prec\; \mathrm{bb}, $$

where $\mathrm{cb}$ is a compiler barrier, $\mathrm{acf}$ an atomic compiler fence, $\mathrm{mb}$ the CPU memory barrier, and $\mathrm{bb}$ the `black_box` register pin. $\mathrm{cb}_1$ blocks sinking pre-wipe work below the stores; $\mathrm{cb}_2$ and $\mathrm{acf}$ block hoisting post-wipe work above them; $\mathrm{mb}$ forces the retired stores to become globally visible in hardware.

## Assembly-Level Verification (llvm-objdump)

Volatile semantics are a *language-level* contract. To confirm the contract survives the full release pipeline (`opt-level = "z"`, `lto = true`, `panic = "abort"`) all the way down to machine code, the emitted binary is disassembled and validated statically. This reuses the same harness that guards the constant-time crate: `constant-time/scripts/check_ct_asm.sh` drives both, and its `PROBES_ZEROIZE` group covers this crate.

Two probes in `zeroize/examples/zeroize_asm_probes.rs` are each emitted as an independent symbol via `#[unsafe(no_mangle)] extern "C"` + `#[inline(never)]`:

- `probe_zeroize_flat` runs `zeroize_flat` over a 64-byte buffer.
- `probe_secret_drop` constructs `Secret<[u8; 32]>` and lets it drop.

Unlike the constant-time probes, the wipe path is **not** checked for conditional-branch absence. Its loop bound is the compile-time constant `size_of`, so the loop branch is not secret-dependent and a branch check would be a false positive. Instead each zeroize probe must satisfy two predicates at once:

$$ \#\{\text{volatile zero store}\} \ge 1 \quad\wedge\quad \#\{\text{memory fence}\} \ge 1 . $$

If either count falls to zero, a dead-store regression (CWE-14 / CWE-316) has slipped in and the check fails. On aarch64 the zero store is `strb wzr` and the fence is `dsb sy`; on x86_64 they are `mov $0`-class stores and `mfence`.

Disassembling `probe_zeroize_flat` on the host (`aarch64-apple-darwin`) shows the byte loop over `0x40 = 64` bytes, ending in the surviving fence and the `black_box` tail call (labels trimmed, comments added):

```text
<_probe_zeroize_flat>:
    mov     x8, #0x0
    cmp     x8, #0x40            ; i == 64 ? (counter bound, not secret)
    b.eq    <+0x18>              ; loop exit
    strb    wzr, [x0, x8]        ; volatile store: mem[p+i] <- 0  (survives DCE)
    add     x8, x8, #0x1
    b       <+0x4>
    dsb     sy                   ; memory_barrier(): retire stores in hardware
    b       <zeroize::barrier::aarch64::black_box>
```

`probe_secret_drop` materializes the 32-byte secret (`dup.16b` + `stp q0, q0`), wipes it through the same volatile loop, then emits the fence and the `black_box` pin:

```text
<_probe_secret_drop>:
    ...
    dup.16b v0, w0               ; secret = [seed; 32]
    stp     q0, q0, [sp]
    ...
    cmp     x8, #0x20            ; i == 32 ?
    b.eq    <+0x38>
    strb    wzr, [x9, x8]        ; volatile byte wipe
    add     x8, x8, #0x1
    b       <+0x24>
    dsb     sy                   ; memory_barrier()
    mov     x0, sp
    bl      <zeroize::barrier::aarch64::black_box>
    ...
    ret
```

A full run reports both probes preserving their store and their fence:

```text
>> zeroize probe (zero store + fence survival)
    PASS probe_secret_drop  (zero store: 1, fence: 1)
    PASS probe_zeroize_flat (zero store: 1, fence: 1)
RESULT: PASS
```

To inspect a single symbol directly:

```bash
llvm-objdump -d --no-show-raw-insn target/<host-triple>/release/examples/zeroize_asm_probes
```

On macOS the binary is at `/Library/Developer/CommandLineTools/usr/bin/llvm-objdump`.

### Counter-Example: DSE in Action

DSE is a *permitted* transformation, and whether the optimizer exercises it depends on opt-level, compiler version, and surrounding code. That unpredictability is the hazard. The contrast below makes the freedom concrete: two functions wipe a 32-byte stack secret that becomes dead after a checksum is read from it, one with a plain store and one with `ptr::write_volatile`. Built at `opt-level = 3`:

```text
<_naive_wipe_dead>:                  ; plain `*b = 0`
    ubfiz   w0, w0, #5, #3           ; return checksum (32*seed mod 256);
    ret                              ; buffer + all 32 stores ELIMINATED (0 stores)

<_volatile_wipe_dead>:               ; ptr::write_volatile(.., 0)
    sub     sp, sp, #0x20
    strb    wzr, [sp, #0x1f]         ; 32 volatile stores, every one preserved
    strb    wzr, [sp, #0x1e]
    ...                              ; (32 total)
    strb    wzr, [sp, #0x1]
    ubfiz   w0, w0, #5, #3
    strb    wzr, [sp], #0x20
    ret
```

The plain version collapses to two instructions: the optimizer proved the buffer dead and deleted all 32 stores, so the secret's bytes would survive on the stack. The volatile version keeps every store. Note that this same plain loop happens to survive at `opt-level = "z"` yet vanishes at `opt-level = 3`: survival of a non-volatile wipe is guaranteed at no optimization level. The crate therefore never relies on the optimizer's discretion. Volatile plus barriers force the wipe to survive across every opt-level, including the project's own `opt-level = "z"`.

### Runtime Readback Verification

The static check proves the stores are *emitted*; `zeroize/tests/zeroize_readback.rs` proves they *take effect*. Each test writes a non-zero pattern, captures the raw address, triggers the wipe (`Secret::drop`, `zeroize_flat`, `[T; N]::zeroize`, `&mut [T]::zeroize`), then reads the same address back and asserts every byte is zero:

```text
running 5 tests
test secret_array_zeroized_on_drop ... ok
test secret_into_inner_extracts_value ... ok
test zeroize_flat_wipes_bytes ... ok
test array_zeroize_wipes ... ok
test slice_zeroize_wipes ... ok
test result: ok. 5 passed
```

Together the two layers close the loop: readback confirms the wipe is correct *when it runs*, and the llvm-objdump check confirms the optimizer cannot silently drop it from the shipped binary.

---

## API

### `Zeroize` Trait

```rust
pub trait Zeroize {
    fn zeroize(&mut self);
}
```

Implemented for `u8`~`u128`, `i8`~`i128`, `usize`, `isize`, `[T; N]`, `&mut [T]`.

### `Secret<T>`

```rust
// let key = Secret::new([0u8; 32]);
// Drop is called at the end of the scope to automatically wipe internal data
```

The `Drop` implementation performs the 6-step wipe order described above. Internal values can only be accessed via `expose()` / `expose_mut()`, preventing accidental exposure of plaintext.

### `zeroize_flat<T>`

Wipes any `T` that does not implement `Zeroize` (like structs) byte by byte.

> [!WARNING]
> If `T` contains a pointer, be careful as only the pointer itself will be wiped, not the referenced target.

### `secure_zero`

```rust
// pub unsafe fn secure_zero(dest: *mut u8, count: usize);
```

A raw pointer-based byte array wipe. Used to directly wipe buffers in a `no_std` bare-metal environment.

## `no_std` Compatibility

Only uses the `core` crate without any external dependencies. Works without `std` in AMD64, AArch64, and bare-metal environments, with architecture detection handled by compile-time `cfg`.