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