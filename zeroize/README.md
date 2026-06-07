# zeroize

민감한 데이터를 메모리에서 안전하게 소거하는 크레이트입니다.

## 핵심 문제: Dead Store Elimination

일반적인 메모리 소거(`*ptr = 0`)는 컴파일러에 의해 제거될 수 있습니다. 컴파일러는 해당 쓰기 이후 값이 다시 읽히지 않으면 불필요한 연산으로 판단하여 최적화 과정에서 생략합니다(Dead Store Elimination, DSE). 이는 암호 키, 비밀번호, 서명 중간값 등이 메모리에 그대로 남아 공격자에게 노출될 수 있다는 것을 의미합니다.

이 크레이트는 다음 세 가지 메커니즘을 조합하여 소거 연산이 반드시 실행되도록 보장합니다.

## 메커니즘 1: Volatile Write

```
src/volatile.rs
```

`ptr::write_volatile`은 Rust 및 LLVM에서 제거 불가(cannot be elided)로 지정된 연산입니다. 컴파일러는 volatile 접근을 관측 가능한 부수 효과(observable side effect)로 간주하므로 DSE을 적용하지 않습니다.

- `volatile_write<T>`: 단일 값에 대한 volatile 쓰기
- `volatile_set`: 바이트 배열 전체를 순회하며 바이트 단위로 volatile 쓰기
- `secure_zero`: `volatile_set`을 0으로 호출하는 래퍼

모든 기본 정수 타입(`u8`~`u128`, `i8`~`i128`, `usize`, `isize`)의 `Zeroize` 구현과, `[T; N]` 및 `&mut [T]` 슬라이스 구현이 이 경로를 통합니다.

## 메커니즘 2: Compiler Barrier

```
src/barrier/{x86_64, aarch64, fallback}.rs
```

volatile 쓰기만으로는 컴파일러가 쓰기 순서를 재배치(reorder) 하거나 레지스터에 값을 캐싱하는 것을 막지 못할 수 있습니다. 컴파일러 배리어(compiler barrier)는 컴파일러가 그 시점을 기준으로 앞뒤의 메모리 연산을 재배치하지 못하도록 강제합니다.

| 아키텍처     | 구현                                           |
|----------|----------------------------------------------|
| x86_64   | 빈(empty) 인-라인 어셈블리                           |
| AArch64  | x86_64와 동일                                   |
| fallback | `core::sync::atomic::compiler_fence(SeqCst)` |

소거 연산의 앞뒤 양쪽에 `compiler_barrier()`가 삽입되어 소거 코드가 소거 범위 밖으로 이동하지 않음을 보장합니다.

## 메커니즘 3: Memory Barrier + `black_box`

```
src/barrier/{x86_64, aarch64, fallback}.rs
```

현대 CPU는 컴파일러와 독립적으로 명령어를 비순서(Out-of-Order) 실행하거나 캐시 계층에 쓰기를 지연시킬 수 있습니다. 메모리 배리어(memory barrier)는 하드웨어 수준에서 이 시점 이전의 모든 쓰기가 완료되고 가시(visible) 상태가 됨을 보장합니다.

| 아키텍처     | 명령어             | 의미                             |
|----------|-----------------|--------------------------------|
| x86_64   | `mfence`        | 모든 Load/Store의 전역 순서 보장        |
| AArch64  | `dsb sy`        | 모든 메모리 접근의 Full system barrier |
| fallback | `fence(SeqCst)` | `SeqCst` 순서의 원자적 펜스            |

`atomic_compiler_fence()`는 소거 완료 이후 컴파일러 수준 재배치를 추가로 차단합니다.

`black_box(ptr)`는 소거 대상 포인터를 CPU 레지스터에 강제 로드하여, 컴파일러가 해당 포인터를 "사용되지 않는 값"으로 간주하는 것을 차단합니다.

| 아키텍처     | 구현                                             |
|----------|------------------------------------------------|
| x86_64   | `asm!("", in("rax") &value)` + `read_volatile` |
| AArch64  | `asm!("", in("x0") &value)` + `read_volatile`  |
| fallback | `read_volatile(ptr)`                           |

## 소거 실행 순서

`zeroize_flat`, `Secret::drop`, `volatile_set` 모두 동일한 순서를 따릅니다.

```
1. compiler_barrier()       -> 컴파일러: 소거 이전 연산을 소거 블록 뒤로 이동 금지
2. write_volatile(ptr+i, 0) -> 실제 소거, 컴파일러 제거 불가
   (바이트 단위 순회)
3. compiler_barrier()       -> 컴파일러: 소거 이후 연산을 소거 블록 앞으로 이동 금지
4. atomic_compiler_fence()  -> SeqCst 컴파일러 수준 추가 차단
5. memory_barrier()         -> CPU: Out-of-Order 실행 및 캐시 지연 쓰기 플러시
6. black_box(ptr)           -> 포인터를 레지스터에 로드하여 최적화 최종 차단
```

---

## API

### `Zeroize` 트레이트

```rust
pub trait Zeroize {
    fn zeroize(&mut self);
}
```

`u8`~`u128`, `i8`~`i128`, `usize`, `isize`, `[T; N]`, `&mut [T]`에 구현되어 있습니다.

### `Secret<T>`

```rust
let key = Secret::new([0u8; 32]);
// 스코프 종료 시 Drop이 호출되어 내부 데이터를 자동 소거
```

`Drop` 구현이 위의 6단계 소거 순서를 수행합니다. `expose()` / `expose_mut()`로만 내부 값에 접근할 수 있어 실수로 평문이 노출되는 것을 방지합니다.

### `zeroize_flat<T>`

구조체와 같이 `Zeroize`가 구현되지 않은 임의의 `T`를 바이트 단위로 소거합니다.

> [!WARNING]
> `T`가 포인터를 포함하는 경우 포인터 자체만 소거되며 참조 대상은 소거되지 않으므로 주의하시기 바랍니다.

### `secure_zero`

```rust
pub unsafe fn secure_zero(dest: *mut u8, count: usize);
```

raw 포인터 기반의 바이트 배열 소거입니다. `no_std` 베어 메탈 환경에서 직접 버퍼를 소거할 때 사용합니다.

## `no_std` 호환성

외부 의존성 없이 `core` 크레이트만 사용합니다. `std` 없이 AMD64, AArch64, 베어메탈 환경 모두에서 동작하며, 아키텍처 탐지는 컴파일 타임 `cfg`로 처리됩니다.
