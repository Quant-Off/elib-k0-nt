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

## 형식 모델

버퍼가 바이트 $p, p{+}1, \dots, p{+}n{-}1$을 차지한다고 합시다. 소거는 다음 store들의 집합입니다.

$$ W = \bigl\{\, \mathrm{mem}[p{+}i] \leftarrow 0 \;\bigm|\; 0 \le i < n \,\bigr\}. $$

**Dead Store Elimination.** 주소 $a$에 쓰는 store $s \in W$는, $a$가 덮어써지거나 그 저장 공간이 해제되기 전에 $a$에 대한 어떤 load도 $s$로부터 도달 불가능할 때 *죽은(dead)* store입니다.

$$ \mathrm{dead}(s) \iff \nexists\, \ell \in \mathrm{Loads}(a) \ \text{such that}\ s \prec \ell . $$

올바른 최적화기는 죽은 store를 삭제해도 프로그램의 관측 가능 동작 $\mathcal{O}$가 바뀌지 않으므로, 어떤 죽은 store든 삭제할 수 있습니다. 소거 이후 더 이상 사용되지 않는 비밀의 경우 $W$의 *모든* $s$가 죽은 store이므로, $W$는 DSE가 제거하도록 허용된 집합과 정확히 일치합니다. 이것이 암호 코드에서 최악의 경우입니다. 소거가 "쓸모없어" 보일수록 제거 대상이 되기 더 쉽습니다.

**Volatile가 DSE를 무력화.** volatile 접근은 정의상 $\mathcal{O}$의 원소입니다. 바이트 $i$의 volatile store를 $w^{\mathrm{vol}}_i$로 쓰면,

$$ w^{\mathrm{vol}}_i \in \mathcal{O} \quad\Longrightarrow\quad \forall\,\text{sound } \mathcal{T}:\; w^{\mathrm{vol}}_i \in \mathcal{T}(\mathcal{O}) . $$

죽은 store라는 전제가 무의미해집니다. 관측 가능한 부수 효과는 그 결과가 다시 읽히든 말든 보존됩니다. 이로써 "제거될 수 있음"이 "반드시 방출됨"으로 바뀝니다.

**순서.** 배리어들은 소거 연산에 전순서(total order)를 부여합니다.

$$ \mathrm{cb}_1 \;\prec\; w^{\mathrm{vol}}_0 \prec \dots \prec w^{\mathrm{vol}}_{n-1} \;\prec\; \mathrm{cb}_2 \;\prec\; \mathrm{acf} \;\prec\; \mathrm{mb} \;\prec\; \mathrm{bb}, $$

여기서 $\mathrm{cb}$는 컴파일러 배리어, $\mathrm{acf}$는 원자적 컴파일러 펜스, $\mathrm{mb}$는 CPU 메모리 배리어, $\mathrm{bb}$는 `black_box` 레지스터 고정입니다. $\mathrm{cb}_1$은 소거 이전 연산을 store 아래로 내리는 것을 막고, $\mathrm{cb}_2$와 $\mathrm{acf}$는 소거 이후 연산을 store 위로 올리는 것을 막으며, $\mathrm{mb}$는 확정된 store가 하드웨어에서 전역 가시화되도록 강제합니다.

## 어셈블리 수준 검증 (llvm-objdump)

volatile 의미론은 *언어 차원의* 계약입니다. 이 계약이 release 파이프라인 전체(`opt-level = "z"`, `lto = true`, `panic = "abort"`)를 거쳐 기계어까지 살아남는지 확인하기 위해, 산출된 바이너리를 디스어셈블하여 정적으로 검증합니다. 이는 constant-time 크레이트를 지키는 것과 동일한 하니스를 재사용합니다. `constant-time/scripts/check_ct_asm.sh`가 둘 다 구동하며, 그 `PROBES_ZEROIZE` 그룹이 이 크레이트를 담당합니다.

`zeroize/examples/zeroize_asm_probes.rs`의 probe 두 개는 각각 `#[unsafe(no_mangle)] extern "C"` + `#[inline(never)]`로 독립 심볼로 방출됩니다.

- `probe_zeroize_flat`은 64바이트 버퍼에 `zeroize_flat`을 실행합니다.
- `probe_secret_drop`은 `Secret<[u8; 32]>`를 생성하고 drop시킵니다.

constant-time probe와 달리, 소거 경로는 조건 분기 부재를 검사하지 **않습니다**. 루프 한계가 컴파일타임 상수 `size_of`이므로 루프 분기는 비밀에 의존하지 않고, 분기 검사는 오탐이 됩니다. 대신 각 zeroize probe는 두 술어를 동시에 만족해야 합니다.

$$ \#\{\text{volatile zero store}\} \ge 1 \quad\wedge\quad \#\{\text{memory fence}\} \ge 1 . $$

둘 중 하나라도 0이 되면 dead store 회귀(CWE-14 / CWE-316)가 끼어든 것이며 검사는 실패합니다. aarch64에서 영점화 store는 `strb wzr`, fence는 `dsb sy`이고, x86_64에서는 `mov $0` 계열 store와 `mfence`입니다.

호스트(`aarch64-apple-darwin`)에서 `probe_zeroize_flat`을 디스어셈블하면 `0x40 = 64`바이트에 대한 바이트 루프가 살아남은 fence와 `black_box` 꼬리 호출로 끝나는 것을 볼 수 있습니다(라벨 축약, 주석 추가).

```text
<_probe_zeroize_flat>:
    mov     x8, #0x0
    cmp     x8, #0x40            ; i == 64 ? (카운터 한계, 비밀 아님)
    b.eq    <+0x18>              ; 루프 종료
    strb    wzr, [x0, x8]        ; volatile store: mem[p+i] <- 0  (DCE 생존)
    add     x8, x8, #0x1
    b       <+0x4>
    dsb     sy                   ; memory_barrier(): 하드웨어에서 store 확정
    b       <zeroize::barrier::aarch64::black_box>
```

`probe_secret_drop`은 32바이트 비밀을 스택에 구성하고(`dup.16b` + `stp q0, q0`), 같은 volatile 루프로 소거한 뒤 fence와 `black_box` 고정을 방출합니다.

```text
<_probe_secret_drop>:
    ...
    dup.16b v0, w0               ; secret = [seed; 32]
    stp     q0, q0, [sp]
    ...
    cmp     x8, #0x20            ; i == 32 ?
    b.eq    <+0x38>
    strb    wzr, [x9, x8]        ; volatile 바이트 소거
    add     x8, x8, #0x1
    b       <+0x24>
    dsb     sy                   ; memory_barrier()
    mov     x0, sp
    bl      <zeroize::barrier::aarch64::black_box>
    ...
    ret
```

전체 실행은 두 probe 모두 store와 fence를 보존함을 보고합니다.

```text
>> zeroize probe (별도 크레이트 — zero store + fence 잔존 검증)
    PASS probe_secret_drop — zero store 1 건 + fence 1 건 잔존
    PASS probe_zeroize_flat — zero store 1 건 + fence 1 건 잔존
RESULT: PASS — 모든 probe 가 조건분기 부재 + 영점화 보존
```

단일 심볼을 직접 확인하려면 다음과 같이 디스어셈블합니다.

```bash
llvm-objdump -d --no-show-raw-insn target/<호스트-트리플>/release/examples/zeroize_asm_probes
```

macOS의 경우 이 바이너리는 `/Library/Developer/CommandLineTools/usr/bin/llvm-objdump`에 있습니다.

### 반례: DSE의 실제 동작

DSE는 *허용된* 변환이며, 최적화기가 이를 실제로 수행할지는 opt-level, 컴파일러 버전, 주변 코드에 달려 있습니다. 그 예측 불가능성이 바로 위험입니다. 아래 대조가 그 자유를 구체적으로 보여줍니다. 두 함수는 체크섬을 읽은 직후 죽는 32바이트 스택 비밀을 소거하는데, 하나는 단순 store, 다른 하나는 `ptr::write_volatile`을 씁니다. `opt-level = 3`으로 빌드한 결과입니다.

```text
<_naive_wipe_dead>:                  ; 단순 `*b = 0`
    ubfiz   w0, w0, #5, #3           ; 체크섬 반환 (32*seed mod 256)
    ret                              ; 버퍼 + 32개 store 전부 제거 (store 0개)

<_volatile_wipe_dead>:               ; ptr::write_volatile(.., 0)
    sub     sp, sp, #0x20
    strb    wzr, [sp, #0x1f]         ; 32개 volatile store, 전부 보존
    strb    wzr, [sp, #0x1e]
    ...                              ; (총 32개)
    strb    wzr, [sp, #0x1]
    ubfiz   w0, w0, #5, #3
    strb    wzr, [sp], #0x20
    ret
```

단순 버전은 두 명령으로 줄어듭니다. 최적화기가 버퍼를 죽었다고 증명하고 32개 store를 전부 삭제했으므로, 비밀의 바이트는 스택에 그대로 남게 됩니다. volatile 버전은 모든 store를 유지합니다. 이 동일한 단순 루프가 `opt-level = "z"`에서는 우연히 살아남지만 `opt-level = 3`에서는 사라진다는 점에 주목하십시오. 비-volatile 소거의 생존은 어떤 최적화 수준에서도 보장되지 않습니다. 따라서 이 크레이트는 최적화기의 재량에 결코 기대지 않습니다. volatile과 배리어가 프로젝트 자신의 `opt-level = "z"`를 포함한 모든 opt-level에서 소거가 살아남도록 강제합니다.

### 런타임 readback 검증

정적 검사는 store가 *방출됨*을 증명하고, `zeroize/tests/zeroize_readback.rs`는 store가 *효력을 가짐*을 증명합니다. 각 테스트는 0이 아닌 패턴을 쓰고, raw 주소를 확보하고, 소거(`Secret::drop`, `zeroize_flat`, `[T; N]::zeroize`, `&mut [T]::zeroize`)를 유발한 뒤, 같은 주소를 되읽어 모든 바이트가 0인지 단언합니다.

```text
running 5 tests
test secret_array_zeroized_on_drop ... ok
test secret_into_inner_extracts_value ... ok
test zeroize_flat_wipes_bytes ... ok
test array_zeroize_wipes ... ok
test slice_zeroize_wipes ... ok
test result: ok. 5 passed
```

두 계층이 함께 고리를 닫습니다. readback은 *실행 시* 소거가 올바름을 확인하고, llvm-objdump 검사는 최적화기가 출하 바이너리에서 소거를 조용히 제거할 수 없음을 확인합니다.

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
