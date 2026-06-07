# 상수-시간 (Constant-Time, CT) 모듈

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)

암호화에는 상수-시간 로직이 매우 중요합니다. 이 문서는 이 프로젝트에서 상수-시간이 어떻게 동작하는지에 대해 기술적으로 설명합니다.

---

## 구현된 프리미티브

이 크레이트는 비밀 값에 의존하는 분기나 데이터 의존 메모리 접근 없이 동작하는 정수 연산을 제공합니다. 공개 API는 `Choice` 타입과 네 개의 트레이트로 구성됩니다.

- `Choice`: 항상 0 또는 1 값을 갖는 상수-시간 bool. `&`, `|`, `^`, `!` 비트 연산이 정규화 없이 0/1 불변을 보존하며, 민감 값 유출(CWE-532) 방지를 위해 `Debug`를 의도적으로 파생하지 않습니다.
- `CtSelOps`: 조건 선택(`select`), 조건 대입(`assign`), 조건 교환(`swap`).
- `CtEqOps`: 동등 비교(`eq`, `ne`).
- `CtGreeter`: 대소 비교(`gt`).
- `CtLess`: 작음 비교(`lt`). `CtEqOps + CtGreeter`를 만족하는 모든 타입에 `!gt & !eq`로 자동 제공됩니다.

네 가지 트레이트는 고정폭 정수 `u8`부터 `i128`까지에 구현되며, `Sealed`로 봉인되어 외부 타입이 끼어들 수 없습니다. 각 구현은 `internal` 모듈의 저수준 프리미티브에 위임합니다.

- 선택: `ct_sel32`, `ct_sel64`
- 동등: `ct_eq32`, `ct_eq64`, `ct_eq128`
- 대소: `ct_gt_u32`, `ct_gt_u64`, `ct_gt_i64`, `ct_gt_u128`, `ct_gt_i128`

작은 타입은 호출 전에 32 또는 64비트로 영(zero) 확장 또는 부호 확장하고, 128비트 연산은 64비트 프리미티브 위에 상위 절반과 하위 절반을 결합하여 구성합니다.

## 상수-시간 보장 근거

상수-시간 성질은 세 겹으로 보장됩니다.

### 1. 데이터 독립 명령만 사용

x86_64와 aarch64에서 각 프리미티브는 인-라인 어셈블리로 직접 작성되며, 피연산자 값과 무관하게 고정 사이클로 실행되는 명령만 사용합니다.

| 연산        | x86_64            | aarch64           |
|-----------|-------------------|-------------------|
| 선택        | `test` + `cmovnz` | `cmp` + `csel`    |
| 동등        | `cmp` + `sete`    | `cmp` + `cset eq` |
| 대소(부호 없음) | `cmp` + `seta`    | `cmp` + `cset hi` |
| 대소(부호 있음) | `cmp` + `setg`    | `cmp` + `cset gt` |

`mul`, `div`나 조건 분기 같은 고전적 가변-시간 명령을 일절 쓰지 않습니다. `cmov`, `csel`, `setcc`, `cset`은 플래그 레지스터를 읽어 결과를 만들 뿐 지연 시간이 데이터에 의존하지 않습니다.

### 2. 레지스터 전용, 메모리·스택 비접근

모든 asm 블록은 피연산자를 레지스터로만 받고 `options(nomem, nostack)`을 지정합니다. 메모리에 접근하지 않으므로 비밀 의존 캐시 및 TLB 타이밍이 생기지 않고, 스택 스필이 없으며, 비밀에 의존하는 분기가 존재하지 않습니다. 따라서 실행 시간이 비밀 값에 따라 달라질 경로가 원천적으로 없습니다.

### 3. Choice 0/1 불변

`Choice`는 `(v | v.wrapping_neg()) >> 7` 마스크로 분기 없이 0/1로 정규화되고, 비트 연산이 이 불변을 보존합니다. 덕분에 `lt = !gt & !eq` 같은 상위 조합도 분기 없이 유지됩니다.

추가로, 검증된 인-라인 어셈블리가 없는 아키텍처는 컴파일 게이트(`compile_error!`)로 거부되어 best-effort `black_box` fallback이 고보안 빌드에 섞이지 않습니다(아래 '발견한 문제와 조치' 절 참고). `swap`의 영점화 루프는 종료 조건이 `size_of::<Self>()`라는 컴파일타임 상수이므로 그 분기는 비밀에 의존하지 않습니다.

## 최적화기 검증 (llvm-objdump)

소스가 분기 없이 작성되어도, 최적화기(LLVM)가 패턴을 `select` 관용구로 재인식해 `cmov`나 분기를 재구성할 여지가 이론적으로 남습니다. 인-라인 어셈블리 경로는 어셈블리가 그대로 방출되므로 이 위험이 없지만, 회귀를 막고 주변 글루 코드까지 확인하기 위해 산출 바이너리를 정적으로 검증합니다.

`scripts/check_ct_asm.sh`가 이 과정을 자동화합니다.

1. `examples/ct_asm_probes.rs`를 호스트 타겟 release로 빌드합니다. 각 probe는 `#[unsafe(no_mangle)] extern "C"` + `#[inline(never)]`라 독립 심볼로 방출됩니다.
2. `llvm-objdump -d`로 디스어셈블(disassemble)합니다. macOS의 경우 `/Library/Developer/CommandLineTools/usr/bin/llvm-objdump`에 이 바이너리가 존재합니다.
3. 각 CT probe 심볼에서 조건 분기 명령(x86_64 `jcc`, `loop`, aarch64 `b.cc`, `cbz`, `cbnz`, `tbz`, `tbnz`)을 grep합니다. 하나라도 검출되면 FAIL입니다. 무조건 `jmp`, `b`(꼬리 호출)는 허용됩니다.
4. `swap` probe는 영점화 루프의 분기가 비밀 비의존이라 분기 검사를 건너뛰고, 대신 volatile 영점화 store가 살아남았는지(CWE-316 회귀)를 검증합니다.

예를 들어, aarch64에서 `u64::select`는 분기 없이 `csel` 하나로 값을 고르고 `ret`로 끝납니다.

```text
<_probe_sel_u64>:
	cmp	w0, #0x0
	cset	w8, ne
	cmp	w8, #0x0
	csel	x0, x2, x1, ne
	ret
```

전체 실행은 모든 probe가 조건 분기 없이 통과함을 보고합니다.

```text
>> CT primitive probe (조건분기 부재)
    PASS probe_sel_u64
    PASS probe_eq_u64
    PASS probe_gt_u64
    ...
>> swap probe (volatile zero store 잔존만 검증)
    PASS probe_swap_u64 — zero store 1 건 잔존
RESULT: PASS — 모든 probe 가 조건분기 부재 + 영점화 보존
```

단일 심볼을 직접 확인하려면 다음과 같이 디스어셈블합니다.

```bash
llvm-objdump -d --no-show-raw-insn target/<호스트-트리플>/release/examples/ct_asm_probes
```

---

## 발견한 문제와 조치

구현된 상수-시간 로직에 존재하는 문제와 해결을 기술합니다.

### Fallback 경로의 `black_box` 의존 문제 (해결)

`black_box`는 Rust 공식적으로 ["최적화 배리어를 보장하지 않는다"](https://internals.rust-lang.org/t/optimization-barriers-suitable-for-cryptographic-use/21047)고 못박혀 있습니다. 컴파일러는 `black_box`를 통째로 무시할 자유가 있습니다만, `ct_sel64`, `ct_eq64`, `ct_mask`([internal.rs](src/internal.rs))가 아무리 `(m & a) | (!m & b)` 같은 분기 없이 작성되어 있어도 최적화기가 이 패턴을 `select` 관용구로 재인식해서 `cmov`나 최악의 경우 분기로 되돌릴 가능성을 언어 차원에서 막을 방법이 없습니다. 즉, "태생적 불확실성"이라 볼 수 있습니다. 이건 `black_box`의 설계 자체에서 오는 거라 코드를 더 잘 작성해도 해소가 안 됩니다.

하지만 다행히도, 산술 자체는 mul/div/branch 같은 고전적 가변-시간 명령을 사용하지 않고 AND/OR/shift/sub만 사용하여 잔여 리스크는 사실상 "최적화기가 분기를 재구성하는 경우" 하나로 좁혀져 있습니다.

`#[deprecated]` const 트릭, 각 함수 `# Security Note`까지 보면 알 수 있듯 코드의 '약함'은 저 또한 명확히 인지하고 있습니다. 문제는 이게 경고 수준이라는 것입니다. 따라서 제가 이 시점에 생각한 대안은 "인-라인 어셈블리 미지원 타겟은 `compiler_fence` fallback 또는 `Err(Unsupported)` 명시 반환"이며, 지원 타겟을 AMD64 + AArch64 둘로 결정하는 것입니다.

#### 해결

이 문제는 [PR #7](https://github.com/Quant-Off/elib-k0-nt/pull/7)에서 컴파일 게이트로 해결했습니다.

검증된 상수-시간 구현(인-라인 어셈블리)이 있는 x86_64와 aarch64만 지원 타겟으로 확정하고, 그 외 아키텍처의 miri가 아닌 빌드는 `compile_error!`로 컴파일 단계에서 거부합니다.

```rust
#[cfg(all(not(miri), not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
compile_error!("constant-time 의 검증된 상수-시간 구현은 x86_64와 aarch64 에서만 제공됩니다 ...");
```

이로써 기존 `#[deprecated]` 경고(soft)를 하드 게이트로 승격했고, best-effort `black_box` fallback이 고보안 빌드에 조용히 섞일 일이 없어졌습니다. `miri`는 인-라인 어셈블리를 실행하지 못하므로 fallback 로직 검증을 위해 예외로 둡니다. 실제로 `riscv64gc-unknown-none-elf` 빌드가 이 게이트 메시지로 거부되는 것을 확인했습니다.

남은 과제로, x86_64/aarch64의 `cmov`/`csel`이 ISA 차원에서 데이터 독립 시간을 보장받으려면 aarch64 DIT 비트와 x86 DOITM을 켜는 하드닝이 별도로 필요하며 이는 향후 다룰 예정입니다.

---

### swap 메모리 소거의 UB(Undefined Behavior) 위험 문제 (해결)

이 문제는 심각성이 높았습니다. `CtSelOps`는 `pub` 트레이트고, 바운드가 `: Copy` 하나뿐이었습니다. `Copy` 바운드가 막아주는 건 `Drop` 타입뿐이고(Copy와 Drop은 공존 불가), 니치(niche)를 가진 `Copy` 타입은 막지 못 합니다. 그래서 다음과 같이 확장한다면,

```rust
impl CtSelOps for SomeCopyTypeWithNiche { ... }
```

여기서 `SomeCopyTypeWithNiche가 &'static T`, `NonZeroU32`, `fn()`, `NonNull<T>`, 또는 이들을 필드로 가진 구조체라면, all-zero를 써넣는 순간 invalid value(null 참조, 0인 NonZero, null 함수 포인터)가 만들어지게 됩니다. Rust에서 **타입이 붙은 place가 invalid value를 보유하는 것 자체가 UB**입니다. "어차피 안 읽으니 괜찮다"는 엄격한 유효성 검사(strict validity) 기준에서 통하지 않습니다. `Copy` 바운드 덕분에 `Drop` 기반 변종은 이미 막혀 있었고 이는 레일이 하나는 있는 셈인데, 그것만으론 니치를 막을 순 없었습니다.

추가로, [커밋](https://github.com/Quant-Off/elib-k0-nt/tree/db229a365efdd4327b74b7c01c563820b566ae57)에서 `swap`의 [Safety docstring](https://github.com/Quant-Off/elib-k0-nt/blob/db229a365efdd4327b74b7c01c563820b566ae57/constant-time/src/lib.rs#L170-L182)은 `Self: Copy + Sized`만 근거로 건전성을 주장하는데, "all-zero가 Self의 유효한 값이어야 한다"는 전제를 명시하지 않아 살짝 과대 주장 상태이기도 했습니다.

#### 해결

이 문제는 [PR #6](https://github.com/Quant-Off/elib-k0-nt/pull/6)에서 (A) 트레이트 봉인(seal) 방식으로 해결했습니다.

`private` 모듈의 `Sealed` 마커 트레이트를 `CtSelOps`의 슈퍼트레이트로 지정하고, `Sealed`를 크레이트 내부의 고정폭 정수(`u8..i128`)에만 구현했습니다.

```rust
mod private {
    pub trait Sealed {}
}

pub trait CtSelOps: Copy + private::Sealed { /* ... */ }
```

이제 외부 크레이트는 자기 타입에 `CtSelOps`를 구현할 수 없으므로, `swap`이 소거하는 `Self`는 all-zero가 항상 유효한 고정폭 정수로 한정됩니다. 니치(niche) 타입이 끼어들 길이 사라져 invalid value UB가 구조적으로 불가능해지며, 소거 핫패스 코드는 한 줄도 바뀌지 않습니다. 더불어 `swap`의 `# Safety` 문서에 이 봉인 불변식을 명시하여 기존의 과대 주장도 함께 바로잡았습니다.
