# 상수-시간 (Constant-Time, CT) 모듈

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)

암호화에는 상수-시간 로직이 매우 중요합니다. 이 문서는 이 프로젝트에서 상수-시간이 어떻게 동작하는지에 대해 기술적으로 설명합니다.

---

## 발견한 문제와 조치

구현된 상수-시간 로직에 존재하는 문제와 해결을 기술합니다.

### Fallback 경로의 `black_box` 의존 문제 (예정)

`black_box`는 Rust 공식적으로 ["최적화 배리어를 보장하지 않는다"](https://internals.rust-lang.org/t/optimization-barriers-suitable-for-cryptographic-use/21047)고 못박혀 있습니다. 컴파일러는 `black_box`를 통째로 무시할 자유가 있습니다만, `ct_sel64`, `ct_eq64`, `ct_mask`([internal.rs](src/internal.rs))가 아무리 `(m & a) | (!m & b)` 같은 분기 없이 작성되어 있어도 최적화기가 이 패턴을 `select` 관용구로 재인식해서 `cmov`나 최악의 경우 분기로 되돌릴 가능성을 언어 차원에서 막을 방법이 없습니다. 즉, "태생적 불확실성"이라 볼 수 있습니다. 이건 `black_box`의 설계 자체에서 오는 거라 코드를 더 잘 작성해도 해소가 안 됩니다.

하지만 다행히도, 산술 자체는 mul/div/branch 같은 고전적 가변-시간 명령을 사용하지 않고 AND/OR/shift/sub만 사용하여 잔여 리스크는 사실상 "최적화기가 분기를 재구성하는 경우" 하나로 좁혀져 있습니다.

`#[deprecated]` const 트릭, 각 함수 `# Security Note`까지 보면 알 수 있듯 코드의 '약함'은 저 또한 명확히 인지하고 있습니다. 문제는 이게 경고 수준이라는 것입니다. 따라서 제가 이 시점에 생각한 대안은 "인-라인 어셈블리 미지원 타겟은 `compiler_fence` fallback 또는 `Err(Unsupported)` 명시 반환"이며, 지원 타겟을 AMD64 + AArch64 둘로 결정하는 것입니다. **추 후 PR을 통해 이러한 문제를 '게이트'로 명명짓고 강화를 수행하겠습니다.**

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
