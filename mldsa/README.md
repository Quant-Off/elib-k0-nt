# ML-DSA 크레이트 (mldsa)

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)

`mldsa`는 [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)에 규정된 모듈 격자 기반 전자 서명 알고리즘(Module Lattice-based Digital Signature Algorithm, ML-DSA)의 순수 Rust 구현체입니다. 본 크레이트는 세 가지 파라미터 셋(ML-DSA-44/65/87)을 지원하며, 비밀 키 메모리 보호, 헤지드(hedged) 서명, 상수-시간 필드(field) 연산을 통해 부채널 공격을 방어합니다. 구현 범위는 pure ML-DSA이며, 사전 해시 변형(HashML-DSA)과 external-mu 인터페이스는 제공하지 않습니다.

## 보안 위협 모델

RSA 및 ECDSA와 같은 기존 전자 서명 알고리즘은 Shor 알고리즘을 구현한 양자 컴퓨터에 의해 다항식 시간 내 파훼됩니다. ML-DSA는 모듈 격자 위의 LWE(Learning With Errors) 문제와 SIS(Short Integer Solution) 문제의 계산적 난해성에 안전성을 근거하며, 현재 알려진 양자 알고리즘으로도 지수 시간이 소요됩니다.

구현 수준의 공격 표면은 세 가지입니다.
1. 비밀 키 메모리 노출
   - `s1`, `s2`, `t0`, `K`(서명 시드) 등 비밀 성분이 스왑 파일이나 코어 덤프에 유출될 수 있습니다. 이를 `Secret<T>` 래퍼의 Drop 시 자동 소거와 명시적 `zeroize()` 호출로 방어합니다(아래 '민감 데이터의 소거' 절 참고).
2. 서명 시 타이밍 공격(timing attack)
   - 비밀 성분에 의존하는 분기가 서명 키를 노출할 수 있습니다. 유한체 연산(`Fq::add`, `Fq::sub`, `Fq::mul`, `power2round` 등)은 [`constant-time`](../constant-time)의 상수-시간 선택 연산으로 구현됩니다.
3. nonce 재사용
   - 마스킹 벡터 `y`가 재사용되거나 노출되면 $z = y + c s_1$ 관계에서 비밀 키가 복원됩니다. 헤지드 서명 모드(`rnd <- RNG`)는 결정론적 모드의 fault 공격 내성 약화까지 함께 방어합니다.

## 파라미터 셋

NIST FIPS 204 Section 4에 정의된 세 가지 파라미터 셋을 지원합니다.

| 파라미터 셋    |  NIST 보안 카테고리  |  pk 크기 |  sk 크기 |  서명 크기 | λ (충돌 강도) |
|-----------|:--------------:|-------:|-------:|-------:|:---------:|
| ML-DSA-44 | 2 (AES-128 동급) | 1312 B | 2560 B | 2420 B |  128-bit  |
| ML-DSA-65 | 3 (AES-192 동급) | 1952 B | 4032 B | 3309 B |  192-bit  |
| ML-DSA-87 | 5 (AES-256 동급) | 2592 B | 4896 B | 4627 B |  256-bit  |

각 파라미터 셋은 행렬 차원 $(k, l)$, 비밀 계수 범위 $\eta$, 챌린지 다항식 가중치 $\tau$, 마스킹 범위 $\gamma_1$, 분해 범위 $\gamma_2$, 힌트 최대 가중치 $\omega$를 달리합니다. 컴파일 타임 const 제네릭으로 단형화(monomorphization)되어 런타임 오버헤드가 없습니다.

---

## 알고리즘 구현

모든 연산은 $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$, $q = 8380417$ 위에서 이루어지며, 다항식 곱셈은 NTT(Number-Theoretic Transform) 도메인에서 수행됩니다. 모듈 구성은 FIPS 204의 알고리즘 역할을 따릅니다.

| 모듈          | FIPS 204 대응                                        | 책임                            |
|-------------|----------------------------------------------------|-------------------------------|
| `keys.rs`   | Algorithm 1/6 (KeyGen), Algorithm 35 (Power2Round) | 키 생성, sk/pk 인코딩·디코딩           |
| `sign.rs`   | Algorithm 2/7 (Sign), Algorithm 3/8 (Verify)       | 서명·검증, Decompose/Hint 계열      |
| `sample.rs` | Algorithm 29~34 (Sampling)                         | ExpandA, ExpandS, ExpandMask, SampleInBall |
| `pack.rs`   | Algorithm 16~23 (Encoding)                         | BitPack/BitUnpack, HintBitPack/Unpack |
| `ntt.rs`    | Algorithm 41/42 (NTT/NTT⁻¹)                        | 256-포인트 NTT, ζ 테이블            |
| `field.rs`  | -                                                  | $\mathbb{Z}_q$ 상수-시간 산술 (Montgomery 곱셈) |

### 키 생성 (Algorithm 6, `ML-DSA.KeyGen_internal`)

32바이트 시드 $\xi$에서 결정론적으로 키 쌍을 유도합니다.

1. $(\rho, \rho', K) \leftarrow \text{SHAKE256}(\xi \| k \| l)$ 으로 128바이트를 확장합니다. 도메인 분리 바이트 $k, l$ 포함은 파라미터 셋 간 시드 재사용 공격을 차단합니다.
2. 공개 행렬 $\hat{A} \in R_q^{k \times l}$를 $\rho$로부터 SHAKE128 거부 샘플링(`RejNTTPoly`)으로 생성합니다. 행렬은 NTT 도메인에서 직접 샘플링되므로 변환 비용이 없습니다.
3. 비밀 벡터 $s_1 \in R_q^l$, $s_2 \in R_q^k$를 $\rho'$로부터 SHAKE256 거부 샘플링(`RejBoundedPoly`, 계수 범위 $[-\eta, \eta]$)으로 생성합니다.
4. $t = \text{NTT}^{-1}(\hat{A} \circ \text{NTT}(s_1)) + s_2$를 계산하고, `Power2Round`($d = 13$)로 상위 비트 $t_1$(공개)과 하위 비트 $t_0$(비밀)로 분해합니다.
5. 공개 키는 $(\rho, t_1)$, 비밀 키는 $(\rho, K, tr, s_1, s_2, t_0)$이며 $tr = \text{SHAKE256}(pk)$ 입니다.

### 서명 (Algorithm 7, `ML-DSA.Sign_internal`)

Fiat-Shamir with Aborts 구조의 거부 샘플링 루프입니다.

1. 메시지 표현자 $\mu = \text{SHAKE256}(tr \| M')$, 마스킹 시드 $\rho'' = \text{SHAKE256}(K \| rnd \| \mu)$를 유도합니다. `rnd`가 RNG 출력이면 헤지드, 0이면 결정론적 서명입니다.
2. 루프 반복마다 마스킹 벡터 $y \leftarrow \text{ExpandMask}(\rho'', \kappa)$를 생성하고 $w = \text{NTT}^{-1}(\hat{A} \circ \text{NTT}(y))$, $w_1 = \text{HighBits}(w)$를 계산합니다.
3. 챌린지 $\tilde{c} = \text{SHAKE256}(\mu \| w_1)$에서 `SampleInBall`로 $\tau$개 계수가 $\pm 1$인 희소 다항식 $c$를 만들고 $z = y + c s_1$을 계산합니다.
4. $\lVert z \rVert_\infty \ge \gamma_1 - \beta$ 또는 $\lVert \text{LowBits}(w - c s_2) \rVert_\infty \ge \gamma_2 - \beta$ 이면 해당 반복의 비밀 중간값을 전부 소거하고 $\kappa$를 증가시켜 재시도합니다. 이 거부 검사가 서명 분포에서 비밀 키 의존성을 제거하는 핵심입니다.
5. 검증자 보정용 힌트 $h = \text{MakeHint}(-c t_0,\ w - c s_2 + c t_0)$를 만들고, $\lVert c t_0 \rVert_\infty \ge \gamma_2$ 또는 힌트 개수가 $\omega$를 초과하면 역시 재시도합니다.
6. 서명은 $(\tilde{c}, z, h)$ 입니다. 루프는 최대 1,000회로 제한되며(FIPS 204 Table 2 기준 평균 반복 횟수는 4.25/5.1/3.85회) 초과 시 `Error::SigningFailed`를 반환합니다.

### 검증 (Algorithm 8, `ML-DSA.Verify_internal`)

1. `sigDecode`가 서명 구조를 검증합니다. 특히 `HintBitUnpack`(Algorithm 21)은 힌트 인덱스의 순증가, 누적 한도, 잔여 바이트의 0 패딩을 모두 검사하여 서명 가단성(malleability)을 차단합니다. 형식 위반은 즉시 검증 실패입니다.
2. $w'_{approx} = \hat{A} \circ \text{NTT}(z) - \text{NTT}(c) \circ \text{NTT}(t_1 \cdot 2^d)$를 계산하고, $w'_1 = \text{UseHint}(h, \text{NTT}^{-1}(w'_{approx}))$로 서명자의 $w_1$을 복원합니다.
3. $\lVert z \rVert_\infty < \gamma_1 - \beta$ 검사 후 $\tilde{c}' = \text{SHAKE256}(\mu \| w'_1)$를 재계산하여 $\tilde{c}$와 비교합니다. 비교는 XOR 누적 방식의 상수-시간 바이트 비교(`ct_eq_bytes`)로 수행합니다.

공개 API(`MLDSA44::sign/verify` 등)는 FIPS 204 Algorithm 2/3에 따라 $M' = 0x00 \| |ctx| \| ctx \| M$ 형식으로 컨텍스트(최대 255바이트)를 바인딩합니다. 길이가 고정된 입력(pk, sk, 서명, 시드)은 전부 고정 크기 배열 참조(`&[u8; N]`)로 받으므로 잘못된 길이는 타입 시스템이 컴파일 단계에서 차단합니다.

---

## 저수준 (어셈블리) 관점

`mldsa` 자체는 인-라인 어셈블리를 포함하지 않습니다. 대신 비밀 의존 연산을 [`constant-time`](../constant-time)과 [`zeroize`](../zeroize)의 검증된 저수준 프리미티브에 위임하고, 그 보장을 그대로 상속합니다. 두 크레이트 모두 검증된 인-라인 어셈블리가 없는 아키텍처를 컴파일 게이트로 거부하므로, `mldsa`의 지원 타겟도 x86_64와 aarch64로 한정됩니다.

### 상수-시간 필드 산술의 기계어 수준 동작

$\mathbb{Z}_q$ 산술의 조건부 보정(reduction)은 비밀 값에 의존하는 분기를 만들 수 있는 유일한 지점입니다. 이 구현은 모든 보정을 `i32::select`(내부적으로 `ct_sel32`)로 처리하며, 해당 프리미티브는 데이터 독립 지연 명령만 사용합니다.

| 연산                          | x86_64            | aarch64        |
|-----------------------------|-------------------|----------------|
| 조건 선택 (`Fq::add/sub` 보정)    | `test` + `cmovnz` | `cmp` + `csel` |
| 부호 판정 (`is_negative_ct`)    | `sar` 산술 시프트      | `asr` 산술 시프트   |

- `Fq::add`는 $a + b - q$를 무조건 계산한 뒤 부호 비트(`(v >> 31) & 1`)로 두 후보 중 하나를 `cmov`/`csel`로 고릅니다. 조건 분기(`jcc`, `b.cc`)가 생성되지 않습니다.
- `Fq::mul`은 $R = 2^{32}$ Montgomery REDC로 구현됩니다. 64비트 곱셈 명령(x86_64 `imul`, aarch64 `mul`/`smulh`)은 두 타겟 모두 피연산자 값과 무관한 고정 지연입니다. 다만 ISA 차원의 보장(aarch64 DIT, x86 DOITM)은 `constant-time` 크레이트와 동일하게 향후 하드닝 과제로 남아 있습니다.
- NTT 버터플라이의 메모리 접근 인덱스는 공개 루프 변수와 사전 계산된 ζ 테이블 인덱스뿐이므로, 비밀 의존 캐시 타이밍이 발생하지 않습니다.
- 비밀 계수의 직렬화(`BitPack`)는 `fq_to_signed_ct`가 `wrapping_sub`와 부호 비트 마스크만으로 부호 변환을 수행하여 패킹 경로에도 분기가 없습니다.

거부 샘플링 루프의 노름 검사와 채택 여부 분기는 비밀 값에서 파생되지만, 거부된 후보는 즉시 소거되고 외부로 노출되지 않으며 채택 여부 자체는 공개 정보(서명 출력 시점)입니다. 이는 FIPS 204의 Fiat-Shamir with Aborts 설계가 의도한 동작입니다.

### 소거의 기계어 수준 동작

일반 대입(`buf = [0; N]`)은 컴파일러가 dead store로 제거할 수 있습니다. `zeroize`는 모든 소거를 `write_volatile` 기반으로 수행하고, 아키텍처별 배리어로 스토어의 생존과 완료를 강제합니다.

| 단계        | x86_64                  | aarch64                 |
|-----------|-------------------------|-------------------------|
| 휘발성 store | `write_volatile` (제거 불가) | `write_volatile` (제거 불가) |
| 컴파일러 배리어  | 빈 `asm!` + `compiler_fence(SeqCst)` | 빈 `asm!` + `compiler_fence(SeqCst)` |
| CPU 메모리 배리어 | `mfence`                | `dsb sy`                |

릴리즈 바이너리에서 zero-store와 배리어 명령(aarch64 기준 `strb wzr` + `dsb sy`)이 LTO 이후에도 살아남는 것은 zeroize 크레이트의 별도 probe 빌드로 검증되어 있습니다.

---

## 민감 데이터의 소거

이 크레이트의 모든 비밀 성분은 두 겹으로 소거됩니다. 장기 보관 값은 `Secret<T>` RAII 래퍼가 Drop 시점에 자동 소거하고, `Poly`/`PolyVec`의 `Copy` 시맨틱 때문에 래퍼 밖에 남는 스택 사본은 명시적 `zeroize()`로 즉시 소거합니다.

| 비밀 값                                  | 위치                | 소거 방식                                   |
|---------------------------------------|-------------------|-----------------------------------------|
| $s_1, s_2, t_0$, $K$                  | `PrivateKey` 필드   | `Secret<T>` Drop 자동 소거                  |
| $\mu, \rho''$                         | 서명 중 스택           | `Secret<T>` Drop 자동 소거                  |
| $\xi$ 확장 버퍼, $\rho'$, $K$ 지역 사본       | 키 생성 중 스택         | 반환 직전 명시적 `zeroize()`                   |
| NTT 적용된 $s_1$ 사본, $t = A s_1 + s_2$   | 키 생성 중 스택         | 반환 직전 명시적 `zeroize()`                   |
| $y, \hat{y}, w, c s_1, z, c s_2, r_0$ | 서명 거부 루프          | 거부·채택 모든 경로에서 반복 종료 전 명시적 `zeroize()`   |
| $c t_0$, 힌트 계산 중간값                    | 서명 거부 루프          | 거부·채택 모든 경로에서 반복 종료 전 명시적 `zeroize()`   |
| $\hat{s}_1, \hat{s}_2, \hat{t}_0$     | 서명 함수 전역          | 성공 반환·실패 경로 모두에서 명시적 `zeroize()`        |

설계 원칙은 다음과 같습니다.

- **거부 루프의 모든 탈출 경로에서 소거.** 노름 검사 실패로 `continue`하는 두 경로, 서명 채택 후 반환하는 경로 모두에서 해당 반복의 비밀 중간값을 소거합니다. 거부된 $y$와 $z$는 한 쌍만 노출되어도 $z - y = c s_1$ 관계로 비밀 키 복원에 직결되므로 가장 민감한 값입니다.
- **`Copy` 잔존 사본 직접 소거.** `Secret::new(v)`는 `v`의 복사본을 보호할 뿐 원본 스택 슬롯을 소거하지 않습니다. 키 생성은 `Secret` 래핑 직후 원본(`s2pv`, `t0pv`, NTT된 `s1` 등)을 명시적으로 소거합니다.
- **공개 값은 소거하지 않음.** $\rho$, $t_1$, $tr$(공개 키의 해시), $w_1$, $\tilde{c}$는 공개 성분이므로 소거 대상이 아닙니다.

검증 경로는 공개 입력(pk, 서명, 메시지)만 다루므로 소거가 필요한 비밀이 존재하지 않습니다.

---

## KAT 검증

자가 일관성 테스트(자기 서명을 자기가 검증)는 인코딩 버그를 탐지하지 못합니다. pack/unpack이 서로 역함수이기만 하면 비표준 직렬화도 라운드트립을 통과하기 때문입니다. 따라서 본 크레이트는 외부 공식 벡터로 바이트 단위 일치를 검증합니다.

| 검증 항목                       | 출처                                                              | 결과                                |
|-----------------------------|-----------------------------------------------------------------|-----------------------------------|
| keyGen (44/65/87)           | [NIST ACVP](https://github.com/usnistgov/ACVP-Server) FIPS204   | 75/75 (pk·sk 바이트 정확 일치)           |
| verify 유효 서명 (44/65/87)     | [Wycheproof](https://github.com/C2SP/wycheproof) testvectors_v1 | 226/226 수락                        |
| verify 무효 서명 (44/65/87)     | Wycheproof testvectors_v1                                       | 391/391 거부 (가단성·경계값·컨텍스트 변조 포함)   |
| sigGen 결정론적 (44)            | Wycheproof testvectors_v1                                       | 73/73 (서명 바이트 정확 일치)              |

ACVP keyGen 첫 벡터(파라미터 셋별 1건)는 `tests/mldsa_test.rs`에 회귀 테스트로 상주합니다.

## 발견한 문제와 조치

위 KAT 검증 과정(2026-06-10)에서 발견되어 수정된 문제를 기술합니다. 두 문제 모두 자가 일관성 테스트는 통과하면서 표준 비적합 상태를 만들었다는 공통점이 있으며, 외부 벡터 검증이 없었다면 발견되지 않았을 결함입니다.

### CoeffFromHalfByte의 η=2 경로 오구현 (해결)

`RejBoundedPoly`(Algorithm 31)의 half-byte 변환이 FIPS 204 Algorithm 14와 다르게 구현되어 있었습니다. 기존 코드는 η 값과 무관하게 `z <= 2η`이면 `η - z`를 채택했는데, 표준은 η=2일 때 `b < 15`에 대해 `2 - (b mod 5)`를 요구합니다. 채택 조건과 계수 공식이 모두 달라 ML-DSA-44/87(η=2)의 비밀 벡터 $s_1, s_2$ 분포 자체가 표준과 어긋났습니다. η=4 경로는 두 정의가 우연히 일치하여 ML-DSA-65의 공개 키만 ACVP 벡터와 일치했고, 이것이 원인 격리의 결정적 단서였습니다.

#### 해결

`coeff_from_half_byte::<const ETA: i32>`를 Algorithm 14 그대로 구현하여 교체했습니다. 거부 조건(η=2에서 `b >= 15`)이 mod 5 축소보다 먼저 적용되므로 출력 분포가 $[-2, 2]$ 균등으로 복원되었습니다.

### BitPack 부호 규칙 위반 (해결)

`BitPack`/`BitUnpack`(Algorithm 16/18)은 범위 $[-a, b]$의 계수 $w$를 `b - w`로 인코딩해야 하지만, 기존 구현은 `a + w`를 사용했습니다. pack과 unpack이 서로 정확한 역함수였기 때문에 자가 라운드트립과 자기 서명 검증은 전부 통과했지만, $s_1, s_2, t_0$(비밀 키)와 $z$(서명)의 직렬화가 비표준이어서 표준 구현체와 키·서명을 교환하면 전면 실패하는 상태였습니다. 실측으로는 Wycheproof 유효 서명 226건이 전부 거부되고 ACVP keyGen 75건이 전부 불일치했습니다.

#### 해결

인코딩을 `b - w`, 디코딩을 `b - encoded`로 정정했습니다. 비트폭 계산(`bitlen(a + b)`)은 영향이 없으므로 서명·키 길이는 변하지 않습니다. 수정 후 위 KAT 표의 전 항목이 통과했으며, 거부 루프 소거 보강과 `K` 시드의 `Secret` 래핑이 같은 패치로 함께 적용되었습니다.

---

## 오류 타입

모든 오류 변형은 `Copy`이며 할당과 문자열 메시지가 없습니다.

| 변형               | 발생 조건                                       |
|------------------|---------------------------------------------|
| `ContextTooLong` | 컨텍스트 문자열이 255바이트 초과                         |
| `InvalidLength`  | 메시지와 컨텍스트 합이 내부 버퍼(1024바이트) 초과              |
| `SigningFailed`  | 거부 샘플링 1,000회 초과 (확률적으로 사실상 도달 불가)          |
| `InternalError`  | XOF 출력 고갈 등 내부 샘플링 실패 (정상 입력에서는 도달 불가)      |

검증 실패는 오류가 아니라 `Ok(false)`로 반환됩니다. 형식 위반 서명(힌트 가단성 포함)과 암호학적 불일치를 호출자가 구분할 필요가 없도록 동일하게 처리합니다.

## 사용법

```rust
use mldsa::MLDSA65;

// 키 생성 (xi는 32바이트 시드, 반드시 암호학적 RNG로 생성)
let xi: [u8; 32] = /* RNG */;
let (pk, sk) = MLDSA65::keygen(&xi)?;

// 헤지드 서명 (rnd 역시 RNG 출력 권장, 결정론적 서명은 [0u8; 32])
let rnd: [u8; 32] = /* RNG */;
let ctx = b"";
let sig = MLDSA65::sign(&sk, b"message", ctx, &rnd)?;

// 검증
assert!(MLDSA65::verify(&pk, b"message", &sig, ctx)?);
```

시드 `xi`와 `rnd`는 워크스페이스의 [`rng`](../rng) 크레이트(NIST SP 800-90A Hash_DRBG)로 생성할 수 있습니다. `sk` 바이트 배열은 사용 후 호출자가 직접 `zeroize()` 해야 합니다. 크레이트 내부는 트랜잭션 단위로 모든 비밀 중간값을 소거하지만, 호출자가 보유한 키 사본까지 책임지지 않습니다.
