# ML-DSA 크레이트 (mldsa)

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)

`mldsa`는 [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)에 규정된 모듈 격자 기반 전자 서명 알고리즘(Module Lattice-based Digital Signature Algorithm, ML-DSA)의 순수 Rust 구현체입니다. 본 크레이트는 세 가지 파라미터 셋(ML-DSA-44/65/87)을 지원하며, 비밀 키 메모리 보호, 헤지드(hedged) 서명, 상수-시간 필드(field) 연산을 통해 부채널 공격을 방어합니다.

## 보안 위협 모델

RSA 및 ECDSA와 같은 기존 전자 서명 알고리즘은 Shor 알고리즘을 구현한 양자 컴퓨터에 의해 다항식 시간 내 파훼됩니다. ML-DSA는 모듈 격자 위의 LWE(Learning With Errors) 문제와 SIS(Short Integer Solution) 문제의 계산적 난해성에 안전성을 근거하며, 현재 알려진 양자 알고리즘으로도 지수 시간이 소요됩니다.

구현 수준의 공격 표면은 세 가지입니다. 
1. 비밀 키 메모리 노출
   - `s1`, `s2`, `t0`, `K_seed`, `tr` 등 비밀 성분이 스왑 파일이나 코어 덤프에 유출될 수 있습니다. 이를 Drop 시 자동 소거로 방어합니다. 
2. 서명 시 타이밍 공격(timing attack)
   - 비밀 성분에 의존하는 분기가 서명 키를 노출할 수 있습니다. 유한체 연산(`Fq::add`, `Fq::sub`, `power2round` 등)은 [`constant-time`](../constant-time)의 상수-시간 선택 연산으로 구현됩니다.
3. nonce 재사용
   - 동일한 `rnd`로 두 개의 서명을 생성하면 비밀 키가 복원됩니다. 헤지드 서명 모드(`rnd ← RNG`)로 이를 완전히 방지합니다.

## 파라미터 셋

NIST FIPS 204 Section 4에 정의된 세 가지 파라미터 셋을 지원합니다.

| 파라미터 셋    |  NIST 보안 카테고리  |  pk 크기 |  sk 크기 |  서명 크기 | λ (충돌 강도) |
|-----------|:--------------:|-------:|-------:|-------:|:---------:|
| ML-DSA-44 | 2 (AES-128 동급) | 1312 B | 2560 B | 2420 B |  128-bit  |
| ML-DSA-65 | 3 (AES-192 동급) | 1952 B | 4032 B | 3309 B |  192-bit  |
| ML-DSA-87 | 5 (AES-256 동급) | 2592 B | 4896 B | 4627 B |  256-bit  |

각 파라미터 셋은 행렬 차원 $(k, l)$, 비밀 계수 범위 $\eta$, 챌린지 다항식 가중치 $\tau$, 마스킹 범위 $\gamma_1$, 분해 범위 $\gamma_2$, 힌트 최대 가중치 $\omega$를 달리합니다. 컴파일 타임 const 제네릭으로 단형화(monomorphization)되어 런타임 오버헤드가 없습니다.

## 오류 타임

## 사용법

