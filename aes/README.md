# AES-256 모듈

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)

FIPS 197 AES-256 블록 암호와 NIST SP 800-38A(CBC·CTR), SP 800-38D(GCM) 운용 모드를 외부 의존성 없이 `no_std` 순수 Rust로 구현한 크레이트입니다. 이 문서는 기능 명세와 보안 설계 근거, 그리고 1.1.0 교차 검증에서 발견한 문제와 조치를 기술합니다.

---

## 구현된 프리미티브

| 타입          | 표준         | 설명                                      |
|-------------|------------|-----------------------------------------|
| `AES256`    | FIPS 197   | 단일 16바이트 블록 암·복호화. 라운드 키는 `Secret`으로 보호 |
| `AES256CBC` | SP 800-38A | 패딩 없는 CBC 모드. 입력은 16바이트 배수여야 함          |
| `AES256CTR` | SP 800-38A | 카운터 모드. 96비트 nonce 또는 128비트 IV 초기화      |
| `AES256GCM` | SP 800-38D | 인증 암호화(AEAD). 96비트 nonce, 128비트 태그      |
| `GHash`     | SP 800-38D | GF(2^128) 인증 해시. GCM 내부에서 사용            |

크기 상수는 `KEY_SIZE = 32`, `BLOCK_SIZE = 16`, `CBC_IV_SIZE = 16`, `CTR_NONCE_SIZE = 12`, `CTR_IV_SIZE = 16`, `GCM_NONCE_SIZE = 12`, `GCM_TAG_SIZE = 16`으로 고정되며, 키·nonce·태그 길이는 타입(`&[u8; N]`)으로 강제되어 길이 오류가 컴파일 단계에서 차단됩니다.

설계 결정 명세는 다음과 같습니다.

- 키는 AES-256(256비트)만 지원합니다. AES-128/192는 의도적으로 제공하지 않습니다.
- GCM nonce는 96비트 고정입니다. 비-96비트 IV의 GHASH 기반 J0 유도는 구현하지 않습니다(SP 800-38D 권장 구성).
- GCM 태그는 128비트 전체 길이만 지원합니다. 절단 태그를 막아 위조 확률 상한을 보존합니다.
- GCM 복호화는 태그 검증이 성공하기 전까지 평문을 단 한 바이트도 출력 버퍼에 기록하지 않습니다(SP 800-38D 7.2절).
- CTR `apply`는 카운터 블록을 `nonce || 0x00000001`로 초기화하고 하위 32비트만 inc32로 증가시킵니다.
- 입력 길이 한계를 코드로 강제합니다. GCM 평문 2^39-256 비트, GCM AAD 2^64-1 비트, CTR 입력 2^32 블록. 위반 시 `assert!`가 즉시 중단시킵니다(`panic = "abort"`).
- 모든 버퍼는 고정 크기 스택 배열입니다. `alloc`을 사용하지 않습니다.

## 상수-시간 보장 근거

### 1. 비트슬라이스 Boyar-Peralta S-box

S-box를 룩업 테이블 없이 약 115개의 AND/XOR/NOT 게이트 회로로 계산합니다. 16바이트 블록을 `[u32; 8]` 비트 평면으로 변환해 한 번의 회로 통과로 SubBytes를 일괄 처리하며, 비밀 의존 분기와 비밀 의존 메모리 접근이 전혀 없어 캐시·TLB 타이밍 부채널이 원천 차단됩니다. 회로 출처는 Boyar & Peralta(2010)이며 BearSSL `aes_ct.c`와 동일한 회로입니다.

역 S-box는 항등식 `InvSBox(y) = Affine^-1(SBox(Affine^-1(y)))`로 정방향 회로를 재사용합니다. 키 확장의 `sub_word`도 같은 회로를 사용하므로 키 스케줄 역시 테이블 없이 수행됩니다.

### 2. GHASH carryless 곱셈

GF(2^128) 곱을 룩업 테이블 없이 정수 곱셈만으로 합성합니다. BearSSL `bmul32` 방식으로 피연산자를 4비트 간격 마스크로 4등분하면 lane당 부분곱이 carry 없이 합산되어 일반 정수 곱셈에서 GF(2)[X] 다항식 곱이 정확히 추출됩니다. 64비트와 128비트는 Karatsuba 3-곱으로 합성하고, 환원은 `p(X) = X^128 + X^7 + X^2 + X + 1`에 대한 시프트-XOR로 분기 없이 수행합니다.

이 경로의 전제는 "AMD64·AArch64의 정수 곱셈은 데이터 비종속 시간"입니다. 이 전제는 constant-time 크레이트의 `compile_error!` 게이트가 두 아키텍처 외 빌드를 거부하므로 지원 타겟 전체에서 성립합니다. DIT(aarch64)·DOITM(x86) 하드닝 과제는 constant-time README와 공유합니다.

### 3. 태그 비교

GCM 태그 검증은 constant-time 크레이트의 `CtEqOps`(인-라인 어셈블리 `cmp + sete / cset`)를 바이트별로 누적해 분기·조기 종료 없이 수행합니다. 비교가 끝난 뒤 수락/거부라는 공개 결과에만 분기합니다.

### 4. 나머지 연산

- `xtime`·`gf_mul`(MixColumns): 비밀 의존 분기 대신 `(b & 1).wrapping_neg()` 마스크와 곱셈-마스크 형태만 사용
- ShiftRows·상태 전치: 고정 인덱스 접근만 존재
- `inc32`: u16 carry 산술로 브랜치리스

## 비밀 소거 (zeroize)

트랜잭션 단위 전부 소거 원칙에 따라 다음이 보장됩니다.

| 비밀                              | 보호 방식                                   |
|---------------------------------|-----------------------------------------|
| 라운드 키(60워드)                     | `Secret<[u32; 60]>`, Drop 시 volatile 소거 |
| GCM 해시 서브키 `h`                  | `Drop`에서 zeroize                        |
| `GHash`의 `h_n`·`state_n`        | `Drop`에서 zeroize, `reset`도 zeroize 경유   |
| 키스트림 블록(CTR·GCM)                | 매 블록 사용 직후 zeroize                      |
| AES 상태 행렬·비트슬라이스 평면             | 함수 종료 전 zeroize                         |
| 키 확장 `temp`                     | 매 반복 직후 zeroize                         |
| `E(J0)`·GHASH 출력·`expected_tag` | 태그 합성·비교 직후 zeroize                     |

Drop 소거는 `test_aes256_zeroize_on_drop`, `test_aes256gcm_zeroize_on_drop`, `test_ghash_zeroize_on_drop`이 `MaybeUninit` 기반으로 해제 후 메모리를 직접 검사해 회귀를 방지합니다.

잔여 한계: 레지스터에 상주하는 워드 미만 임시값(MixColumns 열 변수, `sub_word`의 바이트, GHASH의 u128 중간값)은 zeroize 대상이 아닙니다. 레지스터·스필 잔존(CWE-316)은 zeroize 모델의 알려진 한계이며, 후속 연산이 즉시 덮어쓰는 짧은 수명에 의존합니다.

## 표준 부합 검증

키 확장은 FIPS 197 KeyExpansion(Nk=8, Nr=14, RCON 7개, `i mod 8 = 4`에서의 추가 SubWord 분기)과 일치하며, GCM은 `J0 = IV || 0^31 || 1`, GCTR 시작 카운터 `inc32(J0)`, GHASH 입력 순서 `A || pad || C || pad || [len(A)]64 || [len(C)]64`가 명세와 일치함을 확인했습니다.

| 테스트                            | 출처                                 |
|--------------------------------|------------------------------------|
| `fips197_c3_test_vector`       | FIPS 197 부록 C.3 (AES-256)          |
| `cbc_nist_f_2_5`               | SP 800-38A F.2.5 (CBC-AES256)      |
| `ctr_nist_f_5_5`               | SP 800-38A F.5.5 (CTR-AES256)      |
| `gcm_test_case_14/15/16`       | GCM 명세(McGrew & Viega) AES-256 케이스 |
| `ghash_basic`·`gf128_mul_test` | GCM 명세 GHASH 중간값                   |
| `sub_byte_matches_reference`   | FIPS 197 S-box 256개 전수 대조          |
| `bmul32_against_bitserial`     | carryless 곱 비트시리얼 대조               |
| `gcm_auth_failure`             | 변조 태그 거부 + 평문 미방출                  |

`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test -p aes --target <호스트 트리플>`, `cargo build -p aes --target x86_64-unknown-none`(베어메탈) 모두 무경고 통과합니다.

## 호출자 계약

이 크레이트는 stateless이므로 다음은 호출자가 보장해야 합니다.

1. **nonce/IV 유일성:** 같은 키로 GCM 및 CTR nonce를 재사용하면 키스트림 재사용으로 기밀성과 무결성이 즉시 붕괴합니다. 라이브러리는 호출 간 상태를 갖지 않아 이를 감지할 수 없습니다.
2. **CBC IV 예측 불가성:** SP 800-38A 부록 C에 따라 CBC IV는 예측 불가능해야 합니다.
3. **모드 간 키 분리:** CTR `apply`의 첫 카운터 블록(`nonce || 1`)이 GCM의 J0와 동일한 형식입니다. 같은 키·nonce를 CTR과 GCM 양쪽에 쓰면 CTR 키스트림 첫 블록이 GCM 태그 마스크 `E_K(J0)`와 일치해 태그 위조와 평문 복원으로 이어집니다. 한 키는 한 모드에만 사용해야 합니다.
4. **ECB 구성 금지:** `AES256::encrypt`는 단일 블록 프리미티브입니다. 여러 블록을 모드 없이 이어붙이는 사용은 금지됩니다.
5. **CBC는 무결성을 제공하지 않습니다:** 패딩도 제공하지 않습니다. 무결성이 필요하면 GCM을 사용해야 합니다.

---

## 발견한 문제와 조치

교차 검증에서 발견한 문제와 해결을 기술합니다.

### 키스트림·중간 상태 zeroize 누락 (해결)

라운드 키(`Secret`)는 보호되고 있었지만, CTR·GCM 키스트림 블록, CBC의 평문 XOR 블록, AES 상태 행렬, 비트슬라이스 평면, 키 확장 `temp`, `E(J0)`, GHASH 출력이 스택에 잔존했습니다. "한 요청·한 데이터·즉시 소거" 헌장 위반입니다.

#### 해결

모든 비밀 중간값에 사용 직후 `zeroize()`를 추가했습니다. 위 zeroize 절의 표가 조치 후 상태입니다.

### release 빌드에서 버퍼 검증 소실 (해결)

CBC·CTR의 길이 검증이 `debug_assert!`여서 release 빌드에서 제거되었습니다. 출력 버퍼가 입력보다 작으면 CBC는 `zip`이 조기 종료해 무음 절단(CWE-1284)이 발생하고, 블록 비배수 입력은 꼬리가 침묵 속에 무시되었습니다. CTR·GCM은 인덱스 패닉으로 중단되긴 하나 사유 없는 abort였습니다.

#### 해결

검증을 `assert!`로 승격해 release에서도 강제하고, GCM `encrypt`/`decrypt`에는 없던 출력 버퍼 검증을 신설했습니다. 위반은 진단 메시지와 함께 즉시 중단됩니다.

### GCM 태그 비교의 최적화기 재구성 여지 (해결)

기존 태그 비교는 XOR 누적(`diff |= tag[i] ^ expected[i]`) 방식으로 소스 수준에서는 분기가 없지만, 순수 Rust 산술이라 최적화기가 패턴을 재구성할 여지를 언어 차원에서 막을 수 없습니다(constant-time README의 `black_box` 논의와 동일한 문제). 프로젝트 헌장은 암호 로직의 비교 연산에 constant-time 크레이트 사용을 요구합니다.

#### 해결

인-라인 어셈블리 기반 `CtEqOps` 바이트 누적으로 교체했습니다. 어셈블리는 그대로 방출되므로 재구성 위험이 없습니다.

### SP 800-38D·38A 입력 길이 한계 미검증 (해결)

GCM과 CTR의 카운터는 하위 32비트만 inc32로 증가하므로 한 호출에서 2^32 블록을 넘으면 카운터가 wrap되어 키스트림이 재사용됩니다. GCM에서는 wrap이 J0까지 도달하면 태그 마스크 유출로 위조까지 가능해집니다. 또한 `len_block`의 AAD 비트 길이 계산(`aad_len * 8`)이 2^61 바이트 초과 입력에서 silent overflow였습니다. SP 800-38D 5.2.1.1절은 `len(P) <= 2^39-256` 비트, `len(A) <= 2^64-1` 비트를 요구하지만 어떤 검증도 없었습니다.

#### 해결

`GCM_MAX_INPUT_LEN = 2^36 - 32`바이트(= 2^39-256 비트), `GCM_MAX_AAD_LEN = 2^61 - 1`바이트(= 2^64-8 비트), `CTR_MAX_INPUT_LEN = 2^36`바이트(= 2^32 블록)를 `encrypt`/`decrypt`/`apply` 입구에서 `assert!`로 강제했습니다. GCM 한계는 카운터가 J0로 되돌아오기 전에 정확히 멈추는 값입니다. 64 GiB급 입력은 고정 스택 배열 환경에서 실질적으로 도달 불가능하지만, 표준 요구 사항을 코드로 명시해 가정이 아닌 보장으로 만들었습니다.

### GHash::reset의 Plain 0 대입 (해결)

`reset`이 `self.state_n = 0` 플레인 대입이었습니다. 프로젝트가 금지하는 anti-pattern(DCE-eligible 소거)으로, 재사용 직전이라 기능상 문제는 없으나 소거 경로의 일관성을 깨뜨립니다.

#### 해결

`zeroize()` 경유로 교체해 volatile 보장 경로로 일원화했습니다.

### 잔여 과제

- 레지스터 상주 임시값의 잔존(위 zeroize 절의 잔여 한계)
- aarch64 DIT·x86 DOITM 하드닝은 constant-time 크레이트와 공동 과제
- `inc32`가 `ctr.rs`와 `gcm.rs`에 중복 정의되어 있음(동작 동일, 통합은 후속 정리)
- `sbox.rs`·`ghash.rs` 모듈 주석의 TODO 표기 정리
