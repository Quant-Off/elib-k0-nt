# BLAKE 모듈

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)

RFC 7693 BLAKE2b 해시·MAC, BLAKE3 해시·키드 해시·XOF, RFC 9106 가변 길이 해시 `H'`를 외부 의존성 없이 `no_std` 순수 Rust로 구현한 크레이트입니다. 이 문서는 기능 명세와 보안 설계 근거, 표준 부합 근거, 그리고 발견한 문제와 조치를 기술합니다.

---

## 구현된 기능

| 알고리즘        | 표준          | 출력           | 블록 크기            | 내부 워드 | 라운드 | 키드 모드                  |
|--------------|-------------|--------------|------------------|-------|-----|------------------------|
| `Blake2b`    | RFC 7693    | 1..=64바이트    | 128바이트           | `u64` | 12  | `new_keyed` (1..=64 B 키) |
| `Blake3`     | BLAKE3 명세   | 32바이트 / XOF  | 64 B (1024 B 청크) | `u32` | 7   | `new_keyed` (32 B 키)   |
| `blake2b_long` | RFC 9106 §3.3 | 1..=1024바이트 | (BLAKE2b 코어)     | `u64` | 12  | 없음                     |

공개 API는 `Blake2b`·`Blake3` 타입, 자유 함수 `blake2b_long`, `SecureBuffer` 컨테이너, `ct_eq_slice` 비교 헬퍼로 구성됩니다.

- `Blake2b`: `new(hash_len)` / `new_keyed(hash_len, key)` -> `update(&[u8])` (임의 횟수) -> `finalize(self) -> Result<SecureBuffer, HashError>`의 스트리밍 인터페이스. `finalize`는 `self`를 소비하므로 인스턴스 재사용이 타입 차원에서 차단됩니다. 키드 생성자는 키를 128바이트 0-패딩 첫 블록으로 처리하여 BLAKE2b MAC을 제공합니다.
- `Blake3`: `new()` / `new_keyed(&[u8; 32])` -> `update(&[u8])` -> `finalize(self)`(32바이트 출력) 또는 `finalize_xof(self, out_len)`(`MAX_OUTPUT_LEN`까지 임의 길이)의 스트리밍 인터페이스. 내부 머클 트리는 고정 깊이 54의 체이닝 값 스택으로 구동됩니다.
- `blake2b_long`: Argon2id 블록 초기화와 최종 태그 생성에 쓰이는 RFC 9106 `H'` 구성. `out_len <= 64`이면 단일 `BLAKE2b(LE32(out_len) || input)`이고, 더 큰 출력은 64바이트 다이제스트를 체이닝하며 32바이트 프리픽스와 마지막 `(out_len - 32r)`바이트 블록을 방출합니다.
- `SecureBuffer`: 고정 용량(`MAX_OUTPUT_LEN` = 1024바이트) 스택 기반 버퍼로, 페이로드를 `Secret` 내부에 보관하고 길이 필드를 별도로 둡니다. 유일한 다이제스트 반환 타입이며 원시 `[u8; N]`은 반환하지 않습니다.
- `ct_eq_slice` / `CtEqOps for SecureBuffer`: 공격자 제어 값과 MAC 태그·다이제스트를 비교하기 위한 상수-시간 동등 비교.

설계 결정 명세는 다음과 같습니다.

- 모든 버퍼는 고정 크기 스택 배열입니다. `alloc`을 사용하지 않으며, 크레이트는 `#![cfg_attr(not(test), no_std)]`입니다.
- 다이제스트는 원시 배열이 아니라 자체 소거되는 `SecureBuffer`로만 반환합니다. 원시 배열 반환은 프로젝트가 금지하는 anti-pattern입니다.
- `Blake2b::finalize`와 `Blake3::finalize`·`finalize_xof`는 `self`를 소비하므로, 출력이 산출되는 순간 전체 해싱 상태가 volatile 소거됩니다.
- BLAKE2b와 BLAKE3 코어 모두 지연 압축 전략을 씁니다. 마지막 가득 찬 블록(BLAKE2b)과 마지막 가득 찬 청크(BLAKE3)를 보류하여 최종 블록 플래그(`f0`)와 `CHUNK_END`·`ROOT` 플래그를 정확히 적용합니다. 버퍼된 블록은 추가 입력이 있음이 확인된 뒤에야 압축됩니다.
- BLAKE2b는 순차 모드만 동작합니다(fanout 1, depth 1, salt·personalization 없음). 이는 RFC 7693이 표준화한 범위와 정확히 일치합니다. BLAKE3는 해시와 키드 해시 모드를 구현하며, 컨텍스트 기반 derive-key 모드는 제공하지 않습니다.

## 보안 처리 근거

두 해시 모두 비밀 메시지(BLAKE2b MAC 키, BLAKE3 키드 해시 자료)에 적용될 수 있으므로, 실행 시간이 비밀 값에 의존하지 않아야 합니다. 데이터 비종속은 다음 수준에서 보장됩니다.

### 1. 압축 함수는 데이터 비종속 연산만 사용

BLAKE2b 믹싱 함수 `g`와 BLAKE3 믹싱 함수 `g3`는 `wrapping_add`, `^`, `rotate_right`만으로 구성됩니다(회전량 BLAKE2b 32/24/16/63, BLAKE3 16/12/8/7). 비밀 값에 따른 분기나 비밀 의존 메모리 접근이 전혀 없습니다. 라운드 순열 `SIGMA`(BLAKE2b)와 `MSG_PERMUTATION`(BLAKE3)은 공개 정보인 라운드 번호로만 인덱싱되므로 비밀 인덱스 룩업 테이블을 형성하지 않습니다. 따라서 캐시·TLB 타이밍 부채널이 원천 차단됩니다.

### 2. 메시지 길이는 공개 정보

두 표준 모두에서 메시지 길이는 공개 정보입니다. `update`·`finalize`의 길이 기반 제어 흐름(버퍼 채우기, `.min()`, 블록·청크 카운팅, 체이닝 값 스택의 `popcount` 병합)은 입력 길이에만 의존하며 입력 바이트에는 의존하지 않습니다. 128비트 BLAKE2b 바이트 카운터는 분기 없는 캐리(`overflowing_add` -> `wrapping_add(carry as u64)`)로 증가합니다.

### 3. 상수-시간 태그·다이제스트 비교

`ct_eq_slice`와 `SecureBuffer`의 `CtEqOps` 구현은 두 바이트 영역을 상수-시간으로 비교하며, 각 바이트 비교를 `constant-time` 크레이트의 인-라인 어셈블리 프리미티브에 위임합니다. 이 보장은 두 길이가 공개라고 가정하며, 이는 길이가 표준 파라미터인 MAC 태그·다이제스트·키에 대해 성립합니다. 길이 불일치 시 짧은 프리픽스를 비교한 뒤 결과를 `Choice(0)`으로 마스킹하므로 어떤 분기 결과도 호출자에게 새지 않습니다. 크레이트가 `constant-time`에 의존하므로, 검증된 상수-시간 구현이 있는 x86_64·aarch64에서만 빌드가 허용되는 제약이 전이적으로 적용됩니다.

## 비밀 소거 (zeroize)

트랜잭션 단위 전부 소거 원칙에 따라 다음이 보장됩니다.

| 비밀                                              | 보호 방식                                           |
|-------------------------------------------------|-------------------------------------------------|
| BLAKE2b 체이닝 값 `h`(`[u64; 8]`)                  | `Secret`, Drop 시 volatile 소거 + `Zeroize`        |
| BLAKE2b 카운터 `t`(`[u64; 2]`)                    | `Secret`, Drop 시 volatile 소거                     |
| BLAKE2b·BLAKE3 입력 버퍼                            | `SecureBuffer`·`Secret`, 블록 압축 직후 즉시 `zeroize`   |
| BLAKE2b 워크 벡터 `v`(`[u64; 16]`)                 | `Secret`, `compress` 종료 시 Drop 소거               |
| BLAKE2b 로드된 블록 `m`(`[u64; 16]`)               | `Secret`, Drop 소거(명시적 `drop`)                   |
| BLAKE3 키 워드(`[u32; 8]`)                        | `Secret`, 생성 시점에 래핑되어 평문 사본 미잔류                |
| BLAKE3 체이닝 값 스택(`[[u32; 8]; 54]`)             | `Secret`, Drop 시 volatile 소거                     |
| BLAKE3 청크 체이닝 값·블록 워드·new CV                  | `Secret`, Drop 소거                                |
| BLAKE3 압축 상태·`m`·순열된 워드                       | `Secret`, 반복마다·스코프 종료 시 Drop 소거               |
| BLAKE3 부모·병합 CV(`Output`·`parent_cv`)         | `Secret`, 스코프 종료 시 Drop 소거                      |
| 출력 직렬화 임시값(`word.to_le_bytes()`)              | `finalize`·`root_output_bytes`에서 워드마다 명시적 `zeroize` |
| finalize 시 전체 해싱 상태                            | `finalize`가 `self`를 소비하므로 `Drop`이 전 필드 volatile 소거 |

`Secret<T>::drop`은 `T: Zeroize` 여부와 무관하게 전체 바이트 범위를 `ptr::write_volatile`로 기록하고 컴파일러·메모리 배리어로 봉인하므로, 위에 나열된 모든 `Secret` 래핑 중간값을 덮습니다. `Blake2b`와 `Blake3`는 추가로 `Zeroize`·`Drop`을 구현하여 비-비밀 길이·플래그 필드도 volatile 쓰기로 소거합니다.

잔여 한계: `g`·`g3` 내부의 라운드별 워킹 값과 `to_le_bytes`·`from_le_bytes`가 만드는 레지스터 사본은 레지스터에 짧게 상주하며 명시적 소거 대상이 아닙니다. 레지스터·스필 잔존(CWE-316)은 zeroize 모델의 알려진 한계이며, 후속 연산이 즉시 덮어쓰는 짧은 수명에 의존합니다.

## 표준 부합 근거

| 요소                                          | 근거                  |
|---------------------------------------------|---------------------|
| BLAKE2b 상수(IV, `SIGMA`)·파라미터 블록·키드 초기화      | RFC 7693 §2         |
| BLAKE2b 믹싱 함수 `G`·압축 `F`(12라운드, 회전 32/24/16/63) | RFC 7693 §3.2    |
| BLAKE2b 계산 예시·`"abc"` 테스트 벡터                 | RFC 7693 Appendix A |
| 가변 길이 해시 `H'`                               | RFC 9106 §3.3       |
| BLAKE3 IV·메시지 순열·도메인 플래그·머클 트리              | BLAKE3 명세           |

간접 검증에만 의존하는 크레이트와 달리, 이 크레이트는 모든 모드에 대해 자체 KAT(known-answer test)를 포함합니다.

- BLAKE2b: RFC 7693 빈 입력·`"abc"` 벡터, 64바이트 키 `00..3f`에 대한 공식 `blake2-kat` 키드 벡터(빈 입력·단일 바이트 입력), 키 블록 경계를 넘는 레퍼런스 기반 다중 블록 키드 벡터.
- `blake2b_long`: RFC 9106 `H'` 레퍼런스 구현에서 산출한 `out_len` 80(`r = 1`)·128(`r = 2`)의 바이트 정확 벡터.
- BLAKE3: 공식 비키드 빈 입력·`"hello"` 벡터, 그리고 길이 0·1·64·1024·1025·8192의 공식 키드 벡터로, 각각 단일 블록·블록 경계·단일 청크·다중 청크·3단 머클 병합 경로를 운동합니다.
- `tests/threat_inputs.rs`: 경계 길이·비대칭 길이 회귀 커버리지와, 분할 `update` 호출이 단일 호출과 바이트 동일 출력을 내는지 검증하는 스트리밍 등가성 점검.

`cargo fmt -p blake -- --check`, `cargo clippy -p blake --all-targets --all-features -- -D warnings`, `cargo build -p blake --target x86_64-unknown-none`, `cargo build -p blake --target aarch64-unknown-none` 모두 무경고 통과합니다.

## 호출자 계약

이 크레이트는 stateless이므로 다음은 호출자가 보장하거나 인지해야 합니다.

1. **1회용 finalize:** `finalize`·`finalize_xof`는 `self`를 소비합니다. 같은 입력에 대한 재해시는 새 인스턴스로 수행해야 합니다.
2. **다이제스트 즉시 사용:** `SecureBuffer`는 Drop 시 소거됩니다. `as_slice()` 결과를 호출자 측에 보존하려면 그 즉시 복사해야 하며, 다이제스트가 비밀(예: MAC 태그)이라면 복사본도 호출자가 소거해야 합니다.
3. **상수-시간 비교는 공개 길이 데이터용:** 태그·다이제스트 비교에는 `ct_eq_slice`·`CtEqOps::eq`를 사용합니다. 상수-시간 보장은 비교 길이가 공개임을 가정합니다.
4. **길이 사전조건:** `Blake2b::new`·`new_keyed`는 1..=64 출력 길이(및 1..=64 키 길이)를 단언하며, 위반 시 패닉(`panic = "abort"` 하)합니다. 호출자가 유효한 길이를 전달해야 합니다. `blake2b_long`은 `out_len == 0` 또는 `out_len > MAX_OUTPUT_LEN`이면 `Err(HashError)`를 반환합니다. BLAKE3 키 길이는 `&[u8; 32]` 타입으로 32바이트에 고정됩니다.

---

## 발견한 문제와 조치

검증 과정에서 발견한 문제와 해결을 기술합니다.

### BLAKE3 `new_keyed` 평문 키 워드 잔류 (해결)

`new_keyed`는 32바이트 키를 `Secret`으로 감싸기 전에 `[u32; 8]` 평문 지역변수로 변환했습니다. `[u32; 8]`은 `Copy`이므로 `Secret::new`이 배열을 이동이 아니라 복사하여, 함수 반환 후에도 키의 비-소거 평문 사본(키 바이트로 자명하게 역변환 가능)이 함수 스택 프레임에 남았습니다. 구조체 도스트링도 키가 스택에 노출되지 않는다고 과장했습니다.

#### 해결

헬퍼 `words_from_le_bytes_32`가 기존 `words_from_le_bytes_64` 패턴을 따라 `Secret<[u32; 8]>`을 반환하도록 변경하여, 변환된 키가 생성 시점에 래핑되고 명명된 평문 사본이 잔류하지 않게 했습니다. 도스트링도 실제 동작에 맞게 정정했습니다.

### 다이제스트 직렬화의 미사용 출력 바이트 잔존 (해결)

요청한 출력 길이가 워드 크기의 배수가 아닐 때, 마지막 `word.to_le_bytes()`는 8바이트(BLAKE2b) 또는 4바이트(BLAKE3) 배열 전체를 만들지만 그중 앞부분만 출력에 기록되었습니다. 나머지 바이트는 최종 내부 체이닝 상태에서 파생되어 출력에 포함되지 않으면서 스택에 남았습니다.

#### 해결

`Blake2b::finalize`와 `Output::root_output_bytes`에서 워드마다 직렬화 임시값을 `zeroize()`하여 메모리 상주 시간을 제한했습니다.

### 키드 BLAKE2b 미검증·`blake2b_long` 출력 미검증 (해결)

`Blake2b::new_keyed`(MAC 경로)는 테스트 커버리지가 전혀 없었고, 유일한 `blake2b_long` 테스트는 값이 아니라 출력 길이만 단언했습니다. Argon2id에 입력되는 함수에서 조용한 오류 위험입니다.

#### 해결

공식·레퍼런스 기반 키드 BLAKE2b KAT(빈 입력·단일 바이트·다중 블록)와 바이트 정확 RFC 9106 `H'` 값 KAT를 추가했으며 모두 통과하여, 키드 카운터 로직과 `H'` 체이닝이 바이트 정확함을 확인했습니다.

### 문서 정정 (해결)

`Blake2b::new`·`new_keyed` 생성자는 `Result`가 아니라 `Self`를 반환함에도 패닉 조건을 `# Errors`에 기술했으므로 `# Panics`로 변경했습니다. `blake2b_long` 도스트링은 `H'`를 "RFC 9106 §3.2"로 인용했으나 §3.3에 정의됩니다.

### TODO

- `g`·`g3` 워킹 값과 `to_le_bytes`·`from_le_bytes` 중간값의 레지스터·스필 잔존(CWE-316)은 다른 알고리즘 크레이트와 공유하는 알려진 한계입니다.
- `Blake2b::new`·`new_keyed`는 길이 사전조건을 `Result`가 아니라 `assert!`(panic = abort)로 강제합니다. 이는 전역(total) 생성자의 문서화된 강제 경계이나, 실패 가능 생성자라면 호출자 유발 abort를 피할 수 있습니다.
- BLAKE2b salt·personalization과 BLAKE3 derive-key 모드는 의도적으로 범위 밖입니다.
- aarch64 DIT·x86 DOITM 하드닝은 `constant-time` 크레이트와 공동 과제입니다.
