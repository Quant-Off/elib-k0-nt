# 난수 생성 (Random Number Generation, RNG) 모듈

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)

암호 시스템의 모든 비밀은 결국 하나의 난수원으로 수렴합니다. 키, IV, nonce, Capability 토큰이 예측 가능해지는 순간 그 위의 모든 표준 준수는 무의미해집니다. 이 문서는 `rng` 크레이트가 [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) Hash_DRBG와 OS 엔트로피 어댑터를 어떻게 구현했는지, 그리고 그 보안 근거가 기계어 수준에서 어디에 뿌리내리고 있는지를 기술적으로 설명합니다.

---

## 제공하는 기능

크레이트는 두 계층으로 구성됩니다. 결정론적 비트 생성기(Deterministic Random Bit Generator, DRBG)와 그 시드를 공급하는 OS 엔트로피 어댑터입니다.

### Hash_DRBG (`hash_drbg.rs`)

NIST SP 800-90A Rev. 1, Section 10.1의 Hash_DRBG를 SHA-2의 4종류로 인스턴스화합니다. `impl_hash_drbg!` 매크로가 표준 Table 2 파라미터만 바꿔 동일 로직을 생성하므로 변형 간 동작 차이가 없습니다.

| 타입               | 해시      | 보안 강도    | outlen | seedlen | 최소 엔트로피   |
|------------------|---------|----------|--------|---------|-----------|
| `HashDRBGSHA224` | SHA-224 | 112 bits | 28 B   | 55 B    | 14 B      |
| `HashDRBGSHA256` | SHA-256 | 128 bits | 32 B   | 55 B    | 16 B      |
| `HashDRBGSHA384` | SHA-384 | 192 bits | 48 B   | 111 B   | 24 B      |
| `HashDRBGSHA512` | SHA-512 | 256 bits | 64 B   | 111 B   | 32 B (권장) |

표준 알고리즘 세 개를 그대로 노출합니다.

- `Instantiate` (10.1.1.2): `V = Hash_df(entropy || nonce || personalization, seedlen)`, `C = Hash_df(0x00 || V, seedlen)`, `reseed_counter = 1`.
- `Reseed` (10.1.1.3): `V = Hash_df(0x01 || V || entropy || additional_input, seedlen)` 후 `C` 재유도, 카운터 1로 리셋.
- `Generate` (10.1.1.4): `additional_input` 반영(`w` 경로) -> `Hashgen` -> `V = (V + H + C + reseed_counter) mod 2^seedlen`.

공개 API는 엔트로피 출처에 따라 두 쌍으로 나뉩니다.

| 경로   | 초기화                           | 재시드(Reseed)      | 엔트로피 출처                  |
|------|-------------------------------|------------------|--------------------------|
| 권장   | `new_from_os`                 | `reseed_from_os` | OS CSPRNG (내부 수집)        |
| 베어메탈 | `new_from_entropy` (`unsafe`) | `reseed`         | 호출자 주입 (RDSEED 및 TRNG 등) |

`new_from_os` 계열은 호출자가 엔트로피를 만질 수 없어 예측 가능한 시드 주입 경로를 원천 차단합니다. `new_from_entropy`는 OS가 없는 환경을 위한 탈출구라 `unsafe`로 표시되고, 엔트로피 품질/독립성/재사용 금지 책임을 호출자에게 명시적으로 넘깁니다.

```rust,ignore
use rng::{HashDRBGSHA256, DrbgError};

// 호스트 측: OS CSPRNG로 시드 (권장)
let mut drbg = HashDRBGSHA256::new_from_os(Some(b"host-boot-id"))?;
let mut out = [0u8; 128];
drbg.generate(&mut out, None)?;

// ReseedRequired 수신 시 OS 엔트로피로 안전하게 재시드
drbg.reseed_from_os(None)?;
```

### OS 엔트로피 어댑터 (`os_entropy.rs`)

플랫폼별 CSPRNG를 직접 호출하는 얇은 어댑터입니다. 외부 crate(`getrandom`, `rand`) 없이 syscall 또는 libc 심볼에 직접 연결합니다(Zero-Trust). `fill_bytes`, `get_bytes::<N>`, `extract_os_entropy`(crate 내부) 세 진입점을 제공합니다.

### SecureBuffer (`lib.rs`)

DRBG 내부 상태(V, C)와 수집된 엔트로피를 담는 고정 128바이트 스택 버퍼입니다. `alloc` 없이(`no_std`) 동작하며 Drop/`zeroize` 시 활성 영역이 아니라 backing storage 전체를 휘발성 쓰기로 소거합니다.

---

## 엔트로피 수집의 어셈블리 측면 근거

이 크레이트에서 "기계어 수준" 보안이 가장 직접적으로 드러나는 지점은 엔트로피 syscall입니다. 표준 라이브러리나 외부 crate를 거치지 않고 인-라인 어셈블리로 커널에 직접 진입하므로, 무엇이 클로버(clobber)되고 무엇이 보존되는지가 소스에 그대로 박혀 있습니다.

### 1. 직접 syscall, 중간 계층 없음

Linux x86_64의 `getrandom(2)` 호출은 다음과 같습니다.

```rust
core::arch::asm!(
    "syscall",
    inlateout("rax") SYS_GETRANDOM => ret, // 318
    in("rdi") ptr,
    in("rsi") len,
    in("rdx") 0u32,        // flags = 0 (블로킹)
    lateout("rcx") _,      // syscall이 복귀 RIP 저장 -> 클로버
    lateout("r11") _,      // syscall이 RFLAGS 저장 -> 클로버
    options(nostack),
);
```

Linux x86_64 syscall ABI 그대로입니다. 번호는 `rax`, 인자는 `rdi`/`rsi`/`rdx`, 반환은 `rax`. `syscall` 명령은 복귀 주소를 `rcx`에, 플래그를 `r11`에 덮어쓰므로 두 레지스터를 `lateout(_)`로 클로버 선언해 컴파일러가 살아있는 값을 그곳에 두지 못하게 합니다. aarch64는 동일 구조를 `svc #0` + `x8`(번호) + `x0..x2`(인자)로 표현하며 반환값은 `x0`에 옵니다.

| 플랫폼                    | 메커니즘        | 명령/심볼                                | 번호             |
|------------------------|-------------|--------------------------------------|----------------|
| Linux x86_64           | raw syscall | `syscall`                            | rax = 318      |
| Linux aarch64          | raw syscall | `svc #0`                             | x8 = 278       |
| FreeBSD x86_64/aarch64 | raw syscall | `syscall`/`svc #0`                   | 563            |
| OpenBSD x86_64/aarch64 | raw syscall | `syscall`/`svc #0`                   | getentropy = 7 |
| macOS x86_64/aarch64   | libc        | `getentropy`                         | (심볼 링크)        |
| NetBSD x86_64          | libc        | `getentropy`                         | (심볼 링크)        |
| Windows x86_64         | advapi32    | `RtlGenRandom` (`SystemFunction036`) | (심볼 링크)        |

macOS/NetBSD만 raw syscall 대신 libc `getentropy` 심볼에 링크합니다. 이 두 플랫폼은 syscall 번호가 안정 ABI가 아니어서 직접 호출이 깨질 수 있기 때문이며, 불가피한 예외로 명시합니다. 나머지 Linux/BSD는 번호가 안정적이라 raw syscall을 씁니다.

### 2. `options(nomem)`를 쓰지 않는 이유 (정확성이 곧 보안)

상수-시간 프리미티브(`constant-time` 크레이트)의 asm 블록은 `options(nomem, nostack)`으로 메모리 비접근을 선언합니다. 그러나 엔트로피 syscall은 `nostack`만 선언하고 `nomem`은 **의도적으로 생략**합니다.

커널이 `ptr`가 가리키는 사용자 버퍼에 난수를 써넣기 때문입니다. 즉 이 asm은 포인터를 통해 메모리를 변경합니다. 여기에 `nomem`을 붙이면 "이 asm은 메모리를 읽거나 쓰지 않는다"고 컴파일러에 거짓을 알리는 것이고, 최적화기가 버퍼 채움을 죽은 코드로 제거하거나 인접 메모리 연산과 재정렬할 수 있어 정의되지 않은 동작(UB)이 됩니다. `nomem`의 생략은 누락이 아니라, 버퍼가 실제로 채워졌음을 컴파일러가 신뢰하도록 만드는 정확성 보장입니다.

### 3. 블로킹 모드와 부분 읽기 처리

`flags = 0`은 `GRND_NONBLOCK`도 `GRND_RANDOM`도 켜지 않습니다.

- `GRND_RANDOM` 미설정: 고갈되기 쉬운 블로킹 `/dev/random` 풀이 아니라, 한 번 초기화되면 고갈되지 않는 CSPRNG(`/dev/urandom` 의미론)에서 뽑습니다.
- `GRND_NONBLOCK` 미설정: 부팅 직후 풀이 아직 시드되지 않았다면 시드될 때까지 블로킹합니다. 약한 엔트로피로 조용히 진행하는 것보다 기다리는 쪽을 택합니다.

반환값 처리도 기계어 ABI에 맞춰 방어적입니다.

- `ret < 0`이고 `-4`(EINTR): 시그널로 중단됐을 뿐이므로 루프 재시도.
- `ret < 0` 그 외: `OsEntropyFailed` 반환.
- `ret == 0`: getrandom 계약상 정상 경로에선 나오지 않지만, 무한 루프/과소 시드를 막기 위해 실패로 처리.
- `0 < ret < len`: 부분 읽기. `offset += ret`로 남은 만큼 다시 요청.

`getentropy` 경로(macOS/BSD)는 호출당 256바이트 상한이 있어 `min(remaining, 256)`으로 잘라 반복합니다.

### 4. 베어메탈 기본 타겟에서의 부재

워크스페이스 기본 빌드 타겟은 `x86_64-unknown-none`입니다. 이 타겟에서는 위 어떤 `cfg`도 만족되지 않아 `mod sys`가 항상 `Err(OsEntropyFailed)`만 반환하는 fallback으로 컴파일됩니다. 즉 실제 마이크로커널 Ring-3 데몬 배포본에서 OS 엔트로피는 비가용이며, 시드는 `new_from_entropy`를 통해 커널 또는 하드웨어 TRNG에서 주입되어야 합니다. 위 플랫폼별 syscall 경로는 주로 호스트 측 빌드/테스트를 위한 것입니다.

---

## 메모리 소거의 어셈블리 측면 근거

DRBG의 핵심 가치는 "한 요청/한 데이터/즉시 소거"입니다. 내부 상태 V/C와 중간 계산값이 사용 후 메모리에 남으면 메모리 덤프나 잔존(remanence) 분석으로 출력 전체가 역산될 수 있습니다. 이 크레이트는 두 가지 도구로 잔존을 차단합니다.

### 1. SecureBuffer 전체 영역 소거

`SecureBuffer::zeroize`는 활성 길이 `len`만이 아니라 backing `[u8; 128]` 전체를 소거합니다.

```rust
fn zeroize(&mut self) {
    self.data.zeroize(); // 활성 영역 밖 잔존 바이트까지
    self.len.zeroize();
}
```

과거 더 큰 `len`으로 쓰였다가 줄어든 경우 비활성 영역에 남는 잔존 바이트를 함께 제거하기 위함입니다. 실제 소거는 `zeroize` 크레이트가 담당하며, 그 핵심은 컴파일러가 죽은 쓰기로 제거하지 못하도록 휘발성 쓰기(`volatile_write`) 후 아키텍처별 메모리/컴파일러 배리어(x86_64/aarch64 인-라인 어셈블리, 그 외 `compiler_fence`)를 거는 것입니다. 평범한 `self.data = [0; 128]` 대입은 LLVM의 죽은 저장 제거(DSE)로 사라질 수 있으나, 휘발성 쓰기는 기계어 수준에서 store가 반드시 방출되도록 강제합니다.

`Drop`이 이 `zeroize`를 호출하므로 정상 종료든 패닉(`panic = "abort"` 환경)이든 스코프를 벗어나는 모든 경로에서 backing storage가 0이 됩니다.

### 2. 스택 중간값은 Secret으로

`hash_df`/`hashgen`/`generate`/`reseed`는 V를 스택 배열에 복사해 가공합니다. 이 복사본은 `zeroize::Secret`으로 감쌉니다.

```rust
let mut data = Secret::new([0u8; $seedlen]);
data.expose_mut().copy_from_slice(self.v.as_slice());
// ... 사용 ...
// Drop 시 휘발성 쓰기 + 배리어로 자동 소거
```

`Secret`이 중요한 이유는 `?` 조기 반환과 패닉 경로입니다. `hash_df`가 중간에 `InvalidArgument`로 빠져나가도 `Secret`의 `Drop`이 보장되어, 부분 계산된 `new_v`/`new_c`가 평문으로 스택에 남지 않습니다. `generate` 안의 `w_padded`/`h_padded`/`c_copy`/`data`가 모두 같은 방식으로 보호됩니다.

### 3. reseed_counter와 필드 Drop 순서

DRBG의 `Drop` 본문은 `reseed_counter`만 명시적으로 소거합니다.

```rust
impl Drop for $struct_name {
    fn drop(&mut self) {
        self.reseed_counter.zeroize();
    }
}
```

V/C는 `SecureBuffer` 자신의 `Drop`이 소거하며, Rust가 `Drop::drop` 본문 실행 후 필드를 선언 순서(`v`, `c`, `reseed_counter`)대로 떨어뜨리므로 별도 호출 없이 둘 다 소거됩니다. 카운터는 정수라 자체 Drop이 없어 본문에서 직접 처리합니다.

참고로 이 환경에는 OS 페이지 잠금(`mlock`)이 없습니다. 베어메탈/`no_std`에는 잠글 OS가 없기 때문입니다. 따라서 메모리 보호는 페이지 잠금이 아니라 "사용 직후 휘발성 소거"로 잔존 노출 창을 최소화하는 데 의존합니다.

---

## 상수-시간 불변식

DRBG의 위협 모델에서 보호 대상은 **내부 상태 V/C**이고, `generate`의 반환값은 공개입니다. 따라서 출력 자체의 타이밍 보호는 불필요하지만, 내부 상태를 다루는 산술이 그 값에 따라 분기하면 상태가 새어 나갈 수 있습니다. 상태를 만지는 두 산술은 값-독립적입니다.

### add_mod/add_u64_mod: 값에 무관한 모듈러 덧셈

`V = (V + w) mod 2^seedlen` 같은 갱신은 big-endian 모듈러 덧셈으로 구현됩니다.

```rust
fn add_mod(dst: &mut [u8], src: &[u8]) {
    let mut carry: u16 = 0;
    for (d, s) in dst.iter_mut().rev().zip(src.iter().rev()) {
        let sum = *d as u16 + *s as u16 + carry;
        *d = sum as u8;
        carry = sum >> 8; // 분기 없는 자리올림
    }
}
```

- 반복 횟수는 항상 `dst.len()`(= seedlen, 공개 상수)입니다. 비밀 값에 따라 늘거나 줄지 않습니다.
- 자리올림은 `if carry > 0` 같은 분기가 아니라 `u16` 산술과 `>> 8` 마스킹으로만 처리됩니다. 기계어 수준에서 조건 분기(`jcc`/`b.cc`)가 생기지 않습니다.
- 메모리 접근은 인덱스 선형 증가뿐이라 비밀 의존 캐시/TLB 타이밍이 없습니다.

`add_u64_mod`의 `if i < 8` 분기는 비밀 값이 아니라 **인덱스**(공개 상수)에 의존하며, 더하는 `val`은 비밀이 아닌 단조 증가 `reseed_counter`입니다. 따라서 이 분기의 타이밍 관찰은 위협이 되지 않습니다.

### Hashgen: 공개 길이에만 의존

`hashgen`의 루프 횟수는 `ceil(requested_bytes / outlen)`로 요청 길이(공개)에만 의존하고 비밀 V의 값에 무관합니다. 해시 입력 크기가 고정이라 해시 연산 시간도 V 값과 무관합니다.

> 다만 이 산술의 상수-시간성은 `constant-time` 크레이트의 검증된 인-라인 어셈블리 프리미티브가 아니라 일반 Rust 산술의 분기 부재에 기댑니다. 최적화기가 이 패턴을 분기로 재구성하지 않으리라는 보장은 `constant-time`의 asm 경로만큼 강하지 않습니다. **분기가 비밀이 아닌 카운터/공개 길이에만 걸려 있어 위협면이 좁다는 점이 현재의 근거**입니다.

---

## 표준 준수와 경계값

NIST SP 800-90A Rev. 1 Table 2의 경계가 코드로 강제됩니다.

| 항목        | 값                                | 위반 시                                           |
|-----------|----------------------------------|------------------------------------------------|
| 최소 엔트로피   | security_strength bytes          | `EntropyTooShort`                              |
| 최대 입력 길이  | 2^32 bytes (2^35 bits)           | `EntropyTooLong`/`InputTooLong`/`NonceTooLong` |
| 최소 nonce  | security_strength / 2 bytes      | `NonceTooShort`                                |
| 요청당 최대 출력 | 65536 bytes (2^16 B = 2^19 bits) | `RequestTooLarge`                              |
| 재시드 간격    | 2^48                             | `ReseedRequired`                               |

추가적으로 다음 특징을 가집니다.

- **엔트로피 2배 수집**: `new_from_os`/`reseed_from_os`는 `2 * security_strength` 바이트를 모읍니다(Section 8.6.7).
- **nonce 독립성**: entropy와 nonce를 OS에 대한 **별개 호출**로 수집해 상관을 없앱니다.
- **Hash_df 카운터 wrap 가드**: `Hash_df`의 1바이트 카운터가 넘칠 `m > 255` 입력을 `InvalidArgument`로 거부합니다. 현재 비즈니스 로직 상으로는 절대 발생할 수 없는 문제이지만, 입력 단계에서 엄격한 방어벽을 형성합니다.
- **`additional_input`의 Null 구분**: 표준상 `additional_input != Null`이면 길이 0이어도 `w` 경로가 V를 갱신해야 합니다. `Some(&[])`와 `None`을 구분해 전자는 갱신, 후자만 건너뜁니다.

---

## 설계 한계와 주의

알고 있는 약점을 명시합니다.

### OS CSPRNG는 SP 800-90B 검증 엔트로피원이 아니다

본 모듈이 노출하는 것은 OS CSPRNG(`getrandom`/`getentropy`/`RtlGenRandom`) 출력입니다. 이는 SP 800-90B로 검증된(헬스 테스트를 갖춘) 엔트로피 소스가 아니라 SP 800-90C 관점의 RBG 시드원입니다. FIPS 인증 시 엔트로피 평가는 플랫폼 RBG 보증에 의존합니다.

### 베어메탈에서 OS 엔트로피는 비가용

기본 타겟에서 OS 경로는 컴파일되지 않습니다. 시드는 반드시 외부(`new_from_entropy`)에서 주입해야 하며, 약한 엔트로피 주입은 DRBG 출력을 예측 가능하게 만들어 상위 계층(키/토큰/IV) 전체를 붕괴시킵니다. 그래서 그 경로가 `unsafe`입니다.

### 예측 저항(prediction resistance) 미구현

`generate`는 호출마다 새 엔트로피를 끌어오지 않습니다. 예측 저항이 필요하면 `reseed_from_os`를 호출 전에 명시적으로 실행해야 합니다.

### macOS/NetBSD의 libc 의존

이 두 플랫폼은 raw syscall 대신 libc `getentropy`에 링크합니다. syscall 번호가 안정 ABI가 아니어서 불가피하며, Zero-Trust의 "외부 의존성 0" 원칙에서 OS 표준 C 런타임 심볼 하나에만 한정된 예외입니다.