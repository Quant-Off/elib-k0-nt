//! NIST SP 800-90A Rev. 1에 따른 Hash_DRBG 구현 모듈입니다.
//!
//! 이 모듈은 NIST SP 800-90A Rev. 1 표준의 10.1.1 섹션에 명시된 해시 기반 결정론적 난수 비트 생성기(Hash_DRBG)를 구현합니다.
//!
//! # Features
//! - **NIST 표준 준수**: `Instantiate`, `Reseed`, `Generate` 알고리즘을 표준 명세에 따라 구현합니다.
//! - **다양한 해시 함수 지원**: `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`를 기반으로 하는 DRBG 인스턴스를 제공합니다.
//!   - [`HashDRBGSHA224`] (Security Strength: 112 bits)
//!   - [`HashDRBGSHA256`] (Security Strength: 128 bits)
//!   - [`HashDRBGSHA384`] (Security Strength: 192 bits)
//!   - [`HashDRBGSHA512`] (Security Strength: 256 bits)
//! - **메모리 보안**: 내부 상태 `V`와 `C`를 [`SecureBuffer`]를 사용하여 관리합니다. 이를 통해 OS 레벨의 메모리 잠금(`mlock`)과 Drop 시점의 자동 소거를 보장하여, 메모리 덤프나 콜드 부트 공격으로부터 내부 상태를 보호합니다.
//! - **Reseed 강제**: 표준에 따라 최대 reseed 간격(`RESEED_INTERVAL`)을 초과하면 [`generate`] 함수가 [`ReseedRequired`] 에러를 반환하여 주기적인 엔트로피 갱신을 강제합니다.
//! - **유연한 입력 처리**: `instantiate`, `reseed`, `generate` 함수에서 `additional_input`과 `personalization_string`을 지원합니다.
//!
//! # Examples
//! ```rust,ignore
//! use rng::{HashDRBGSHA256, DrbgError};
//!
//! fn main() -> Result<(), DrbgError> {
//!     // 1. 초기화 — OS 엔트로피 소스 사용 (임의 엔트로피 주입 불가)
//!     let personalization = Some(b"my-app-specific-string" as &[u8]);
//!     let mut drbg = HashDRBGSHA256::new_from_os(personalization)?;
//!
//!     // 2. 난수 생성 (Generate)
//!     let mut random_bytes = [0u8; 128];
//!     drbg.generate(&mut random_bytes, None)?;
//!
//!     // 3. reseed — ReseedRequired 수신 시 OS 엔트로피로 안전하게 재시드
//!     drbg.reseed_from_os(None)?;
//!
//!     // 4. 추가 난수 생성
//!     let mut more_random_bytes = [0u8; 64];
//!     drbg.generate(&mut more_random_bytes, None)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Security Note
//! - `impl_hash_drbg!` 매크로를 사용하여 각 해시 함수에 대한 DRBG 구조체와 구현을 생성합니다. 이는 코드 중복을 최소화하고 일관성을 유지합니다.
//! - 내부 상태 덧셈 연산(`add_mod`, `add_u64_mod`)은 Big-endian 모듈러 덧셈으로 구현되어 표준을 정확히 따릅니다.
//! - 중간 계산값이나 스택에 복사된 민감한 데이터는 [`zeroize::Secret`] 으로 감싸 모든 종료 경로(정상/`?`/패닉) 에서 휘발성 쓰기 + 컴파일러·메모리 배리어로 자동 소거합니다.
//!
//! # Authors
//! Q. T. Felix

use crate::{DrbgError, SecureBuffer};
use core::cmp::min;
use sha2::{SHA2, SHA224, SHA256, SHA384, SHA512};
use zeroize::{Secret, Zeroize};

/// 최대 reseed 간격
const RESEED_INTERVAL: u64 = 1 << 48;

/// 요청당 최대 출력 바이트 (2^19 bits = 65536 bytes)
const MAX_BYTES_PER_REQUEST: usize = 65536;

/// NIST SP 800-90A Rev. 1, Table 2: entropy_input / nonce / personalization_string 최대 길이
/// 2^35 bits = 2^32 bytes. usize가 32-bit인 환경에서도 안전하게 비교하기 위해 u64 사용.
const MAX_LENGTH: u64 = 1u64 << 32;

/// NIST SP 800-90A Rev. 1, Table 2: additional_input 최대 길이 (2^35 bits = 2^32 bytes)
const MAX_ADDITIONAL_INPUT: u64 = 1u64 << 32;

/// Hash_DRBG 함수 일관 구현을 위한 매크로입니다.
///
/// NIST SP 800-90A Rev. 1에 따른 Hash_DRBG 변형을 생성합니다.
///
/// # Arguments
/// - `$struct_name` : 생성할 구조체 이름
/// - `$hasher_type` : 사용할 해시 함수 타입 (예: SHA256)
/// - `$outlen`      : 해시 출력 크기 (bytes, NIST Table 2 outlen)
/// - `$seedlen`     : 시드 길이 (bytes, NIST Table 2 seedlen)
/// - `$min_entropy` : 최소 엔트로피/보안 강도 (bytes, security_strength / 8)
macro_rules! impl_hash_drbg {
    (
        $struct_name:ident,
        $hasher_type:ty,
        $outlen:expr,
        $seedlen:expr,
        $min_entropy:expr
    ) => {
        /// Hash_DRBG 인스턴스입니다.
        ///
        /// 내부 상태 V, C는 [`SecureBuffer`]로 관리되어 OS 레벨 메모리 잠금(lock)과
        /// [Drop] 시점의 강제 소거([`Zeroize`])가 보장됩니다.
        pub struct $struct_name {
            /// 내부 상태 V — seedlen bytes
            v: SecureBuffer,
            /// 내부 상태 C — seedlen bytes
            c: SecureBuffer,
            /// reseed 카운터 (1부터 시작, RESEED_INTERVAL 초과 시 ReseedRequired 반환)
            reseed_counter: u64,
        }

        impl $struct_name {
            /// NIST SP 800-90A Rev. 1의 Section 10.3.1의 Hash_df
            ///
            /// inputs 슬라이스 배열을 순서대로 연결(concatenate)한 것으로 간주하여
            /// `no_of_bytes_to_return` 길이의 바이트를 유도합니다.
            ///
            /// `output.len() == no_of_bytes_to_return` 이어야 합니다.
            fn hash_df(
                inputs: &[&[u8]],
                no_of_bytes_to_return: usize,
                output: &mut [u8],
            ) -> Result<(), DrbgError> {
                // Hash_df 명세: no_of_bits_to_return을 4바이트 big-endian 정수로 인코딩
                // seedlen_bits(max=888) < 2^32 이므로 u32으로 충분
                let no_of_bits = (no_of_bytes_to_return as u32)
                    .checked_mul(8)
                    .ok_or(DrbgError::InvalidArgument)?;
                let no_of_bits_be = no_of_bits.to_be_bytes();

                let m = no_of_bytes_to_return.div_ceil($outlen);
                // Hash_df counter 는 1바이트 — m 이 255 초과 시 카운터 wrap 발생
                // 현 호출은 seedlen 한정(m ≤ 3)이나 계약을 코드로 강제하여 오용 차단
                if m > 255 {
                    return Err(DrbgError::InvalidArgument);
                }
                let mut written = 0usize;

                // counter in [1, m], m ≤ 255 보장됨 — u8 오버플로 없음
                for counter in 1u8..=(m as u8) {
                    let mut hasher = <$hasher_type>::new();
                    hasher.update(&[counter]);
                    hasher.update(&no_of_bits_be);
                    for chunk in inputs {
                        hasher.update(chunk);
                    }
                    let hash = hasher.finalize();
                    let hash_bytes = hash.as_bytes();

                    let copy_len = min($outlen, no_of_bytes_to_return - written);
                    output[written..written + copy_len].copy_from_slice(&hash_bytes[..copy_len]);
                    written += copy_len;
                }

                Ok(())
            }

            /// Big-endian 모듈식 덧셈: `dst = (dst + src) mod 2^(dst.len() * 8)`
            ///
            /// dst와 src는 같은 길이여야 합니다.
            ///
            /// # 상수-시간(Constant-Time) 불변식
            ///
            /// 이 함수는 `dst`와 `src`의 **값**에 대해 데이터 의존적 분기(branch)가 없습니다.
            /// - 반복 횟수: 항상 `dst.len()` (고정, 비밀 데이터에 무관)
            /// - 조건 분기: 없음 — carry는 산술 연산(`u16` 오버플로 마스킹)으로만 처리됨
            /// - 캐시 접근 패턴: 인덱스가 단순 증가(선형) — 캐시-타이밍 공격 면역
            ///
            /// **주의**: 컴파일러가 루프를 언롤하거나 SIMD로 변환해도 CT 보장은 유지됩니다.
            /// 단, 이 함수의 결과를 외부에서 비교(`==`)할 때는 반드시 상수-시간 비교를 사용하세요.
            #[inline]
            fn add_mod(dst: &mut [u8], src: &[u8]) {
                let mut carry: u16 = 0;
                // big-endian: 낮은 인덱스 = 상위 바이트 -> 오른쪽(낮은 유효 바이트)부터 덧셈
                for (d, s) in dst.iter_mut().rev().zip(src.iter().rev()) {
                    let sum = *d as u16 + *s as u16 + carry;
                    *d = sum as u8;
                    carry = sum >> 8;
                }
                // 최종 carry는 mod 2^(seedlen_bits)에 의해 버림
            }

            /// Big-endian 모듈식 u64 덧셈: `dst = (dst + val) mod 2^(dst.len() * 8)`
            ///
            /// `val`을 big-endian 8바이트로 해석하여 `dst`의 최하위 바이트부터 더합니다.
            ///
            /// # 상수-시간(Constant-Time) 불변식
            ///
            /// - 반복 횟수: 항상 `dst.len()` (고정)
            /// - 조건 분기: `if i < 8`은 *인덱스*(공개 상수)에 의존하며, `dst`나 `val`의
            ///   **값**에 의존하지 않습니다.
            /// - `val`(= reseed_counter)은 비밀 데이터가 아닌 단조 증가 카운터이므로
            ///   이 경로의 타이밍 관찰은 보안 위협이 되지 않습니다.
            /// - `dst`(= 내부 상태 V)의 값은 분기 조건에 관여하지 않습니다.
            #[inline]
            fn add_u64_mod(dst: &mut [u8], val: u64) {
                let val_be = val.to_be_bytes(); // [u8; 8]
                let mut carry: u16 = 0;
                let dst_len = dst.len();

                for i in 0..dst_len {
                    let dst_idx = dst_len - 1 - i;
                    // val_be의 최하위 바이트는 val_be[7], i=0에서 사용
                    let val_byte = if i < 8 { val_be[7 - i] } else { 0u8 };
                    let sum = dst[dst_idx] as u16 + val_byte as u16 + carry;
                    dst[dst_idx] = sum as u8;
                    carry = sum >> 8;
                }
            }

            /// NIST SP 800-90A Rev. 1, Section 10.1.1.4: Hashgen
            ///
            /// 내부 상태 V를 기반으로 `requested_bytes` 길이의 출력 바이트를 생성합니다.
            ///
            /// # 상수-시간(Constant-Time) 불변식
            ///
            /// - 루프 횟수: `ceil(requested_bytes / outlen)` — `requested_bytes`(공개)에 의존,
            ///   비밀 상태 V의 **값**에 무관
            /// - 내부 상태 `V`의 복사본 `data`는 값에 무관한 순차 증가(`add_u64_mod`)만 수행
            /// - 해시 입력 크기 고정 -> 해시 연산 자체의 타이밍은 V 값에 무관
            /// - 스택 복사본 `data` 는 [`Secret`] 으로 감싸 Drop 시점에 휘발성 쓰기 + 배리어로 소거
            ///
            /// **CT 위협 모델**: Hashgen의 출력은 공개(반환값)이므로 출력 자체의 CT 보호는
            /// 불필요합니다. 보호 대상은 내부 상태 V이며, V는 외부에 직접 노출되지 않습니다.
            fn hashgen(&self, requested_bytes: usize, output: &mut [u8]) -> Result<(), DrbgError> {
                // data = V — Secret 으로 보호되어 모든 종료 경로에서 자동 소거
                let mut data = Secret::new([0u8; $seedlen]);
                data.expose_mut().copy_from_slice(self.v.as_slice());

                let m = requested_bytes.div_ceil($outlen);
                let mut written = 0usize;

                for _ in 0..m {
                    let mut hasher = <$hasher_type>::new();
                    hasher.update(data.expose());
                    let hash = hasher.finalize();
                    let hash_bytes = hash.as_bytes();

                    let copy_len = min($outlen, requested_bytes - written);
                    output[written..written + copy_len].copy_from_slice(&hash_bytes[..copy_len]);
                    written += copy_len;

                    // data = (data + 1) mod 2^seedlen (NIST 명세)
                    Self::add_u64_mod(data.expose_mut(), 1);
                }

                Ok(())
            }

            //
            //  공개 API
            //

            /// OS 엔트로피 소스로부터 Hash_DRBG를 안전하게 초기화합니다.
            ///
            /// 이것이 **권장되는 유일한 초기화 경로**입니다. 내부 `instantiate`와 달리
            /// 사용자가 엔트로피를 직접 주입할 수 없어, 예측 가능한 시드 사용 위험을 차단합니다.
            ///
            /// # 엔트로피 수집 전략 (NIST SP 800-90A Rev.1 Section 8.6.7)
            ///
            /// | 입력             | 수집 크기                       | 최솟값 대비   |
            /// |------------------|---------------------------------|--------------|
            /// | `entropy_input`  | `2 × security_strength` bytes   | 2배 여유     |
            /// | `nonce`          | `security_strength` bytes       | 2배 여유     |
            ///
            /// 두 값은 OS에 대한 **별개의 호출**로 수집되어 nonce의 독립성을 보장합니다.
            ///
            /// # 엔트로피 소스
            /// - Linux x86_64: `getrandom(2)` 직접 syscall (GRND_RANDOM 플래그 없음)
            /// - macOS aarch64: `getentropy(2)` 직접 syscall
            ///
            /// # 메모리 보안
            /// 수집된 엔트로피·nonce는 [`SecureBuffer`]로 관리되어 Drop 시 자동 소거됩니다.
            ///
            /// # Errors
            /// - `DrbgError::OsEntropyFailed`: OS 엔트로피 소스 접근 실패
            pub fn new_from_os(personalization_string: Option<&[u8]>) -> Result<Self, DrbgError> {
                // entropy_input: 2 × security_strength 바이트 (별개 호출로 독립성 보장)
                let entropy = crate::os_entropy::extract_os_entropy($min_entropy * 2)
                    .map_err(|_| DrbgError::OsEntropyFailed)?;

                // nonce: security_strength 바이트 (entropy_input과 별개 호출)
                let nonce = crate::os_entropy::extract_os_entropy($min_entropy)
                    .map_err(|_| DrbgError::OsEntropyFailed)?;

                // SecureBuffer는 Drop 시 자동 소거 — 별도 write_volatile 루프 불필요
                Self::instantiate(entropy.as_slice(), nonce.as_slice(), personalization_string)
            }

            /// 호출자가 수집한 하드웨어 엔트로피로 DRBG를 초기화합니다.
            ///
            /// OS 엔트로피 소스가 없는 bare-metal / no_std 환경(커널 부트, TEE 등)에서
            /// RDSEED / RDRAND / TRNG 등으로 직접 수집한 엔트로피를 주입할 때 사용합니다.
            ///
            /// # Arguments
            /// - `entropy_input`: `security_strength` 이상의 고엔트로피 시드
            /// - `nonce`: `security_strength / 2` 이상 (엔트로피와 **독립** 수집 필수)
            /// - `personalization_string`: 호스트 고유 식별자 / 부트 ID 등 (선택)
            ///
            /// # Safety
            /// 호출자는 다음을 보장해야 합니다:
            /// - `entropy_input` 및 `nonce` 는 암호학적으로 강한 엔트로피 소스에서
            ///   수집된 값이어야 합니다 (예: x86 RDSEED · RDRAND, ARM RNDR/RNDRRS, TPM).
            /// - 두 입력은 **독립된 호출** 로 수집되어야 하며, 시간/카운터 등
            ///   예측 가능한 값을 그대로 사용해서는 안 됩니다.
            /// - 동일 `entropy_input` / `nonce` 조합을 재사용하면 DRBG 상태가 결정적이
            ///   되어 출력이 재생(replay)될 수 있습니다.
            ///
            /// # Security Note
            /// 약한 엔트로피를 주입하면 DRBG 출력이 공격자에게 예측 가능하게 되어
            /// 상위 계층(키 생성, Capability 토큰, IV)의 보안이 붕괴됩니다.
            /// 가능한 경우 [`new_from_os`] 를 우선 사용하고, 이 함수는 OS 엔트로피
            /// 소스를 사용할 수 없는 경우에만 사용하세요.
            pub unsafe fn new_from_entropy(
                entropy_input: &[u8],
                nonce: &[u8],
                personalization_string: Option<&[u8]>,
            ) -> Result<Self, DrbgError> {
                Self::instantiate(entropy_input, nonce, personalization_string)
            }

            /// NIST SP 800-90A Rev. 1, Section 10.1.1.2: Hash_DRBG_Instantiate_algorithm
            ///
            /// 사용자가 엔트로피를 직접 주입하는 내부 초기화 함수입니다.
            ///
            /// # 보안 요구사항
            /// - `entropy_input`: `security_strength` ~ 125 bytes (충분한 무작위성 필수)
            /// - `nonce`: `security_strength / 2` bytes 이상 (재사용 금지)
            /// - `personalization_string`: 선택적 (최대 125 bytes 권장)
            ///
            /// # 주의 (보안)
            /// 이 함수는 **크레이트 내부 전용**입니다. 외부에서 임의 엔트로피를 주입하면
            /// DRBG 출력의 무작위성이 공격자에 의해 제어될 수 있습니다.
            /// 외부 코드는 반드시 [`new_from_os`]를 통해 OS 엔트로피로 초기화하세요.
            pub(crate) fn instantiate(
                entropy_input: &[u8],
                nonce: &[u8],
                personalization_string: Option<&[u8]>,
            ) -> Result<Self, DrbgError> {
                // NIST SP 800-90A Rev. 1, Section 8.6.7 검증
                if entropy_input.len() < $min_entropy {
                    return Err(DrbgError::EntropyTooShort);
                }
                if (entropy_input.len() as u64) > MAX_LENGTH {
                    return Err(DrbgError::EntropyTooLong);
                }
                // nonce 최소 길이: security_strength / 2
                if nonce.len() < ($min_entropy / 2) {
                    return Err(DrbgError::NonceTooShort);
                }
                if (nonce.len() as u64) > MAX_LENGTH {
                    return Err(DrbgError::NonceTooLong);
                }

                let ps = personalization_string.unwrap_or(&[]);
                if (ps.len() as u64) > MAX_ADDITIONAL_INPUT {
                    return Err(DrbgError::InputTooLong);
                }

                // V = Hash_df(entropy_input || nonce || personalization_string, seedlen)
                let mut v_buf =
                    SecureBuffer::new_owned($seedlen).map_err(|_| DrbgError::AllocationFailed)?;
                Self::hash_df(&[entropy_input, nonce, ps], $seedlen, v_buf.as_mut_slice())?;

                // C = Hash_df(0x00 || V, seedlen)
                let mut c_buf =
                    SecureBuffer::new_owned($seedlen).map_err(|_| DrbgError::AllocationFailed)?;
                Self::hash_df(
                    &[&[0x00u8], v_buf.as_slice()],
                    $seedlen,
                    c_buf.as_mut_slice(),
                )?;

                Ok(Self {
                    v: v_buf,
                    c: c_buf,
                    reseed_counter: 1,
                })
            }

            /// NIST SP 800-90A Rev. 1, Section 10.1.1.3: Hash_DRBG_Reseed_algorithm
            ///
            /// 새로운 엔트로피로 내부 상태를 갱신합니다.
            /// `ReseedRequired` 에러 수신 후 반드시 호출해야 합니다.
            pub fn reseed(
                &mut self,
                entropy_input: &[u8],
                additional_input: Option<&[u8]>,
            ) -> Result<(), DrbgError> {
                if entropy_input.len() < $min_entropy {
                    return Err(DrbgError::EntropyTooShort);
                }
                if (entropy_input.len() as u64) > MAX_LENGTH {
                    return Err(DrbgError::EntropyTooLong);
                }

                let ai = additional_input.unwrap_or(&[]);
                if (ai.len() as u64) > MAX_ADDITIONAL_INPUT {
                    return Err(DrbgError::InputTooLong);
                }

                // new_V = Hash_df(0x01 || V || entropy_input || additional_input, seedlen)
                // Secret 으로 감싸 ? 조기 반환 시에도 부분 결과가 메모리에 남지 않도록 함.
                let mut new_v = Secret::new([0u8; $seedlen]);
                Self::hash_df(
                    &[&[0x01u8], self.v.as_slice(), entropy_input, ai],
                    $seedlen,
                    new_v.expose_mut(),
                )?;
                self.v.as_mut_slice().copy_from_slice(new_v.expose());

                // new_C = Hash_df(0x00 || new_V, seedlen)
                let mut new_c = Secret::new([0u8; $seedlen]);
                Self::hash_df(
                    &[&[0x00u8], self.v.as_slice()],
                    $seedlen,
                    new_c.expose_mut(),
                )?;
                self.c.as_mut_slice().copy_from_slice(new_c.expose());

                self.reseed_counter = 1;
                Ok(())
            }

            /// OS 엔트로피 소스로부터 신선한 엔트로피를 수집하여 안전하게 reseed 합니다.
            ///
            /// [`new_from_os`](Self::new_from_os) 와 대칭인 권장 reseed 경로입니다.
            /// 호출자가 엔트로피를 직접 주입하는 [`reseed`](Self::reseed) 와 달리 OS
            /// CSPRNG 에서 직접 수집하여, 예측 가능하거나 약한 엔트로피 주입 위험을
            /// 차단합니다. `ReseedRequired` 수신 후 이 경로를 우선 사용하세요.
            ///
            /// # 엔트로피 수집 전략 (NIST SP 800-90A Rev.1 Section 8.6.7)
            /// `entropy_input` 으로 `2 × security_strength` bytes 를 수집합니다
            /// (new_from_os 와 동일하게 2배 여유).
            ///
            /// # 메모리 보안
            /// 수집된 엔트로피는 [`SecureBuffer`]로 관리되어 Drop 시 자동 소거됩니다.
            ///
            /// # Errors
            /// - `DrbgError::OsEntropyFailed`: OS 엔트로피 소스 접근 실패
            /// - `DrbgError::InputTooLong`: `additional_input` 이 최대 허용 길이 초과
            pub fn reseed_from_os(
                &mut self,
                additional_input: Option<&[u8]>,
            ) -> Result<(), DrbgError> {
                // entropy_input: 2 × security_strength 바이트 (new_from_os 와 동일 전략)
                let entropy = crate::os_entropy::extract_os_entropy($min_entropy * 2)
                    .map_err(|_| DrbgError::OsEntropyFailed)?;

                // SecureBuffer 는 Drop 시 자동 소거 — 별도 소거 루프 불필요
                self.reseed(entropy.as_slice(), additional_input)
            }

            /// NIST SP 800-90A Rev. 1, Section 10.1.1.4: Hash_DRBG_Generate_algorithm
            ///
            /// `output.len()` 바이트의 의사난수를 생성합니다.
            ///
            /// # 에러
            /// - `ReseedRequired`: reseed 간격(2^48) 초과 — `reseed()` 후 재호출
            /// - `RequestTooLarge`: 요청 크기가 65536 bytes 초과
            pub fn generate(
                &mut self,
                output: &mut [u8],
                additional_input: Option<&[u8]>,
            ) -> Result<(), DrbgError> {
                if output.len() > MAX_BYTES_PER_REQUEST {
                    return Err(DrbgError::RequestTooLarge);
                }
                // reseed 간격 강제 검사
                if self.reseed_counter > RESEED_INTERVAL {
                    return Err(DrbgError::ReseedRequired);
                }

                // additional_input 처리
                // 표준상 additional_input != Null 이면 길이 0이어도 w 경로 실행
                // -> Some(&[]) 은 None 과 구분되어 V 를 갱신, None 만 skip
                if let Some(ai) = additional_input {
                    if (ai.len() as u64) > MAX_ADDITIONAL_INPUT {
                        return Err(DrbgError::InputTooLong);
                    }
                    // w = Hash(0x02 || V || additional_input)
                    let mut hasher = <$hasher_type>::new();
                    hasher.update(&[0x02u8]);
                    hasher.update(self.v.as_slice());
                    hasher.update(ai);
                    let w = hasher.finalize();

                    // w(outlen bytes)를 seedlen bytes로 오른쪽 정렬 (big-endian MSB=0 패딩)
                    // V = (V + w) mod 2^seedlen — Secret 으로 자동 소거
                    let mut w_padded = Secret::new([0u8; $seedlen]);
                    w_padded.expose_mut()[$seedlen - $outlen..].copy_from_slice(w.as_bytes());
                    Self::add_mod(self.v.as_mut_slice(), w_padded.expose());
                }

                // returned_bits = Hashgen(requested_bytes, V)
                self.hashgen(output.len(), output)?;

                // H = Hash(0x03 || V)
                let mut hasher = <$hasher_type>::new();
                hasher.update(&[0x03u8]);
                hasher.update(self.v.as_slice());
                let h = hasher.finalize();

                // V = (V + H + C + reseed_counter) mod 2^seedlen
                // H(outlen bytes)를 seedlen bytes로 오른쪽 정렬 후 덧셈
                let mut h_padded = Secret::new([0u8; $seedlen]);
                h_padded.expose_mut()[$seedlen - $outlen..].copy_from_slice(h.as_bytes());
                Self::add_mod(self.v.as_mut_slice(), h_padded.expose());

                // C를 스택에 복사 후 V에 덧셈 (self.v와 self.c 동시 대여 회피)
                let mut c_copy = Secret::new([0u8; $seedlen]);
                c_copy.expose_mut().copy_from_slice(self.c.as_slice());
                Self::add_mod(self.v.as_mut_slice(), c_copy.expose());

                // reseed_counter를 V에 덧셈
                Self::add_u64_mod(self.v.as_mut_slice(), self.reseed_counter);
                self.reseed_counter += 1;

                Ok(())
            }
        }

        /// 메모리 잔존 공격 방지: reseed_counter 강제 소거
        ///
        /// SecureBuffer(V, C)는 자체 Drop 에서 자동 소거됩니다.
        /// 본 Drop 본문 종료 후 필드 Drop 이 선언 순서대로 실행되어 V, C 가 소거됩니다.
        impl Drop for $struct_name {
            #[inline]
            fn drop(&mut self) {
                self.reseed_counter.zeroize();
            }
        }
    };
}

// NIST SP 800-90A Rev. 1, Table 2 파라미터
// 구조체, 해셔, 출력길이, 시드길이, 최소엔트로피
impl_hash_drbg!(HashDRBGSHA224, SHA224, 28, 55, 14); // security_strength=112 bits
impl_hash_drbg!(HashDRBGSHA256, SHA256, 32, 55, 16); // security_strength=128 bits
impl_hash_drbg!(HashDRBGSHA384, SHA384, 48, 111, 24); // security_strength=192 bits
impl_hash_drbg!(HashDRBGSHA512, SHA512, 64, 111, 32); // security_strength=256 bits !Recommended!

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_SECURE_BUFFER_LEN;
    use core::mem::MaybeUninit;

    /// SHA-256 기반 Hash_DRBG 의 Drop 후 V, C, reseed_counter 가 모두 0 으로 소거됨을 확인.
    #[test]
    fn test_hash_drbg_sha256_zeroize_on_drop() {
        let entropy = [0xAAu8; 32];
        let nonce = [0x55u8; 16];

        let mut storage: MaybeUninit<HashDRBGSHA256> = MaybeUninit::uninit();

        unsafe {
            let drbg =
                HashDRBGSHA256::new_from_entropy(&entropy, &nonce, None).expect("instantiate");
            storage.write(drbg);

            let v_data_ptr = (&raw const (*storage.as_ptr()).v.data) as *const u8;
            let c_data_ptr = (&raw const (*storage.as_ptr()).c.data) as *const u8;
            let counter_ptr = &raw const (*storage.as_ptr()).reseed_counter;

            // 사전 검증: V, C 활성 영역 (seedlen=55B) 에 instantiate 결과가 채워져 있어야 함
            let pre_v = core::slice::from_raw_parts(v_data_ptr, MAX_SECURE_BUFFER_LEN);
            let pre_c = core::slice::from_raw_parts(c_data_ptr, MAX_SECURE_BUFFER_LEN);
            assert!(
                pre_v[..55].iter().any(|&b| b != 0),
                "V 활성 영역이 비어있음 (instantiate 실패?)"
            );
            assert!(
                pre_c[..55].iter().any(|&b| b != 0),
                "C 활성 영역이 비어있음 (instantiate 실패?)"
            );
            assert_eq!(core::ptr::read(counter_ptr), 1u64);

            storage.assume_init_drop();

            let post_v = core::slice::from_raw_parts(v_data_ptr, MAX_SECURE_BUFFER_LEN);
            let post_c = core::slice::from_raw_parts(c_data_ptr, MAX_SECURE_BUFFER_LEN);
            assert!(
                post_v.iter().all(|&b| b == 0),
                "DRBG V 미소거: {:?}",
                post_v
            );
            assert!(
                post_c.iter().all(|&b| b == 0),
                "DRBG C 미소거: {:?}",
                post_c
            );
            assert_eq!(
                core::ptr::read(counter_ptr),
                0u64,
                "DRBG reseed_counter 미소거"
            );
        }
    }

    /// SHA-512 기반 (seedlen=111B) Hash_DRBG 도 동일하게 소거됨을 확인.
    #[test]
    fn test_hash_drbg_sha512_zeroize_on_drop() {
        let entropy = [0xBBu8; 64];
        let nonce = [0x44u8; 32];

        let mut storage: MaybeUninit<HashDRBGSHA512> = MaybeUninit::uninit();

        unsafe {
            let drbg =
                HashDRBGSHA512::new_from_entropy(&entropy, &nonce, None).expect("instantiate");
            storage.write(drbg);

            let v_data_ptr = (&raw const (*storage.as_ptr()).v.data) as *const u8;
            let c_data_ptr = (&raw const (*storage.as_ptr()).c.data) as *const u8;
            let counter_ptr = &raw const (*storage.as_ptr()).reseed_counter;

            let pre_v = core::slice::from_raw_parts(v_data_ptr, MAX_SECURE_BUFFER_LEN);
            assert!(pre_v[..111].iter().any(|&b| b != 0), "V 활성 영역 미반영");

            storage.assume_init_drop();

            let post_v = core::slice::from_raw_parts(v_data_ptr, MAX_SECURE_BUFFER_LEN);
            let post_c = core::slice::from_raw_parts(c_data_ptr, MAX_SECURE_BUFFER_LEN);
            assert!(post_v.iter().all(|&b| b == 0), "SHA512 DRBG V 미소거");
            assert!(post_c.iter().all(|&b| b == 0), "SHA512 DRBG C 미소거");
            assert_eq!(core::ptr::read(counter_ptr), 0u64, "counter 미소거");
        }
    }

    /// generate / reseed 후에도 Drop 시점에 내부 상태가 0 으로 소거되는지 확인.
    #[test]
    fn test_hash_drbg_after_generate_reseed_zeroize() {
        let entropy = [0xCCu8; 32];
        let nonce = [0x33u8; 16];

        let mut storage: MaybeUninit<HashDRBGSHA256> = MaybeUninit::uninit();

        unsafe {
            let mut drbg =
                HashDRBGSHA256::new_from_entropy(&entropy, &nonce, None).expect("instantiate");

            let mut out = [0u8; 64];
            drbg.generate(&mut out, Some(b"ai-1")).expect("generate-1");
            assert!(out.iter().any(|&b| b != 0), "generate 출력이 0 임");

            let new_entropy = [0x77u8; 32];
            drbg.reseed(&new_entropy, Some(b"ai-2")).expect("reseed");

            drbg.generate(&mut out, None).expect("generate-2");

            storage.write(drbg);

            let v_data_ptr = (&raw const (*storage.as_ptr()).v.data) as *const u8;
            let c_data_ptr = (&raw const (*storage.as_ptr()).c.data) as *const u8;
            let counter_ptr = &raw const (*storage.as_ptr()).reseed_counter;

            // reseed 로 counter=1 리셋 후 generate-2 로 +1 → 2
            assert_eq!(core::ptr::read(counter_ptr), 2u64, "counter 추적 실패");

            storage.assume_init_drop();

            let post_v = core::slice::from_raw_parts(v_data_ptr, MAX_SECURE_BUFFER_LEN);
            let post_c = core::slice::from_raw_parts(c_data_ptr, MAX_SECURE_BUFFER_LEN);
            assert!(post_v.iter().all(|&b| b == 0), "Drop 후 V 미소거");
            assert!(post_c.iter().all(|&b| b == 0), "Drop 후 C 미소거");
            assert_eq!(core::ptr::read(counter_ptr), 0u64, "Drop 후 counter 미소거");
        }
    }

    /// 같은 엔트로피·nonce 입력 시 결정론적 출력을 검증 (회귀 방지용).
    #[test]
    fn test_hash_drbg_deterministic_output() {
        let entropy = [0x11u8; 32];
        let nonce = [0x22u8; 16];

        unsafe {
            let mut a =
                HashDRBGSHA256::new_from_entropy(&entropy, &nonce, None).expect("instantiate-a");
            let mut b =
                HashDRBGSHA256::new_from_entropy(&entropy, &nonce, None).expect("instantiate-b");

            let mut out_a = [0u8; 128];
            let mut out_b = [0u8; 128];
            a.generate(&mut out_a, None).expect("generate-a");
            b.generate(&mut out_b, None).expect("generate-b");
            assert_eq!(out_a, out_b, "결정론적 출력 검증 실패");
        }
    }

    /// F-2: 빈 additional_input(Some(&[]))이 None 과 다른 경로로 처리됨을 검증.
    /// 표준상 additional_input != Null 이면 길이 0이어도 w 경로가 V 를 갱신해야 함.
    #[test]
    fn test_hash_drbg_empty_additional_input_differs_from_none() {
        let entropy = [0x11u8; 32];
        let nonce = [0x22u8; 16];

        unsafe {
            let mut a =
                HashDRBGSHA256::new_from_entropy(&entropy, &nonce, None).expect("instantiate-a");
            let mut b =
                HashDRBGSHA256::new_from_entropy(&entropy, &nonce, None).expect("instantiate-b");

            let mut out_empty = [0u8; 64];
            let mut out_none = [0u8; 64];
            a.generate(&mut out_empty, Some(&[]))
                .expect("generate-empty");
            b.generate(&mut out_none, None).expect("generate-none");
            assert_ne!(
                out_empty, out_none,
                "빈 additional_input 이 None 과 동일 취급됨 (표준 위반)"
            );
        }
    }

    /// F-1: reseed_from_os 가 OS 엔트로피로 재시드하고 카운터를 1 로 리셋함을 검증.
    /// OS 엔트로피가 가용한 호스트(예: aarch64-apple-darwin)에서만 통과.
    #[test]
    fn test_hash_drbg_reseed_from_os() {
        let entropy = [0x33u8; 32];
        let nonce = [0x44u8; 16];

        unsafe {
            let mut drbg =
                HashDRBGSHA256::new_from_entropy(&entropy, &nonce, None).expect("instantiate");

            let mut out = [0u8; 32];
            drbg.generate(&mut out, None).expect("generate-1"); // counter -> 2
            drbg.reseed_from_os(None).expect("reseed_from_os"); // counter -> 1
            assert_eq!(drbg.reseed_counter, 1, "reseed_from_os 후 카운터 미리셋");

            drbg.generate(&mut out, None).expect("generate-2"); // counter -> 2
            assert_eq!(drbg.reseed_counter, 2, "generate 후 카운터 미증가");
            assert!(out.iter().any(|&b| b != 0), "재시드 후 출력이 0");
        }
    }
}
