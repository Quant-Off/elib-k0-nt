//! x86_64와 aarch64 인-라인 어셈블리 기반 상수-시간 내부 프리미티브가 구현된 모듈입니다.
//!
//! 미지원 아키텍처에서는 `core::hint::black_box`에 의존하는 best-effort
//! fallback을 제공합니다. 모든 함수는 비밀 의존 분기나 데이터 의존 경로
//! 없이 동작하며 반환값은 항상 0 또는 1 범위로 유지됩니다.
//!
//! # Features
//! 다음 계열별 기능을 32비트와 64비트 폭으로 제공합니다.
//!
//! - `ct_sel`: 조건에 따라 한쪽 값 선택, 조건이 0이 아니면 a를, 0이면 b를 반환
//! - `ct_eq`: 동등 여부 판정, 두 값이 같으면 1을, 다르면 0을 반환
//! - `ct_gt`: 대소 판정, a가 b보다 크면 1을, 아니면 0을 반환
//!
//! 부호 있는 비교에서 더 작은 정수 타입은 호출자가 i64 로 부호 확장한 뒤 ct_gt_i64에
//! 전달합니다. 또한 64비트 프리미티브 위에 구성된 아키텍처 독립 128비트 래퍼인
//! `ct_eq128`, `ct_gt_u128`, `ct_gt_i128`을 제공합니다. x86_64와
//! aarch64에서는 인-라인 어셈블리로 하드웨어 수준 상수-시간을 보장하고 그 외
//! 아키텍처에서는 `black_box`로 최적화를 억제하는 fallback으로 동작합니다.
//!
//! # Examples
//! ```rust,ignore
//! let chosen = ct_sel32(1, 0xAAAA_AAAA, 0x5555_5555);
//! let equal = ct_eq64(7, 7);
//! let greater = ct_gt_u32(9, 4);
//! ```

#[cfg(all(not(miri), not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
compile_error!(
    "constant-time 의 검증된 상수-시간 구현은 x86_64와 AArch64 아키텍처에서만 제공됩니다. \
     이 아키텍처의 fallback은 black_box 기반 방법이며, 하드웨어 수준 상수-시간을 \
     보장하지 않으므로 고보안 빌드를 거부합니다. 테스트 목적이면 miri를 통해 실행하세요."
);

#[cfg(all(target_arch = "x86_64", not(miri)))]
mod x86_64;

#[cfg(all(target_arch = "aarch64", not(miri)))]
mod aarch64;

mod ct128;

#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
mod fallback;

#[cfg(all(target_arch = "x86_64", not(miri)))]
pub(crate) use x86_64::*;

#[cfg(all(target_arch = "aarch64", not(miri)))]
pub(crate) use aarch64::*;

pub(crate) use ct128::*;

#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub(crate) use fallback::*;
