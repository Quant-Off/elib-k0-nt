//! AArch64 PSTATE.DIT 비트를 트랜잭션 단위로 설정하고 복원하는 RAII 가드가
//! 구현된 모듈입니다.
//!
//! ARM은 FEAT_DIT(ARMv8.4-A 이상)가 구현되고 PSTATE.DIT가 1인 경우에만
//! `cmp`/`csel`/`cset` 등 DIT 목록 명령의 데이터 독립 시간을 아키텍처
//! 차원에서 보장합니다. 이 모듈은 암호 연산 진입 시 DIT를 켜고 이탈 시 이전
//! 상태로 복원하는 옵트인 가드를 제공합니다.
//!
//! FEAT_DIT 미구현 코어에서 DIT 레지스터 접근은 UNDEFINED 트랩이므로 실제
//! 접근 코드는 `target_feature = "dit"`가 컴파일 타임에 활성화된 경우에만
//! 생성됩니다. 런타임 기능 감지는 EL0 순수 라이브러리에서 커널 협조 없이
//! 불가능하므로 제공하지 않습니다. 그 외 모든 빌드(x86_64 포함)에서 가드는
//! no-op이며, 하드웨어 보장 여부는 [`DIT_HW_BACKED`]로 구분합니다.
//!
//! # Features
//! - `DitGuard`: 생성 시 이전 PSTATE.DIT 저장 후 1로 설정, Drop 시 복원
//! - `DIT_HW_BACKED`: 현재 빌드에서 가드가 실제 하드웨어 보장을 제공하는지 여부
//!
//! # Security Note
//! x86_64의 대응 기능인 DOITM(IA32_UARCH_MISC_CTL)은 Ring 0 전용 MSR 이므로
//! 이 크레이트가 Ring 3에서 설정할 수 없습니다. x86_64 배포에서는 커널이
//! 부트 시 DOITM을 설정해야 하며 이는 통합 측 책임입니다.
//!
//! # Examples
//! ```rust,ignore
//! let _dit = DitGuard::enter();
//! // 이 스코프의 상수-시간 연산은 DIT 활성 상태에서 수행됨
//! ```

/// 현재 빌드에서 `DitGuard`가 실제 하드웨어 DIT 설정을 수행하는지 여부입니다.
///
/// `target_arch = "aarch64"` 이면서 `target_feature = "dit"`가 활성화된
/// 빌드에서만 `true` 입니다. `false`인 빌드에서 가드는 no-op 입니다.
pub const DIT_HW_BACKED: bool = cfg!(all(target_arch = "aarch64", target_feature = "dit"));

#[cfg(all(target_arch = "aarch64", target_feature = "dit"))]
mod imp {
    // DIT 특수 레지스터의 PSTATE.DIT 비트 위치
    const DIT_BIT: u64 = 1 << 24;

    /// 생성 시 PSTATE.DIT를 1로 설정하고 Drop 시 이전 값으로 복원하는
    /// RAII 가드 구조체입니다.
    ///
    /// 중첩 생성이 안전합니다. 각 가드는 자신이 관측한 이전 값만 복원하므로
    /// 안쪽 가드가 해제되어도 바깥 가드의 활성 상태가 유지됩니다.
    ///
    /// # Security Note
    /// PSTATE.DIT는 스레드별 상태입니다. 가드가 살아 있는 동안 수행되는
    /// DIT 목록 명령만 아키텍처 차원의 데이터 독립 시간을 보장받습니다.
    #[must_use = "가드가 즉시 해제되면 DIT 보장이 적용되지 않음"]
    pub struct DitGuard {
        prev: u64,
    }

    impl DitGuard {
        /// 이전 PSTATE.DIT 값을 저장한 뒤 DIT를 1로 설정하는 함수입니다.
        ///
        /// # Safety
        /// `mrs`/`msr`로 DIT 특수 레지스터(인코딩 값: S3_3_C4_C2_5)만 접근합니다.
        /// 이 코드는 `target_feature = "dit"` 빌드에서만 생성되므로 UNDEFINED
        /// 트랩이 발생하지 않습니다. `nomem`을 지정하지 않아 컴파일러가
        /// 메모리 연산을 가드 경계 밖으로 재배치하지 못하며 `nostack`,
        /// `preserves_flags`로 스택과 조건 플래그를 건드리지 않습니다.
        #[inline]
        pub fn enter() -> Self {
            let prev: u64;
            unsafe {
                core::arch::asm!(
                    "mrs {p}, S3_3_C4_C2_5",
                    "msr S3_3_C4_C2_5, {v}",
                    p = out(reg) prev,
                    v = in(reg) DIT_BIT,
                    options(nostack, preserves_flags),
                );
            }
            Self { prev }
        }
    }

    impl Drop for DitGuard {
        /// 생성 시 저장한 이전 PSTATE.DIT 값을 복원하는 함수입니다.
        ///
        /// # Safety
        /// `enter`와 동일한 근거로 안전합니다. 기록 값은 DIT 비트만 유효하고
        /// 나머지 비트는 무시되므로 저장해 둔 원시 값을 그대로 되씁니다.
        #[inline]
        fn drop(&mut self) {
            unsafe {
                core::arch::asm!(
                    "msr S3_3_C4_C2_5, {v}",
                    v = in(reg) self.prev,
                    options(nostack, preserves_flags),
                );
            }
        }
    }
}

#[cfg(not(all(target_arch = "aarch64", target_feature = "dit")))]
mod imp {
    /// DIT 미지원 빌드에서 동일한 API를 제공하는 no-op 가드 구조체입니다.
    ///
    /// # Security Note
    /// 이 변형은 어떤 하드웨어 상태도 변경하지 않습니다. 아키텍처 차원의
    /// DIT 보장이 필요한 배포는 [`super::DIT_HW_BACKED`]로 빌드 구성을
    /// 검증해야 합니다.
    #[must_use = "가드가 즉시 해제되면 DIT 보장이 적용되지 않음"]
    pub struct DitGuard {
        _priv: (),
    }

    impl DitGuard {
        /// 아무 상태도 변경하지 않고 가드를 생성하는 함수입니다.
        #[inline]
        pub fn enter() -> Self {
            Self { _priv: () }
        }
    }
}

pub use imp::DitGuard;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_arch = "aarch64", target_feature = "dit"))]
    fn read_dit_bit() -> u64 {
        let raw: u64;
        unsafe {
            core::arch::asm!(
                "mrs {r}, S3_3_C4_C2_5",
                r = out(reg) raw,
                options(nostack, preserves_flags),
            );
        }
        (raw >> 24) & 1
    }

    // 빌드 구성과 상수가 일치해야 배포 측이 하드웨어 보장 여부를 신뢰할 수 있음
    #[test]
    fn dit_hw_backed_matches_build_config() {
        assert_eq!(
            DIT_HW_BACKED,
            cfg!(all(target_arch = "aarch64", target_feature = "dit")),
            "DIT_HW_BACKED 가 빌드 구성과 불일치"
        );
    }

    // 가드 생존 중 DIT=1, 해제 후 이전 값 복원이 RAII의 핵심
    #[cfg(all(target_arch = "aarch64", target_feature = "dit"))]
    #[test]
    fn dit_guard_sets_and_restores() {
        let before = read_dit_bit();
        {
            let _g = DitGuard::enter();
            assert_eq!(read_dit_bit(), 1, "가드 생존 중 DIT 미설정");
        }
        assert_eq!(read_dit_bit(), before, "가드 해제 후 DIT 미복원");
    }

    // 중첩 가드에서 안쪽 해제가 바깥 가드의 활성 상태를 깨면 안 됨
    #[cfg(all(target_arch = "aarch64", target_feature = "dit"))]
    #[test]
    fn dit_guard_nesting_preserves_outer() {
        let before = read_dit_bit();
        {
            let _outer = DitGuard::enter();
            {
                let _inner = DitGuard::enter();
                assert_eq!(read_dit_bit(), 1, "중첩 가드 생존 중 DIT 미설정");
            }
            assert_eq!(read_dit_bit(), 1, "안쪽 가드 해제가 바깥 가드 상태를 훼손");
        }
        assert_eq!(read_dit_bit(), before, "전체 해제 후 DIT 미복원");
    }
}
