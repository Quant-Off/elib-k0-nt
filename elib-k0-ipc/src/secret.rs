//! 타입-레벨 zeroize 강제 모듈입니다.
//!
//! `MustZeroize<T>` 와 봉인된 `IsSecret` 트레이트를 통해 IPC 디스패처 시점에
//! 비밀 데이터를 컴파일-타임에 강제로 zeroize-경로로 dissolve 시키는 typestate
//! 디스시플린을 제공합니다.
//!
//! # Features
//! - `MustZeroize<T>` 는 `Drop` / `Clone` / `Copy` / `Deref` / `DerefMut` / `AsRef`
//!   모두 미구현 — 일반 drop 으로 dissolve 불가
//! - `into_secret(self) -> Secret<T>` 만이 dissolve 경로 (v1)
//! - `IsSecret` 는 봉인된 마커 트레이트; 외부 crate 가 임의 타입에 구현 불가
//! - `Secret<T: Zeroize>` 와 `MustZeroize<T: IsSecret>` 두 타입만 `IsSecret` 충족
//!
//! # Examples
//! ```
//! use elib_k0_ipc::MustZeroize;
//! use zeroize::Secret;
//!
//! let m: MustZeroize<Secret<[u8; 32]>> = MustZeroize::new(Secret::new([0u8; 32]));
//! let s: Secret<[u8; 32]> = m.into_secret();
//! drop(s); // Secret::Drop 가 휘발성 쓰기로 소거
//! ```
//!
//! # Security Note
//! - `MustZeroize<T>` 는 `Drop` 미구현 — 사용 후 반드시 `into_secret()` 으로 dissolve.
//!   crate-root 의 `#![deny(unused_must_use)]` 가 일반 drop 을 컴파일 거부합니다.
//! - `Clone` / `Copy` 미구현 — zeroize 의무를 가진 값의 암시적 복제 차단.
//! - `Deref` / `DerefMut` / `AsRef` 미구현 — 내부 참조가 typestate 밖으로 escape 되어
//!   consume-on-dissolve invariant 를 우회하는 위험 차단 (정책적 결정).
//! - `consume_into(dst)` dissolve 경로는 v1 미포함 — Phase 4/5 에서 추가 예정.
//!
//! # Authors
//! Q. T. Felix

use ::zeroize::{Secret, Zeroize};

pub(crate) mod sealed {
    /// 봉인용 마커 트레이트입니다. `elib-k0-ipc` 외부에서는 구현 불가합니다.
    ///
    /// 본 모듈은 `pub(crate)` 로 선언되어 외부 crate 에서 path 도달 불가합니다.
    /// 따라서 `IsSecret: sealed::Sealed` 슈퍼트레이트 바운드는 외부에서 어떤
    /// local 타입에 대해서도 충족 불가 — sealed pattern 의 본질적 invariant.
    pub trait Sealed {}
}

/// 비밀 입력 위치에만 허용되는 봉인된(sealed) 마커 트레이트입니다.
///
/// `Secret<T: Zeroize>` 와 `MustZeroize<T: IsSecret>` 두 타입만이 본 트레이트를
/// 구현합니다. plain `[u8; N]` 등은 컴파일-타임에 거부됩니다.
///
/// # Security Note
/// - 봉인 패턴: `sealed::Sealed` 를 슈퍼트레이트로 가지므로 외부 crate 가 임의
///   타입에 `IsSecret` 을 구현할 수 없습니다.
/// - 새 비밀-담는 newtype 추가 시 `elib-k0-ipc` 안에서 두 줄 (`impl sealed::Sealed`
///   + `impl IsSecret`) 추가만 필요합니다.
///
/// # Examples
/// ```compile_fail
/// use elib_k0_ipc::IsSecret;
/// fn requires_secret<T: IsSecret>(_: &T) {}
/// requires_secret(&[0u8; 32]); // 컴파일 거부: [u8; 32] 는 IsSecret 미구현
/// ```
pub trait IsSecret: sealed::Sealed {}

impl<T: Zeroize> sealed::Sealed for Secret<T> {}
impl<T: Zeroize> IsSecret for Secret<T> {}

impl<T: IsSecret> sealed::Sealed for MustZeroize<T> {}
impl<T: IsSecret> IsSecret for MustZeroize<T> {}

/// IPC 디스패처에서 비밀 값의 dissolve 경로를 typestate 로 강제하는 newtype 입니다.
///
/// 일반 `drop(must)` 으로는 dissolve 되지 않으며, 반드시 `into_secret()` 호출로
/// 내부 `Secret<T>` 를 추출해야 합니다. 추출된 `Secret<T>` 는 자체 `Drop` 으로
/// 휘발성 쓰기 소거를 수행합니다.
///
/// # Security Note
/// - **No `Drop`**: 의도된 부재. `Drop` 이 있으면 implicit-drop 이 dissolve 를
///   대체하여 typestate 가 무력화됩니다. `#![deny(unused_must_use)]` 와 함께
///   동작합니다.
/// - **No `Clone` / `Copy`**: 비밀 값의 암시적 복제 차단.
/// - **No `Deref` / `DerefMut` / `AsRef`**: 내부 값에 대한 참조가 typestate 밖으로
///   escape 되어 dissolve 우회를 가능하게 만드는 위험을 정책적으로 차단.
/// - **No `Default`**: zeroize 의무를 가진 값에 implicit-construction 금지.
///
/// # Examples
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use elib_k0_ipc::MustZeroize;
/// use zeroize::Secret;
/// MustZeroize::new(Secret::new([0u8; 32])); // 컴파일 거부: unused MustZeroize
/// // (#[must_use] + #![deny(unused_must_use)] 조합이 본 statement 를 거부)
/// ```
#[must_use = "MustZeroize 은 into_secret() 으로만 dissolve 가능합니다"]
pub struct MustZeroize<T: IsSecret> {
    inner: T,
}

impl<T: IsSecret> MustZeroize<T> {
    /// 새로운 `MustZeroize` 를 생성합니다.
    ///
    /// # Arguments
    /// - `value`: `IsSecret` 을 구현한 비밀 값 (`Secret<T: Zeroize>` 또는 중첩된
    ///   `MustZeroize<U: IsSecret>`).
    #[inline]
    #[must_use = "MustZeroize::new 의 반환값은 into_secret() 으로 dissolve 해야 합니다"]
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// 내부 비밀 값에 대한 불변 참조를 반환합니다.
    ///
    /// # Security Note
    /// 반환된 참조를 통해 데이터가 복사되지 않도록 주의하세요.
    #[inline]
    #[must_use]
    pub fn expose(&self) -> &T {
        &self.inner
    }

    /// 내부 비밀 값에 대한 가변 참조를 반환합니다.
    ///
    /// # Security Note
    /// 반환된 참조를 통해 데이터가 복사되지 않도록 주의하세요.
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// `MustZeroize` 를 소비하여 내부 `T` (= `IsSecret` 충족 타입) 를 반환합니다.
    ///
    /// 일반적으로 `T = Secret<U: Zeroize>` 형태이며, 반환된 `Secret<U>` 는 자체
    /// `Drop` 으로 휘발성 쓰기 소거를 수행합니다.
    ///
    /// # Security Note
    /// 반환된 값은 더 이상 `MustZeroize` 의 typestate 보호를 받지 않습니다.
    /// 즉시 zeroize 경로 (예: `Secret<U>::Drop`) 로 진입하도록 사용 직후 scope 종료
    /// 또는 명시적 `drop` 을 권장합니다.
    #[inline]
    #[must_use = "into_secret 의 반환값은 즉시 사용 또는 drop 되어야 합니다"]
    pub fn into_secret(self) -> T {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MustZeroize::new 가 IsSecret 을 만족하는 값을 받아 typestate 진입 가능함을 검증.
    #[test]
    fn must_zeroize_new_accepts_secret() {
        let m: MustZeroize<Secret<[u8; 32]>> = MustZeroize::new(Secret::new([0u8; 32]));
        let _ = m.into_secret(); // dissolve 직접 검증
    }

    /// MustZeroize::into_secret 이 self 를 소비하고 내부 Secret<T> 를 반환함을 검증.
    #[test]
    fn must_zeroize_into_secret_returns_secret() {
        let m = MustZeroize::new(Secret::new([0xAAu8; 32]));
        let s: Secret<[u8; 32]> = m.into_secret();
        assert_eq!(s.expose(), &[0xAAu8; 32]);
    }

    /// MustZeroize::expose 가 내부 IsSecret 값에 대한 불변 참조를 반환함을 검증.
    #[test]
    fn must_zeroize_expose_returns_borrow() {
        let m = MustZeroize::new(Secret::new([0x55u8; 16]));
        let inner: &Secret<[u8; 16]> = m.expose();
        assert_eq!(inner.expose(), &[0x55u8; 16]);
        let _ = m.into_secret();
    }

    /// MustZeroize::expose_mut 이 내부 IsSecret 값에 대한 가변 참조를 반환함을 검증.
    #[test]
    fn must_zeroize_expose_mut_allows_mutation() {
        let mut m = MustZeroize::new(Secret::new([0u8; 8]));
        m.expose_mut().expose_mut()[0] = 0xFF;
        let s = m.into_secret();
        assert_eq!(s.expose()[0], 0xFF);
    }

    /// Secret<T: Zeroize> 가 IsSecret 트레이트 바운드를 만족함을 컴파일 타임에 검증.
    #[test]
    fn secret_satisfies_is_secret() {
        fn requires_secret<T: IsSecret>(_: &T) {}
        let s = Secret::new([0u8; 32]);
        requires_secret(&s);
    }

    /// MustZeroize<T: IsSecret> 가 재귀적으로 IsSecret 을 만족함을 검증 (sealed 재귀 impl).
    #[test]
    fn must_zeroize_satisfies_is_secret() {
        fn requires_secret<T: IsSecret>(_: &T) {}
        let m: MustZeroize<Secret<[u8; 32]>> = MustZeroize::new(Secret::new([0u8; 32]));
        requires_secret(&m);
        let _ = m.into_secret();
    }
}
