//! FIPS 204 ML-DSA(Module Lattice-based Digital Signature Algorithm) 구현 모듈입니다.
//!
//! 포스트 양자 암호(PQC) 표준인 ML-DSA의 세 가지 파라미터 셋(ML-DSA-44, ML-DSA-65, ML-DSA-87)을
//! 지원하며, `no_std` 환경에서 동작합니다.
//!
//! # Features
//! - ML-DSA-44: NIST 보안 카테고리 2 (128-bit 보안 강도)
//! - ML-DSA-65: NIST 보안 카테고리 3 (192-bit 보안 강도)
//! - ML-DSA-87: NIST 보안 카테고리 5 (256-bit 보안 강도)
//! - 상수-시간 연산으로 사이드채널 공격 방지
//! - 외부 의존성 없음 (프로젝트 내부 크레이트만 사용)
//!
//! # Examples
//! ```rust,ignore
//! use mldsa::MLDSA44;
//!
//! // 키 생성 (xi는 32바이트 시드, RNG로 생성 필요)
//! let xi = [0u8; 32];
//! let (pk, sk) = MLDSA44::keygen(&xi).unwrap();
//!
//! // 서명 생성
//! let message = b"Hello, ML-DSA!";
//! let ctx = b"";
//! let rnd = [0u8; 32]; // 헤지드 서명용 난수
//! let sig = MLDSA44::sign(&sk, message, ctx, &rnd).unwrap();
//!
//! // 서명 검증
//! let valid = MLDSA44::verify(&pk, message, &sig, ctx).unwrap();
//! assert!(valid);
//! ```
//!
//! # Security Note
//! - `xi`와 `rnd`는 반드시 암호학적으로 안전한 RNG로 생성해야 합니다.
//! - 비밀 키는 사용 후 반드시 소거(zeroize)해야 합니다.
//!
//! # Authors
//! Q. T. Felix

#![cfg_attr(not(test), no_std)]

mod error;
mod field;
mod keys;
mod ntt;
mod pack;
mod poly;
mod sample;
mod sign;

pub use error::Error;

pub const Q: i32 = 8380417;
pub const D: usize = 13;
pub const Q_INV: i32 = 58728449;
pub const SEED_LEN: usize = 32;

mod params {
    pub const K_44: usize = 4;
    pub const L_44: usize = 4;
    pub const ETA_44: i32 = 2;
    pub const TAU_44: usize = 39;
    pub const BETA_44: i32 = 78;
    pub const LAMBDA_44: usize = 128;
    pub const GAMMA1_44: i32 = 131072;
    pub const GAMMA2_44: i32 = 95232;
    pub const OMEGA_44: usize = 80;
    pub const PK_LEN_44: usize = 1312;
    pub const SK_LEN_44: usize = 2560;
    pub const SIG_LEN_44: usize = 2420;

    pub const K_65: usize = 6;
    pub const L_65: usize = 5;
    pub const ETA_65: i32 = 4;
    pub const TAU_65: usize = 49;
    pub const BETA_65: i32 = 196;
    pub const LAMBDA_65: usize = 192;
    pub const GAMMA1_65: i32 = 524288;
    pub const GAMMA2_65: i32 = 261888;
    pub const OMEGA_65: usize = 55;
    pub const PK_LEN_65: usize = 1952;
    pub const SK_LEN_65: usize = 4032;
    pub const SIG_LEN_65: usize = 3309;

    pub const K_87: usize = 8;
    pub const L_87: usize = 7;
    pub const ETA_87: i32 = 2;
    pub const TAU_87: usize = 60;
    pub const BETA_87: i32 = 120;
    pub const LAMBDA_87: usize = 256;
    pub const GAMMA1_87: i32 = 524288;
    pub const GAMMA2_87: i32 = 261888;
    pub const OMEGA_87: usize = 75;
    pub const PK_LEN_87: usize = 2592;
    pub const SK_LEN_87: usize = 4896;
    pub const SIG_LEN_87: usize = 4627;
}

use keys::{keygen_internal, pk_encode, sk_encode};
use params::*;
use sign::{sign_internal, verify_internal};

/// ML-DSA-44 파라미터 셋 (NIST 보안 카테고리 2)
pub struct MLDSA44;

/// ML-DSA-65 파라미터 셋 (NIST 보안 카테고리 3)
pub struct MLDSA65;

/// ML-DSA-87 파라미터 셋 (NIST 보안 카테고리 5)
pub struct MLDSA87;

impl MLDSA44 {
    /// 공개 키 바이트 길이 (1312 바이트)
    pub const PK_LEN: usize = PK_LEN_44;
    /// 비밀 키 바이트 길이 (2560 바이트)
    pub const SK_LEN: usize = SK_LEN_44;
    /// 서명 바이트 길이 (2420 바이트)
    pub const SIG_LEN: usize = SIG_LEN_44;

    /// ML-DSA-44 키 쌍을 생성합니다.
    ///
    /// # Arguments
    /// - `xi`: 32바이트 시드 (암호학적 RNG로 생성 필요)
    ///
    /// # Errors
    /// 내부 연산 실패 시 `Error::InternalError` 반환
    pub fn keygen(xi: &[u8; 32]) -> Result<([u8; PK_LEN_44], [u8; SK_LEN_44]), Error> {
        let (pk, sk) = keygen_internal::<K_44, L_44, ETA_44>(xi)?;
        let pk_bytes = pk_encode::<K_44, PK_LEN_44>(&pk);
        let sk_bytes = sk_encode::<K_44, L_44, ETA_44, SK_LEN_44>(&sk);
        Ok((pk_bytes, sk_bytes))
    }

    /// 메시지에 대한 ML-DSA-44 서명을 생성합니다.
    ///
    /// # Arguments
    /// - `sk`: 비밀 키 (2560 바이트)
    /// - `message`: 서명할 메시지
    /// - `ctx`: 컨텍스트 문자열 (최대 255 바이트)
    /// - `rnd`: 헤지드 서명용 32바이트 난수
    ///
    /// # Errors
    /// - `Error::ContextTooLong`: ctx가 255바이트 초과
    /// - `Error::InvalidLength`: 메시지+컨텍스트가 버퍼 초과
    /// - `Error::SigningFailed`: 서명 생성 실패 (극히 드문 경우)
    pub fn sign(
        sk: &[u8; SK_LEN_44],
        message: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Result<[u8; SIG_LEN_44], Error> {
        if ctx.len() > 255 {
            return Err(Error::ContextTooLong);
        }

        let mut m_prime = [0u8; 1024];
        let m_prime_len = 2 + ctx.len() + message.len();
        if m_prime_len > m_prime.len() {
            return Err(Error::InvalidLength);
        }
        m_prime[0] = 0x00;
        m_prime[1] = ctx.len() as u8;
        m_prime[2..2 + ctx.len()].copy_from_slice(ctx);
        m_prime[2 + ctx.len()..m_prime_len].copy_from_slice(message);

        sign_internal::<
            K_44,
            L_44,
            ETA_44,
            GAMMA1_44,
            GAMMA2_44,
            BETA_44,
            OMEGA_44,
            LAMBDA_44,
            TAU_44,
            SK_LEN_44,
            SIG_LEN_44,
        >(sk, &m_prime[..m_prime_len], rnd)
    }

    /// ML-DSA-44 서명을 검증합니다.
    ///
    /// # Arguments
    /// - `pk`: 공개 키 (1312 바이트)
    /// - `message`: 원본 메시지
    /// - `sig`: 검증할 서명 (2420 바이트)
    /// - `ctx`: 서명 시 사용한 컨텍스트 문자열
    ///
    /// # Errors
    /// - `Error::ContextTooLong`: ctx가 255바이트 초과
    /// - `Error::InvalidLength`: 메시지+컨텍스트가 버퍼 초과
    pub fn verify(
        pk: &[u8; PK_LEN_44],
        message: &[u8],
        sig: &[u8; SIG_LEN_44],
        ctx: &[u8],
    ) -> Result<bool, Error> {
        if ctx.len() > 255 {
            return Err(Error::ContextTooLong);
        }

        let mut m_prime = [0u8; 1024];
        let m_prime_len = 2 + ctx.len() + message.len();
        if m_prime_len > m_prime.len() {
            return Err(Error::InvalidLength);
        }
        m_prime[0] = 0x00;
        m_prime[1] = ctx.len() as u8;
        m_prime[2..2 + ctx.len()].copy_from_slice(ctx);
        m_prime[2 + ctx.len()..m_prime_len].copy_from_slice(message);

        verify_internal::<
            K_44,
            L_44,
            GAMMA1_44,
            GAMMA2_44,
            BETA_44,
            OMEGA_44,
            LAMBDA_44,
            TAU_44,
            PK_LEN_44,
            SIG_LEN_44,
        >(pk, &m_prime[..m_prime_len], sig)
    }
}

impl MLDSA65 {
    /// 공개 키 바이트 길이 (1952 바이트)
    pub const PK_LEN: usize = PK_LEN_65;
    /// 비밀 키 바이트 길이 (4032 바이트)
    pub const SK_LEN: usize = SK_LEN_65;
    /// 서명 바이트 길이 (3309 바이트)
    pub const SIG_LEN: usize = SIG_LEN_65;

    /// ML-DSA-65 키 쌍을 생성합니다.
    ///
    /// # Arguments
    /// - `xi`: 32바이트 시드 (암호학적 RNG로 생성 필요)
    ///
    /// # Errors
    /// 내부 연산 실패 시 `Error::InternalError` 반환
    pub fn keygen(xi: &[u8; 32]) -> Result<([u8; PK_LEN_65], [u8; SK_LEN_65]), Error> {
        let (pk, sk) = keygen_internal::<K_65, L_65, ETA_65>(xi)?;
        let pk_bytes = pk_encode::<K_65, PK_LEN_65>(&pk);
        let sk_bytes = sk_encode::<K_65, L_65, ETA_65, SK_LEN_65>(&sk);
        Ok((pk_bytes, sk_bytes))
    }

    /// 메시지에 대한 ML-DSA-65 서명을 생성합니다.
    ///
    /// # Arguments
    /// - `sk`: 비밀 키 (4032 바이트)
    /// - `message`: 서명할 메시지
    /// - `ctx`: 컨텍스트 문자열 (최대 255 바이트)
    /// - `rnd`: 헤지드 서명용 32바이트 난수
    ///
    /// # Errors
    /// - `Error::ContextTooLong`: ctx가 255바이트 초과
    /// - `Error::InvalidLength`: 메시지+컨텍스트가 버퍼 초과
    /// - `Error::SigningFailed`: 서명 생성 실패 (극히 드문 경우)
    pub fn sign(
        sk: &[u8; SK_LEN_65],
        message: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Result<[u8; SIG_LEN_65], Error> {
        if ctx.len() > 255 {
            return Err(Error::ContextTooLong);
        }

        let mut m_prime = [0u8; 1024];
        let m_prime_len = 2 + ctx.len() + message.len();
        if m_prime_len > m_prime.len() {
            return Err(Error::InvalidLength);
        }
        m_prime[0] = 0x00;
        m_prime[1] = ctx.len() as u8;
        m_prime[2..2 + ctx.len()].copy_from_slice(ctx);
        m_prime[2 + ctx.len()..m_prime_len].copy_from_slice(message);

        sign_internal::<
            K_65,
            L_65,
            ETA_65,
            GAMMA1_65,
            GAMMA2_65,
            BETA_65,
            OMEGA_65,
            LAMBDA_65,
            TAU_65,
            SK_LEN_65,
            SIG_LEN_65,
        >(sk, &m_prime[..m_prime_len], rnd)
    }

    /// ML-DSA-65 서명을 검증합니다.
    ///
    /// # Arguments
    /// - `pk`: 공개 키 (1952 바이트)
    /// - `message`: 원본 메시지
    /// - `sig`: 검증할 서명 (3309 바이트)
    /// - `ctx`: 서명 시 사용한 컨텍스트 문자열
    ///
    /// # Errors
    /// - `Error::ContextTooLong`: ctx가 255바이트 초과
    /// - `Error::InvalidLength`: 메시지+컨텍스트가 버퍼 초과
    pub fn verify(
        pk: &[u8; PK_LEN_65],
        message: &[u8],
        sig: &[u8; SIG_LEN_65],
        ctx: &[u8],
    ) -> Result<bool, Error> {
        if ctx.len() > 255 {
            return Err(Error::ContextTooLong);
        }

        let mut m_prime = [0u8; 1024];
        let m_prime_len = 2 + ctx.len() + message.len();
        if m_prime_len > m_prime.len() {
            return Err(Error::InvalidLength);
        }
        m_prime[0] = 0x00;
        m_prime[1] = ctx.len() as u8;
        m_prime[2..2 + ctx.len()].copy_from_slice(ctx);
        m_prime[2 + ctx.len()..m_prime_len].copy_from_slice(message);

        verify_internal::<
            K_65,
            L_65,
            GAMMA1_65,
            GAMMA2_65,
            BETA_65,
            OMEGA_65,
            LAMBDA_65,
            TAU_65,
            PK_LEN_65,
            SIG_LEN_65,
        >(pk, &m_prime[..m_prime_len], sig)
    }
}

impl MLDSA87 {
    /// 공개 키 바이트 길이 (2592 바이트)
    pub const PK_LEN: usize = PK_LEN_87;
    /// 비밀 키 바이트 길이 (4896 바이트)
    pub const SK_LEN: usize = SK_LEN_87;
    /// 서명 바이트 길이 (4627 바이트)
    pub const SIG_LEN: usize = SIG_LEN_87;

    /// ML-DSA-87 키 쌍을 생성합니다.
    ///
    /// # Arguments
    /// - `xi`: 32바이트 시드 (암호학적 RNG로 생성 필요)
    ///
    /// # Errors
    /// 내부 연산 실패 시 `Error::InternalError` 반환
    pub fn keygen(xi: &[u8; 32]) -> Result<([u8; PK_LEN_87], [u8; SK_LEN_87]), Error> {
        let (pk, sk) = keygen_internal::<K_87, L_87, ETA_87>(xi)?;
        let pk_bytes = pk_encode::<K_87, PK_LEN_87>(&pk);
        let sk_bytes = sk_encode::<K_87, L_87, ETA_87, SK_LEN_87>(&sk);
        Ok((pk_bytes, sk_bytes))
    }

    /// 메시지에 대한 ML-DSA-87 서명을 생성합니다.
    ///
    /// # Arguments
    /// - `sk`: 비밀 키 (4896 바이트)
    /// - `message`: 서명할 메시지
    /// - `ctx`: 컨텍스트 문자열 (최대 255 바이트)
    /// - `rnd`: 헤지드 서명용 32바이트 난수
    ///
    /// # Errors
    /// - `Error::ContextTooLong`: ctx가 255바이트 초과
    /// - `Error::InvalidLength`: 메시지+컨텍스트가 버퍼 초과
    /// - `Error::SigningFailed`: 서명 생성 실패 (극히 드문 경우)
    pub fn sign(
        sk: &[u8; SK_LEN_87],
        message: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Result<[u8; SIG_LEN_87], Error> {
        if ctx.len() > 255 {
            return Err(Error::ContextTooLong);
        }

        let mut m_prime = [0u8; 1024];
        let m_prime_len = 2 + ctx.len() + message.len();
        if m_prime_len > m_prime.len() {
            return Err(Error::InvalidLength);
        }
        m_prime[0] = 0x00;
        m_prime[1] = ctx.len() as u8;
        m_prime[2..2 + ctx.len()].copy_from_slice(ctx);
        m_prime[2 + ctx.len()..m_prime_len].copy_from_slice(message);

        sign_internal::<
            K_87,
            L_87,
            ETA_87,
            GAMMA1_87,
            GAMMA2_87,
            BETA_87,
            OMEGA_87,
            LAMBDA_87,
            TAU_87,
            SK_LEN_87,
            SIG_LEN_87,
        >(sk, &m_prime[..m_prime_len], rnd)
    }

    /// ML-DSA-87 서명을 검증합니다.
    ///
    /// # Arguments
    /// - `pk`: 공개 키 (2592 바이트)
    /// - `message`: 원본 메시지
    /// - `sig`: 검증할 서명 (4627 바이트)
    /// - `ctx`: 서명 시 사용한 컨텍스트 문자열
    ///
    /// # Errors
    /// - `Error::ContextTooLong`: ctx가 255바이트 초과
    /// - `Error::InvalidLength`: 메시지+컨텍스트가 버퍼 초과
    pub fn verify(
        pk: &[u8; PK_LEN_87],
        message: &[u8],
        sig: &[u8; SIG_LEN_87],
        ctx: &[u8],
    ) -> Result<bool, Error> {
        if ctx.len() > 255 {
            return Err(Error::ContextTooLong);
        }

        let mut m_prime = [0u8; 1024];
        let m_prime_len = 2 + ctx.len() + message.len();
        if m_prime_len > m_prime.len() {
            return Err(Error::InvalidLength);
        }
        m_prime[0] = 0x00;
        m_prime[1] = ctx.len() as u8;
        m_prime[2..2 + ctx.len()].copy_from_slice(ctx);
        m_prime[2 + ctx.len()..m_prime_len].copy_from_slice(message);

        verify_internal::<
            K_87,
            L_87,
            GAMMA1_87,
            GAMMA2_87,
            BETA_87,
            OMEGA_87,
            LAMBDA_87,
            TAU_87,
            PK_LEN_87,
            SIG_LEN_87,
        >(pk, &m_prime[..m_prime_len], sig)
    }
}
