//! 보안 데이터 소거를 위한 크레이트입니다.
//!
//! 스코프 종료 시 민감한 데이터를 안전하게 소거하며, 컴파일러 최적화 및
//! CPU 캐시 문제를 방지하기 위한 다양한 배리어를 제공합니다.
//!
//! # Features
//! - `Secret<T>`: 스코프 종료 시 자동 소거되는 래퍼 타입
//! - `Zeroize` 트레이트: 수동 소거를 위한 인터페이스
//! - 아키텍처별 최적화된 배리어 (x86_64, aarch64, fallback)
//! - 휘발성 메모리 연산으로 컴파일러 최적화 방지
//!
//! # Examples
//! ```rust,ignore
//! use zeroize::{Secret, Zeroize};
//!
//! // Secret으로 민감 데이터 보호
//! {
//!     let key = Secret::new([0u8; 32]);
//!     // key 사용...
//! } // 스코프 종료 시 자동 소거
//!
//! // 수동 소거
//! let mut buffer = [0u8; 64];
//! buffer.zeroize();
//! ```
//!
//! # Security Note
//! 이 크레이트는 소프트웨어 수준에서 달성 가능한 최대 보안을 제공합니다.
//! 콜드 부트 공격 등 물리적 공격에 대해서는 하드웨어 수준의 보호가 필요합니다.
//!
//! # Authors
//! Q. T. Felix

#![no_std]

pub mod barrier;
mod secret;
pub mod volatile;
mod zeroize;

pub use secret::Secret;
pub use zeroize::{Zeroize, zeroize_flat};
