//! 최적화 배리어 모듈입니다.
//!
//! 컴파일러 및 CPU 수준의 최적화를 방지하여 메모리 소거가
//! 실제로 수행되도록 보장합니다.
//!
//! # Features
//! - `memory_barrier`: CPU 메모리 배리어 (캐시 동기화)
//! - `compiler_barrier`: 컴파일러 명령어 재배치 방지
//! - `atomic_compiler_fence`: 원자적 컴파일러 펜스
//! - `black_box`: 값을 레지스터에 강제 로드하여 최적화 방지
//!
//! # Examples
//! ```rust,ignore
//! use zeorize::barrier::{compiler_barrier, memory_barrier};
//!
//! compiler_barrier();
//! // 민감한 메모리 연산
//! memory_barrier();
//! ```
//!
//! # Authors
//! Q. T. Felix

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod fallback;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use fallback::*;
