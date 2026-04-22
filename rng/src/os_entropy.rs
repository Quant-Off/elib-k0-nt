//! OS 엔트로피 소스 모듈입니다.
//!
//! 플랫폼별 시스템 콜을 통해 암호학적으로 안전한 난수를 획득합니다.
//! no_std 환경에서도 동작하며, 지원되지 않는 플랫폼에서는 컴파일 타임 에러
//! 또는 런타임 에러를 반환합니다.
//!
//! # Supported Platform
//! - **Linux** (x86_64, aarch64): `getrandom` syscall (커널 3.17+)
//! - **macOS/iOS** (x86_64, aarch64): `getentropy` libc 호출
//! - **Windows** (x86_64): `RtlGenRandom` (advapi32.dll)
//! - **FreeBSD/OpenBSD** (x86_64, aarch64): `getentropy` syscall
//!
//! # For Embedded
//! OS가 없는 베어메탈 환경에서는 `OsEntropyUnavailable` 에러를 반환합니다.
//! 이 경우 하드웨어 RNG, 외부 엔트로피 소스, 또는 사용자 제공 시드를
//! 사용해야 합니다.
//!
//! # Security Note
//! - 부팅 직후 엔트로피 풀이 초기화되지 않았을 수 있습니다.
//! - VM 환경에서는 엔트로피 품질이 낮을 수 있습니다.
//! - 이 모듈은 블로킹 모드로 동작하여 충분한 엔트로피를 보장합니다.

use crate::DrbgError;

/// OS 엔트로피 소스에서 난수 바이트를 추출합니다.
///
/// # Arguments
/// * `dest` - 난수로 채울 버퍼
///
/// # Returns
/// * `Ok(())` - 성공적으로 버퍼를 채움
/// * `Err(DrbgError::OsEntropyFailed)` - OS 엔트로피 소스 접근 실패
///
/// # Security Note
/// 이 함수는 암호학적으로 안전한 난수를 반환합니다.
/// 부팅 직후나 VM 환경에서는 충분한 엔트로피가 누적될 때까지
/// 블로킹될 수 있습니다.
#[inline]
pub fn fill_bytes(dest: &mut [u8]) -> Result<(), DrbgError> {
    if dest.is_empty() {
        return Ok(());
    }
    sys::fill_bytes_impl(dest)
}

/// 고정 크기 배열로 OS 엔트로피를 추출합니다.
///
/// # Returns
/// * `Ok([u8; N])` - N 바이트의 난수 배열
/// * `Err(DrbgError::OsEntropyFailed)` - OS 엔트로피 소스 접근 실패
#[inline]
pub fn get_bytes<const N: usize>() -> Result<[u8; N], DrbgError> {
    let mut buf = [0u8; N];
    fill_bytes(&mut buf)?;
    Ok(buf)
}

/// OS 엔트로피를 SecureBuffer로 추출합니다.
///
/// DRBG 초기화에 사용되며, 반환된 버퍼는 Drop 시 자동 소거됩니다.
///
/// # Arguments
/// * `len` - 요청할 엔트로피 바이트 수
///
/// # Returns
/// * `Ok(SecureBuffer)` - len 바이트의 엔트로피가 담긴 버퍼
/// * `Err(DrbgError)` - 할당 실패 또는 OS 엔트로피 접근 실패
#[inline]
pub(crate) fn extract_os_entropy(len: usize) -> Result<crate::SecureBuffer, DrbgError> {
    let mut buf = crate::SecureBuffer::new_owned(len)?;
    fill_bytes(buf.as_mut_slice())?;
    Ok(buf)
}

//
// Linux (x86_64, aarch64)
//

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod sys {
    use super::*;

    // getrandom syscall number for x86_64
    const SYS_GETRANDOM: i64 = 318;
    // GRND_RANDOM flag: block until enough entropy (더 보수적인 선택)
    const GRND_NONBLOCK: u32 = 0x0001;

    pub fn fill_bytes_impl(dest: &mut [u8]) -> Result<(), DrbgError> {
        let mut offset = 0usize;
        while offset < dest.len() {
            let ptr = dest.as_mut_ptr().wrapping_add(offset);
            let len = dest.len() - offset;

            let ret: i64;
            unsafe {
                core::arch::asm!(
                    "syscall",
                    inlateout("rax") SYS_GETRANDOM => ret,
                    in("rdi") ptr,
                    in("rsi") len,
                    in("rdx") 0u32, // flags: blocking mode
                    lateout("rcx") _,
                    lateout("r11") _,
                    options(nostack),
                );
            }

            if ret < 0 {
                // EINTR (-4): 시그널에 의해 중단됨, 재시도
                if ret == -4 {
                    continue;
                }
                return Err(DrbgError::OsEntropyFailed);
            }

            offset += ret as usize;
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sys {
    use super::*;

    // getrandom syscall number for aarch64
    const SYS_GETRANDOM: i64 = 278;

    pub fn fill_bytes_impl(dest: &mut [u8]) -> Result<(), DrbgError> {
        let mut offset = 0usize;
        while offset < dest.len() {
            let ptr = dest.as_mut_ptr().wrapping_add(offset);
            let len = dest.len() - offset;

            let ret: i64;
            unsafe {
                core::arch::asm!(
                    "svc #0",
                    inlateout("x8") SYS_GETRANDOM => _,
                    inlateout("x0") ptr => ret,
                    in("x1") len,
                    in("x2") 0u32, // flags: blocking mode
                    options(nostack),
                );
            }

            if ret < 0 {
                // EINTR (-4): 재시도
                if ret == -4 {
                    continue;
                }
                return Err(DrbgError::OsEntropyFailed);
            }

            offset += ret as usize;
        }
        Ok(())
    }
}

//
// macOS / iOS (x86_64, aarch64)
//

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod sys {
    use super::*;

    // macOS getentropy syscall (actually a libc wrapper, but we can call it)
    // getentropy is limited to 256 bytes per call

    unsafe extern "C" {
        fn getentropy(buf: *mut u8, len: usize) -> i32;
    }

    pub fn fill_bytes_impl(dest: &mut [u8]) -> Result<(), DrbgError> {
        let mut offset = 0usize;
        while offset < dest.len() {
            let ptr = dest.as_mut_ptr().wrapping_add(offset);
            let len = core::cmp::min(dest.len() - offset, 256); // getentropy limit

            let ret = unsafe { getentropy(ptr, len) };

            if ret != 0 {
                return Err(DrbgError::OsEntropyFailed);
            }

            offset += len;
        }
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod sys {
    use super::*;

    unsafe extern "C" {
        fn getentropy(buf: *mut u8, len: usize) -> i32;
    }

    pub fn fill_bytes_impl(dest: &mut [u8]) -> Result<(), DrbgError> {
        let mut offset = 0usize;
        while offset < dest.len() {
            let ptr = dest.as_mut_ptr().wrapping_add(offset);
            let len = core::cmp::min(dest.len() - offset, 256);

            let ret = unsafe { getentropy(ptr, len) };

            if ret != 0 {
                return Err(DrbgError::OsEntropyFailed);
            }

            offset += len;
        }
        Ok(())
    }
}

//
// Windows (x86_64)
//

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod sys {
    use super::*;

    // RtlGenRandom from advapi32.dll (also known as SystemFunction036)
    #[link(name = "advapi32")]
    extern "system" {
        #[link_name = "SystemFunction036"]
        fn RtlGenRandom(buf: *mut u8, len: u32) -> u8;
    }

    pub fn fill_bytes_impl(dest: &mut [u8]) -> Result<(), DrbgError> {
        let mut offset = 0usize;
        while offset < dest.len() {
            let ptr = dest.as_mut_ptr().wrapping_add(offset);
            // RtlGenRandom은 u32::MAX 바이트까지 지원하지만 안전하게 제한
            let len = core::cmp::min(dest.len() - offset, 0x1000_0000) as u32;

            let ret = unsafe { RtlGenRandom(ptr, len) };

            if ret == 0 {
                return Err(DrbgError::OsEntropyFailed);
            }

            offset += len as usize;
        }
        Ok(())
    }
}

//
// FreeBSD (x86_64, aarch64)
//

#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
mod sys {
    use super::*;

    // FreeBSD getrandom syscall
    const SYS_GETRANDOM: i64 = 563;

    pub fn fill_bytes_impl(dest: &mut [u8]) -> Result<(), DrbgError> {
        let mut offset = 0usize;
        while offset < dest.len() {
            let ptr = dest.as_mut_ptr().wrapping_add(offset);
            let len = dest.len() - offset;

            let ret: i64;
            unsafe {
                core::arch::asm!(
                    "syscall",
                    inlateout("rax") SYS_GETRANDOM => ret,
                    in("rdi") ptr,
                    in("rsi") len,
                    in("rdx") 0u32,
                    lateout("rcx") _,
                    lateout("r11") _,
                    options(nostack),
                );
            }

            if ret < 0 {
                if ret == -4 {
                    continue;
                }
                return Err(DrbgError::OsEntropyFailed);
            }

            offset += ret as usize;
        }
        Ok(())
    }
}

#[cfg(all(target_os = "freebsd", target_arch = "aarch64"))]
mod sys {
    use super::*;

    const SYS_GETRANDOM: i64 = 563;

    pub fn fill_bytes_impl(dest: &mut [u8]) -> Result<(), DrbgError> {
        let mut offset = 0usize;
        while offset < dest.len() {
            let ptr = dest.as_mut_ptr().wrapping_add(offset);
            let len = dest.len() - offset;

            let ret: i64;
            unsafe {
                core::arch::asm!(
                    "svc #0",
                    inlateout("x8") SYS_GETRANDOM => _,
                    inlateout("x0") ptr => ret,
                    in("x1") len,
                    in("x2") 0u32,
                    options(nostack),
                );
            }

            if ret < 0 {
                if ret == -4 {
                    continue;
                }
                return Err(DrbgError::OsEntropyFailed);
            }

            offset += ret as usize;
        }
        Ok(())
    }
}

//
// OpenBSD (x86_64, aarch64)
//

#[cfg(all(target_os = "openbsd", target_arch = "x86_64"))]
mod sys {
    use super::*;

    // OpenBSD getentropy syscall
    const SYS_GETENTROPY: i64 = 7;

    pub fn fill_bytes_impl(dest: &mut [u8]) -> Result<(), DrbgError> {
        let mut offset = 0usize;
        while offset < dest.len() {
            let ptr = dest.as_mut_ptr().wrapping_add(offset);
            let len = core::cmp::min(dest.len() - offset, 256); // getentropy limit

            let ret: i64;
            unsafe {
                core::arch::asm!(
                    "syscall",
                    inlateout("rax") SYS_GETENTROPY => ret,
                    in("rdi") ptr,
                    in("rsi") len,
                    lateout("rcx") _,
                    lateout("r11") _,
                    options(nostack),
                );
            }

            if ret != 0 {
                return Err(DrbgError::OsEntropyFailed);
            }

            offset += len;
        }
        Ok(())
    }
}

#[cfg(all(target_os = "openbsd", target_arch = "aarch64"))]
mod sys {
    use super::*;

    const SYS_GETENTROPY: i64 = 7;

    pub fn fill_bytes_impl(dest: &mut [u8]) -> Result<(), DrbgError> {
        let mut offset = 0usize;
        while offset < dest.len() {
            let ptr = dest.as_mut_ptr().wrapping_add(offset);
            let len = core::cmp::min(dest.len() - offset, 256);

            let ret: i64;
            unsafe {
                core::arch::asm!(
                    "svc #0",
                    inlateout("x8") SYS_GETENTROPY => _,
                    inlateout("x0") ptr => ret,
                    in("x1") len,
                    options(nostack),
                );
            }

            if ret != 0 {
                return Err(DrbgError::OsEntropyFailed);
            }

            offset += len;
        }
        Ok(())
    }
}

//
// NetBSD (x86_64)
//

#[cfg(all(target_os = "netbsd", target_arch = "x86_64"))]
mod sys {
    use super::*;

    unsafe extern "C" {
        fn getentropy(buf: *mut u8, len: usize) -> i32;
    }

    pub fn fill_bytes_impl(dest: &mut [u8]) -> Result<(), DrbgError> {
        let mut offset = 0usize;
        while offset < dest.len() {
            let ptr = dest.as_mut_ptr().wrapping_add(offset);
            let len = core::cmp::min(dest.len() - offset, 256);

            let ret = unsafe { getentropy(ptr, len) };

            if ret != 0 {
                return Err(DrbgError::OsEntropyFailed);
            }

            offset += len;
        }
        Ok(())
    }
}

//
// Unsupported platforms (bare-metal, embedded, unknown OS)
//

#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "windows", target_arch = "x86_64"),
    all(
        target_os = "freebsd",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(
        target_os = "openbsd",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "netbsd", target_arch = "x86_64"),
)))]
mod sys {
    use super::*;

    /// 지원되지 않는 플랫폼에서는 항상 실패를 반환합니다.
    ///
    /// 임베디드 환경에서는 다음 대안을 고려하세요:
    /// - 하드웨어 RNG (TRNG) 사용
    /// - 외부 엔트로피 소스 (센서 노이즈, 타이밍 지터 등)
    /// - 사용자 제공 시드로 DRBG 초기화
    #[inline]
    pub fn fill_bytes_impl(_dest: &mut [u8]) -> Result<(), DrbgError> {
        Err(DrbgError::OsEntropyFailed)
    }
}
