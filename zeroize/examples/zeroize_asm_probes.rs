//! 소거 회귀 방어용 어셈블리 probe 바이너리입니다.
//!
//! # Features
//! `constant-time/scripts/check_ct_asm.sh` 의 `PROBES_ZEROIZE[]` 가 참조합니다.
//!
//! 각 probe는 `#[unsafe(no_mangle)] extern "C"` + `#[inline(never)]`로 standalone 심볼을
//! 강제 방출하여, release(`lto=true`, `opt-level="z"`) 산출물의 어셈블리에서 zeroize 경로의
//! volatile zero store 와 fence(x86_64 `mfence`, aarch64 `dmb ish`/`dsb sy`)가 DCE 로 제거되지
//! 않고 생존하는지(CWE-14/316 회귀 방지) grep 으로 검증 가능하게 합니다.
//!
//! main 함수는 DCE 방지용 호출만 수행합니다.

use zeroize::{Secret, zeroize_flat};

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_secret_drop(seed: u8) {
    let secret = Secret::new([seed; 32]);
    core::hint::black_box(secret.expose());
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_zeroize_flat(buf: &mut [u8; 64]) {
    zeroize_flat(buf);
}

fn main() {
    use core::hint::black_box;
    probe_secret_drop(black_box(0x5a));
    let mut buf = [black_box(0xa5u8); 64];
    probe_zeroize_flat(&mut buf);
    black_box(&buf);
}
