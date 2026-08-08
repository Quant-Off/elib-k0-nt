#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

mod common;

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let result = core::hint::black_box(common::run_all());
    if result.is_err() {
        panic!();
    }
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(target_os = "none"))]
fn main() {
    if let Err(tag) = common::run_all() {
        panic!("베어메탈 KAT 배터리 실패: {tag}");
    }
}
