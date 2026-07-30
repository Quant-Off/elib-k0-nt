#![cfg(all(target_arch = "aarch64", not(target_os = "none")))]

mod common;

#[test]
fn aarch64_kat_battery() {
    if let Err(tag) = common::run_all() {
        panic!("aarch64 KAT 실패: {tag}");
    }
}

#[test]
fn aarch64_target_arch_guard() {
    assert!(cfg!(target_arch = "aarch64"));
}
