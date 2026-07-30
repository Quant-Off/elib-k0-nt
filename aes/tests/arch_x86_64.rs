#![cfg(all(target_arch = "x86_64", not(target_os = "none")))]

mod common;

#[test]
fn x86_64_kat_battery() {
    if let Err(tag) = common::run_all() {
        panic!("x86_64 KAT 실패: {tag}");
    }
}

#[test]
fn x86_64_target_arch_guard() {
    const {
        assert!(cfg!(target_arch = "x86_64"));
    }
}
