//! HRD-06 target whitelist 메시지 정적 검증 통합 테스트입니다.
//!
//! 본 테스트는 `elib-k0-ipc/src/lib.rs` 의 source-text 를 `include_str!` 로
//! 읽어 `compile_error!` 블록이 정확히 1 회 등장하고, 메시지 문자열에
//! 거부 대상 target family ("wasm32") 가 명시적으로 나열되어 있음을 확인합니다.
//!
//! D-15 의 두 검증 prong 중 한 쪽(syntactic 정적 확인)을 자동화로 잠그며,
//! 나머지 한 쪽(manual canary `cargo build --target wasm32-unknown-unknown`)
//! 은 03-03 plan 실행 시 사람이 한 번 수행하여 결과를 SUMMARY 에 기록합니다.

/// HRD-06 whitelist 메시지가 거부 대상 target family ("wasm32") 를 명시적으로
/// 나열하고 compile_error! 블록이 정확히 1 회 등장함을 정적 검증.
#[test]
fn whitelist_message_names_wasm32_and_block_appears_once() {
    let src = include_str!("../src/lib.rs");
    assert!(
        src.contains("wasm32"),
        "compile_error! 메시지에 wasm32 substring 이 누락되었습니다"
    );
    assert_eq!(
        src.matches("compile_error!").count(),
        1,
        "elib-k0-ipc/src/lib.rs 에는 compile_error! 블록이 정확히 1 회 등장해야 합니다"
    );
}
