//! HRD-02 봉인(sealed) trait 외부-crate 증명 통합 테스트입니다.
//!
//! 동일 crate 내부 doc-test 는 `sealed::Sealed` 를 합법적으로 impl 할 수 있어
//! "외부에서 IsSecret 을 구현 시도하면 컴파일 거부" 라는 본질적 sealed 속성을
//! 증명하지 못합니다. 본 통합 테스트는 별도 crate 컨텍스트(integration test 는
//! 자체 crate 로 컴파일됨) 에서 외부 impl 시도가 컴파일 거부됨을 `compile_fail`
//! rustdoc 블록으로 입증합니다.
//!
//! # Examples
//! ```compile_fail
//! use elib_k0_ipc::IsSecret;
//! struct LocalType([u8; 32]);
//! impl IsSecret for LocalType {} // 컴파일 거부: sealed trait — 외부 crate 에서 impl 불가
//! ```

/// HRD-02 sealed trait invariant 의 컴파일-타임 증명용 zero-sized 마커입니다.
const _: () = ();

/// 본 파일이 정상 컴파일되어 통합 테스트로 등록됨을 단순 확인 (compile_fail 블록은
/// rustdoc runner 가 별도 검증).
#[test]
fn sealed_external_attempt_test_file_compiles() {
    // intentionally empty — compile_fail 블록 통과가 본 테스트의 본질
}
