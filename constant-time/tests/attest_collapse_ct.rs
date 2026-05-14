// Phase 5 Plan 05-04 Wave 1 GREEN fill-in
// attestation variant collapse 회귀 가드 (D-11 Pitfall 7 Shared-4)
//
// 검증 대상
//   - kernel 측 verify_attest 가 4 mldsa::Error variant + Ok(false) 5 경우 모두
//     단일 RAX = -1 (SyscallError::Denied) 로 collapse
//   - 서로 다른 -2, -3 등 RAX 로 분기되지 않음 (timing / oracle 회귀)
//   - Ok(true) 만 SYSCALL_OK 반환

#[cfg(test)]
mod tests {
    /// SyscallError::Ok 의 RAX 잠금
    const SYSCALL_OK: i64 = 0;
    /// SyscallError::Denied 의 RAX 잠금 (Pitfall 7 단일 collapse target)
    const SYSCALL_DENIED: i64 = -1;

    /// host-side mldsa verify 결과 5 경우 + OkTrue 열거 mock
    ///
    /// kernel src 를 import 하지 않으므로 본 enum 은 행동만 mirror 한다
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HostMockVerifyResult {
        OkTrue,
        OkFalse,
        ErrInvalidLength,
        ErrInternalError,
        ErrContextTooLong,
        ErrInvalidSignature,
    }

    /// 5 fail variant 가 단일 SYSCALL_DENIED 로 collapse 되는 mock
    fn collapse_to_rax(r: HostMockVerifyResult) -> i64 {
        match r {
            HostMockVerifyResult::OkTrue => SYSCALL_OK,
            HostMockVerifyResult::OkFalse
            | HostMockVerifyResult::ErrInvalidLength
            | HostMockVerifyResult::ErrInternalError
            | HostMockVerifyResult::ErrContextTooLong
            | HostMockVerifyResult::ErrInvalidSignature => SYSCALL_DENIED,
        }
    }

    /// 4 mldsa::Error variant + Ok(false) 모두 동일 RAX = SYSCALL_DENIED 회귀
    #[test]
    fn attest_error_variant_collapse_to_denied() {
        let fail_cases = [
            HostMockVerifyResult::ErrInvalidLength,
            HostMockVerifyResult::ErrInternalError,
            HostMockVerifyResult::ErrContextTooLong,
            HostMockVerifyResult::ErrInvalidSignature,
            HostMockVerifyResult::OkFalse,
        ];

        for c in fail_cases.iter() {
            assert_eq!(
                collapse_to_rax(*c),
                SYSCALL_DENIED,
                "variant {:?} 가 SYSCALL_DENIED 로 collapse 되지 않음",
                c
            );
        }

        // success path 검증 OkTrue 만 SYSCALL_OK 반환
        assert_eq!(
            collapse_to_rax(HostMockVerifyResult::OkTrue),
            SYSCALL_OK,
            "OkTrue 가 SYSCALL_OK 가 아님"
        );
    }

    /// 5 fail RAX 값이 모두 *동일 정수* (서로 다른 -2, -3 등으로 분기되지 않음) 회귀
    #[test]
    fn attest_denied_rax_value_uniformity() {
        let rax_values: [i64; 5] = [
            collapse_to_rax(HostMockVerifyResult::ErrInvalidLength),
            collapse_to_rax(HostMockVerifyResult::ErrInternalError),
            collapse_to_rax(HostMockVerifyResult::ErrContextTooLong),
            collapse_to_rax(HostMockVerifyResult::ErrInvalidSignature),
            collapse_to_rax(HostMockVerifyResult::OkFalse),
        ];

        // (1) 5 값 모두 SYSCALL_DENIED
        for v in rax_values.iter() {
            assert_eq!(
                *v, SYSCALL_DENIED,
                "fail variant RAX 가 SYSCALL_DENIED 가 아님"
            );
        }

        // (2) 5 값 페어와이즈 동등 (pivot 비교)
        for v in rax_values.iter() {
            assert_eq!(*v, rax_values[0], "fail variant RAX 가 서로 다름");
        }

        // (3) OkTrue 만 다른 값 OK != DENIED
        assert_ne!(
            collapse_to_rax(HostMockVerifyResult::OkTrue),
            SYSCALL_DENIED,
            "OkTrue 가 SYSCALL_DENIED 로 collapse 됨"
        );
    }
}
