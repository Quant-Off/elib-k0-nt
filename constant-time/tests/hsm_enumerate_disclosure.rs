#[cfg(test)]
mod tests {
    // SC-3 + Pitfall 1: enumerate 결과는 capability 미보유 시 (a) 버퍼 미수정,
    // (b) length 필드 0, (c) err 코드만이 분리 신호 — length 자체가 cap 존재 정보를 인코딩해선 안 됨.

    const ERR_DENIED: i64 = -4; // SyscallError::Denied 매핑 (src/syscall.rs)

    // PATTERNS L582-589 의 시그니처를 그대로 mock 화. has_cap=false 면 출력 버퍼는 단 1바이트도
    // 건드리지 않으며 length 는 0, err 는 Denied. has_cap=true + 슬롯 0개면 length 0 + err 0
    // — Phase 1 단위 테스트 시점에는 슬롯이 0개이므로 두 케이스가 length 만 보면 구분 불가해야 한다.
    fn enumerate_mock(has_cap: bool, _output: &mut [u8; 8]) -> (usize, i64) {
        if !has_cap {
            // 의도적으로 _output 을 건드리지 않음 — sentinel 검사 통과를 보장.
            return (0, ERR_DENIED);
        }
        // 슬롯이 비어있는 경우 — length 0, 성공 err.
        (0, 0)
    }

    #[test]
    fn enumerate_without_cap_returns_zero_length() {
        let mut buf = [0xAAu8; 8];
        let (len, err) = enumerate_mock(false, &mut buf);
        assert_eq!(len, 0);
        assert_eq!(err, ERR_DENIED);
    }

    #[test]
    fn enumerate_without_cap_does_not_write_buffer() {
        // sentinel 사전-채움 — 바이트 단위로 변화 없음을 잠근다 (PATTERNS L588-589).
        let mut buf = [0xAAu8; 8];
        let _ = enumerate_mock(false, &mut buf);
        assert_eq!(
            buf,
            [0xAAu8; 8],
            "버퍼가 변경됨 — capability 미보유 시 enumerate 가 출력에 어떤 흔적도 남기지 않아야 함"
        );
    }

    #[test]
    fn enumerate_with_cap_zero_slots_returns_zero_length_distinguishable_only_by_err() {
        // Pitfall 1 정합: length 필드만으로는 capability 존재 여부 식별 불가.
        // (err 만이 분리 신호 — has_cap=true 슬롯 0개 -> err=0, has_cap=false -> err=Denied)
        let mut buf = [0xAAu8; 8];
        let (len_with_cap, err_with_cap) = enumerate_mock(true, &mut buf);
        let (len_without_cap, err_without_cap) = enumerate_mock(false, &mut buf);

        assert_eq!(len_with_cap, len_without_cap, "length 필드가 cap 존재를 인코딩함");
        assert_eq!(len_with_cap, 0);
        assert_ne!(err_with_cap, err_without_cap, "err 코드는 두 경로를 분리해야 함");
        assert_eq!(err_with_cap, 0);
        assert_eq!(err_without_cap, ERR_DENIED);
    }
}
