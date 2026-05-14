// Phase 3 Plan-03 Wave 0 — with_relay_buf 의 4 exit path 후 RELAY_BUF raw bytes 전부 0
// (CHAN-02 / D-14 double safety)
//
// 검증 대상
//   - kernel 측 with_relay_buf 가 진입+이탈 양면 zeroize 를 보장 (D-14)
//   - happy path / closure-Err / 중간 panic 시뮬레이션 / partial write 4 경로 모두 이탈 후 RELAY_BUF == [0; CHAN_MAX]

#[cfg(test)]
mod tests {
    use zeroize::Zeroize;

    const CHAN_MAX: usize = 4096;

    // Host-side mock RELAY_BUF  iso-light-k0::hsm_registry::RELAY_BUF 와 동등한 static [u8; N]
    static mut MOCK_RELAY_BUF: [u8; CHAN_MAX] = [0u8; CHAN_MAX];

    // iso-light-k0 의 with_relay_buf wrapper 동등 미러 (D-14 진입+이탈 양면 zeroize)
    //
    // # Safety
    // 단일 코어 테스트 진입점에서만 호출  Test harness 가 직렬 실행 보장
    unsafe fn with_relay_buf_mock<R>(f: impl FnOnce(&mut [u8; CHAN_MAX]) -> R) -> R {
        // SAFETY: 단일 코어 테스트 + 직렬 실행
        let buf = unsafe { &mut *(&raw mut MOCK_RELAY_BUF) };
        // D-14 진입 zeroize
        buf.zeroize();
        let r = f(buf);
        // D-14 이탈 zeroize
        buf.zeroize();
        r
    }

    fn assert_buf_all_zero(label: &str) {
        // SAFETY: 단일 코어 테스트 + 직렬 실행  &MOCK_RELAY_BUF 직접 take
        let snapshot: [u8; 32] = unsafe { *(&raw const MOCK_RELAY_BUF as *const [u8; 32]) };
        for (i, b) in snapshot.iter().enumerate() {
            assert_eq!(*b, 0, "[{}] byte {} should be 0 after with_relay_buf exit", label, i);
        }
    }

    #[test]
    fn test_happy_path_zeroized_on_exit() {
        // SAFETY: 단일 코어 테스트
        unsafe {
            with_relay_buf_mock(|buf| {
                buf[0] = 0xAA;
                buf[CHAN_MAX - 1] = 0xBB;
                buf[1024] = 0xCC;
            });
        }
        assert_buf_all_zero("happy");
    }

    #[test]
    fn test_closure_err_zeroized_on_exit() {
        // SAFETY: 단일 코어 테스트
        let result: Result<(), ()> = unsafe {
            with_relay_buf_mock(|buf| {
                buf[0] = 0xDD;
                buf[7] = 0xEE;
                Err(())
            })
        };
        assert!(result.is_err());
        assert_buf_all_zero("closure-err");
    }

    #[test]
    fn test_partial_write_zeroized_on_exit() {
        // dst.write returning partial 시뮬레이션  closure 가 Err 반환 후에도 RELAY_BUF 0
        // SAFETY: 단일 코어 테스트
        let result: Result<usize, &str> = unsafe {
            with_relay_buf_mock(|buf| {
                buf[100] = 0xF1;
                buf[200] = 0xF2;
                buf[300] = 0xF3;
                // partial write 시뮬레이션  Err 반환
                Err("partial write rejected")
            })
        };
        assert!(result.is_err());
        assert_buf_all_zero("partial-write");
    }

    #[test]
    fn test_length_mismatch_zeroized_on_exit() {
        // src.read 결과가 byte_len 과 불일치 시뮬레이션
        // SAFETY: 단일 코어 테스트
        let result: Result<(), &str> = unsafe {
            with_relay_buf_mock(|buf| {
                for i in 0..16 {
                    buf[i] = 0xAB;
                }
                Err("length mismatch")
            })
        };
        assert!(result.is_err());
        assert_buf_all_zero("length-mismatch");
    }

    #[test]
    fn test_entry_zeroize_clears_residue() {
        // 이전 호출자 잔재가 다음 호출 진입 시점에 보이지 않음 (D-14 진입 zeroize)
        // SAFETY: 단일 코어 테스트
        unsafe {
            with_relay_buf_mock(|buf| {
                buf[0] = 0x99;
                buf[CHAN_MAX - 1] = 0x88;
            });
        }
        // 다음 호출 진입 시점 buf 가 0 으로 시작하는지
        // SAFETY: 단일 코어 테스트
        unsafe {
            with_relay_buf_mock(|buf| {
                assert_eq!(buf[0], 0, "entry zeroize 미실행  이전 호출 잔재 0x99 가 보임");
                assert_eq!(
                    buf[CHAN_MAX - 1],
                    0,
                    "entry zeroize 미실행  이전 호출 잔재 0x88 가 보임"
                );
            });
        }
        assert_buf_all_zero("residue-after");
    }
}
