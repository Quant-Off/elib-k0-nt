// Phase 3 Plan-03 Wave 0 — SoftHsmAesGcmState.nonce_counter == u64::MAX 시 write 거부
// (Pitfall 5 / D-12 — fail-stop 영구 거부)
//
// 검증 대상
//   - iso-light-k0::bus::SoftwareBus::write 의 AesGcm role 분기 (src/bus.rs L236):
//       if state.nonce_counter == u64::MAX { return Err(BusError::Internal); }
//   - counter 가 단조 증가 후 u64::MAX 에 도달하면 더 이상 write 통과 금지

#[cfg(test)]
mod tests {
    // iso-light-k0::bus 의 AesGcm write-arm 미러
    // 본 sibling 테스트는 커널 크레이트에 의존하지 않으므로 분기를 인라인 복제
    #[derive(Clone, Copy)]
    struct MockAesGcmCounter {
        counter: u64,
    }

    impl MockAesGcmCounter {
        fn new(initial: u64) -> Self {
            Self { counter: initial }
        }

        // src/bus.rs 의 AesGcm 분기 write 시뮬레이션
        //   - u64::MAX 시 즉시 Err  fail-stop
        //   - 그 외 wrapping_add(1) 후 nonce 사용 가능 (테스트는 새 counter 만 반환)
        fn simulate_write(&mut self) -> Result<u64, ()> {
            if self.counter == u64::MAX {
                return Err(());
            }
            self.counter = self.counter.wrapping_add(1);
            Ok(self.counter)
        }
    }

    #[test]
    fn test_u64_max_freezes_writes() {
        let mut s = MockAesGcmCounter::new(u64::MAX);
        assert!(
            s.simulate_write().is_err(),
            "u64::MAX counter 는 write 거부"
        );
        // 거부 후 counter 변경 0
        assert_eq!(s.counter, u64::MAX);
    }

    #[test]
    fn test_below_max_writes_ok() {
        let mut s = MockAesGcmCounter::new(u64::MAX - 1);
        let r = s.simulate_write();
        assert!(r.is_ok());
        assert_eq!(s.counter, u64::MAX);
        // 다음 호출은 u64::MAX 에 도달하여 Err
        assert!(s.simulate_write().is_err());
    }

    #[test]
    fn test_zero_initial_writes_ok() {
        let mut s = MockAesGcmCounter::new(0);
        let r = s.simulate_write();
        assert!(r.is_ok());
        assert_eq!(s.counter, 1);
    }

    #[test]
    fn test_monotonic_until_max() {
        let mut s = MockAesGcmCounter::new(u64::MAX - 3);
        assert!(s.simulate_write().is_ok());
        assert_eq!(s.counter, u64::MAX - 2);
        assert!(s.simulate_write().is_ok());
        assert_eq!(s.counter, u64::MAX - 1);
        assert!(s.simulate_write().is_ok());
        assert_eq!(s.counter, u64::MAX);
        // u64::MAX 도달 후 모든 후속 write 거부 (fail-stop)
        assert!(s.simulate_write().is_err());
        assert_eq!(s.counter, u64::MAX);
        assert!(s.simulate_write().is_err());
        assert_eq!(s.counter, u64::MAX);
    }
}
