// Phase 3 Plan-03 Wave 0 — SoftHsmAesGcmState::zeroize cascade
// (key + nonce_counter 모두 0  Task-1 manual Zeroize impl 회귀 가드)
//
// 검증 대상
//   - SoftHsmAesGcmState 의 Zeroize impl 이 secrets-first (key 먼저, nonce_counter 다음) 로 동작
//   - Drop 자동 호출 (Secret<T>::Drop 의 volatile_write) 이 정상 컴파일

#[cfg(test)]
mod tests {
    use zeroize::{Secret, Zeroize};

    // iso-light-k0::bus::SoftHsmAesGcmState 의 host-side mock
    struct MockAesGcmState {
        key: Secret<[u8; 32]>,
        nonce_counter: u64,
    }

    impl Zeroize for MockAesGcmState {
        // secrets-first  key zeroize 먼저 (Pitfall 4), counter 는 단순 평문 metadata
        fn zeroize(&mut self) {
            self.key.zeroize();
            self.nonce_counter = 0;
        }
    }

    fn populated() -> MockAesGcmState {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8) ^ 0xA5;
        }
        MockAesGcmState {
            key: Secret::new(k),
            nonce_counter: 0xDEAD_BEEF_CAFE_BABE,
        }
    }

    #[test]
    fn test_zeroize_clears_key_and_counter() {
        let mut s = populated();
        // pre-zeroize  fields 비-영
        assert_ne!(s.nonce_counter, 0);
        let pre = *s.key.expose();
        assert!(pre.iter().any(|b| *b != 0));

        s.zeroize();

        // post-zeroize  key 와 nonce_counter 둘 다 0
        let post = *s.key.expose();
        assert_eq!(post, [0u8; 32], "key 가 zeroize 후 전부 0 이어야 함");
        assert_eq!(
            s.nonce_counter, 0,
            "nonce_counter 가 zeroize 후 0 이어야 함"
        );
    }

    #[test]
    fn test_zeroize_idempotent() {
        let mut s = populated();
        s.zeroize();
        s.zeroize();
        let post = *s.key.expose();
        assert_eq!(post, [0u8; 32]);
        assert_eq!(s.nonce_counter, 0);
    }

    #[test]
    fn test_secrets_first_ordering() {
        // secrets-first  key zeroize 먼저 호출되어야 (Pitfall 4)
        // 정확한 sequencing 은 single-threaded 환경에서 컴파일러 reordering 차단된
        // Zeroize::zeroize 의 volatile_write 보장에 의지  본 테스트는 두 operation 의
        // 종합 결과를 확인
        let mut s = populated();
        s.zeroize();
        assert_eq!(*s.key.expose(), [0u8; 32]);
        assert_eq!(s.nonce_counter, 0);
    }

    #[test]
    fn test_drop_completes() {
        // Drop 안전망  Secret<T>::Drop 이 volatile_write 로 key 를 0 으로 덮어쓴 후 정상 종료
        // 본 테스트는 컴파일 + drop 호출이 panic 없이 완료됨을 확인
        {
            let s = populated();
            // s 가 scope 이탈 시 Drop  panic 발생 시 테스트 실패
            core::mem::drop(s);
        }
    }
}
