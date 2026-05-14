#[cfg(test)]
mod tests {
    use rng::{DrbgError, HashDRBGSHA256};
    use zeroize::Zeroize;

    // Deterministic seed material — independent of OS entropy so the regression
    // guard is reproducible across hosts and CI.
    const ENTROPY: [u8; 32] = [0x42u8; 32];
    const NONCE: [u8; 16] = [0x37u8; 16];

    fn fresh_drbg() -> HashDRBGSHA256 {
        // SAFETY: 테스트 전용 결정론적 시드 (보안 강도 무관, 회귀 비교만 수행)
        unsafe {
            HashDRBGSHA256::new_from_entropy(&ENTROPY, &NONCE, None)
                .expect("instantiate HashDRBGSHA256")
        }
    }

    fn gen_token_u64_local(drbg: &mut HashDRBGSHA256) -> u64 {
        let mut token_bytes = [0u8; 8];
        for _ in 0..5 {
            match drbg.generate(&mut token_bytes, None) {
                Ok(()) => {
                    let token = u64::from_be_bytes(token_bytes);
                    token_bytes.zeroize();
                    if token != 0 {
                        return token;
                    }
                    // 2^-64 probability — retry up to 5 times.
                    continue;
                }
                Err(DrbgError::ReseedRequired) => {
                    // 본 테스트의 생성량은 reseed_interval 보다 한참 적으므로
                    // 도달하지 않아야 한다. 도달 시 회귀 신호로 패닉.
                    panic!("ReseedRequired in regression test — DRBG budget mis-sized");
                }
                Err(e) => panic!("DRBG error: {:?}", e),
            }
        }
        panic!("gen_token_u64_local: exhausted retry budget");
    }

    #[test]
    fn no_zero_token() {
        let mut drbg = fresh_drbg();
        // 10,000 회 추출 시 진짜 0 토큰이 나올 확률은 약 5e-16.
        // 본 루프 안에서 0 이 한 번이라도 관측되면 retry 루프 자체가
        // 누락된 것이므로 패닉(`gen_token_u64_local` 내부에서 처리).
        for i in 0..10_000usize {
            let t = gen_token_u64_local(&mut drbg);
            assert_ne!(t, 0, "iteration {i}: zero token leaked");
        }
    }

    #[test]
    fn bigendian_decode_stable() {
        let mut drbg_a = fresh_drbg();
        let mut drbg_b = fresh_drbg();

        let mut raw_bytes = [0u8; 8];
        drbg_a.generate(&mut raw_bytes, None).expect("raw generate");
        let expected = u64::from_be_bytes(raw_bytes);

        let observed = gen_token_u64_local(&mut drbg_b);

        // 만약 expected 가 0 이면(2^-64) 본 테스트는 그 한 번의 추출에 대해
        // retry-비교가 무의미해진다. 본 결정론적 시드(0x42 .. / 0x37 ..)에서는
        // 첫 8바이트가 0 이 아니라는 사실이 사전 검증되어 있으므로 보호 가드만 둠.
        assert_ne!(expected, 0, "deterministic seed produced zero first token — pick a different seed");
        assert_eq!(
            expected, observed,
            "big-endian decode contract drift: raw=0x{:016x} helper=0x{:016x}",
            expected, observed
        );
    }

    #[test]
    fn single_drbg_instance_shared() {
        let mut drbg = fresh_drbg();
        let t1 = gen_token_u64_local(&mut drbg);
        let t2 = gen_token_u64_local(&mut drbg);
        // 같은 DRBG 인스턴스를 공유했다면 두 호출이 서로 다른 출력을 내야 한다.
        // 만약 함수가 매 호출마다 새 DRBG 를 만들었다면 결정론적 시드 → 동일 출력
        // → 본 검사가 실패. 회귀 가드의 핵심.
        assert_ne!(
            t1, t2,
            "DRBG state did not advance between calls — accidental per-call instance?"
        );
    }
}
