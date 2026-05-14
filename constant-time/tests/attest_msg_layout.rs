// Phase 5 Plan 05-04 Wave 1 GREEN fill-in
// D-07 amendment 의 BLAKE3(pre) digest 32 옥텟 평문 layout 잠금
//
// 검증 대상
//   - kernel 측 verify_attest 의 message 재구성 buffer 가
//     pk(1312) || bus_kind_octet(1) || boot_challenge(32) = 1345 옥텟 layout 으로 정확 빌드
//   - BLAKE3(pre) 32 옥텟 digest 가 결정론적이며 MLDSA::verify 의 message 인자가 됨
//   - bus_kind 가 바뀌면 digest 도 달라짐 (bus substitution 차단)

#[cfg(test)]
mod tests {
    use blake::{BLAKE3_OUT_LEN, Blake3};

    /// MLDSA-44 public key 길이 잠금
    const PK_LEN: usize = 1312;
    /// boot challenge nonce 길이 잠금
    const CHAL_LEN: usize = 32;
    /// pre-image 총 길이 = pk(1312) + bus_kind(1) + challenge(32)
    const PRE_LEN: usize = PK_LEN + 1 + CHAL_LEN;
    /// BLAKE3 digest 길이 잠금 (서명 평문 32 옥텟)
    const DIGEST_LEN: usize = 32;

    // 컴파일-타임 ABI 가드
    const _: () = assert!(PRE_LEN == 1345);
    const _: () = assert!(PK_LEN == 1312);
    const _: () = assert!(CHAL_LEN == 32);
    const _: () = assert!(DIGEST_LEN == BLAKE3_OUT_LEN);

    /// pre-image 와 digest 를 결정론적으로 산출하는 host-side mock
    ///
    /// kernel 측 verify_attest body 와 동일 copy 순서를 mirror 한다
    fn build_pre_and_digest(
        pk: &[u8; PK_LEN],
        bus_kind: u8,
        challenge: &[u8; CHAL_LEN],
    ) -> ([u8; PRE_LEN], [u8; DIGEST_LEN]) {
        let mut pre = [0_u8; PRE_LEN];
        pre[0..PK_LEN].copy_from_slice(pk);
        pre[PK_LEN] = bus_kind;
        pre[PK_LEN + 1..PK_LEN + 1 + CHAL_LEN].copy_from_slice(challenge);

        let mut hasher = Blake3::new();
        hasher.update(&pre);
        let digest_obj = hasher.finalize().expect("Blake3 finalize 실패");
        let digest_slice = digest_obj.as_slice();
        assert_eq!(digest_slice.len(), DIGEST_LEN, "BLAKE3 출력 길이 ABI 불일치");

        let mut digest = [0_u8; DIGEST_LEN];
        digest.copy_from_slice(&digest_slice[..DIGEST_LEN]);
        (pre, digest)
    }

    /// pre-image 1345 옥텟 layout byte-exact 회귀 + BLAKE3 digest 32 옥텟 결정론 잠금
    #[test]
    fn attest_message_layout_byte_exact() {
        // (1) 결정론적 입력 Software bus_kind = 0
        let pk = [0xAA_u8; PK_LEN];
        let bus_kind: u8 = 0;
        let challenge = [0x55_u8; CHAL_LEN];

        let (pre, digest) = build_pre_and_digest(&pk, bus_kind, &challenge);

        // (2) pre-image 3 영역 byte-exact 단언
        assert_eq!(&pre[0..PK_LEN], &pk[..], "pk 영역 byte 불일치");
        assert_eq!(pre[PK_LEN], bus_kind, "bus_kind octet 위치 불일치");
        assert_eq!(
            &pre[PK_LEN + 1..],
            &challenge[..],
            "challenge 영역 byte 불일치"
        );

        // (3) 길이 단언 D-07 1345 옥텟 잠금
        assert_eq!(pre.len(), 1345, "pre-image 총 길이가 1345 옥텟이 아님");

        // (4) BLAKE3 digest 32 옥텟 잠금 D-07 amendment
        assert_eq!(digest.len(), 32, "BLAKE3 digest 길이가 32 옥텟이 아님");

        // (5) determinism 같은 입력 같은 출력
        let (pre2, digest2) = build_pre_and_digest(&pk, bus_kind, &challenge);
        assert_eq!(pre, pre2, "동일 입력에 대해 pre-image 가 달라짐");
        assert_eq!(digest, digest2, "동일 입력에 대해 digest 가 달라짐");
    }

    /// bus_kind 변경 시 digest 변화 회귀 bus substitution 차단 보안 속성
    #[test]
    fn attest_message_bus_kind_changes_digest() {
        let pk = [0xAA_u8; PK_LEN];
        let challenge = [0x55_u8; CHAL_LEN];

        // Software (0) vs Ring3Process (1)
        let (pre_sw, digest_sw) = build_pre_and_digest(&pk, 0, &challenge);
        let (pre_r3, digest_r3) = build_pre_and_digest(&pk, 1, &challenge);

        // (1) layout 동일 단 bus_kind octet 만 다름
        assert_eq!(&pre_sw[0..PK_LEN], &pre_r3[0..PK_LEN], "pk 영역은 동일해야 함");
        assert_eq!(
            &pre_sw[PK_LEN + 1..],
            &pre_r3[PK_LEN + 1..],
            "challenge 영역은 동일해야 함"
        );
        assert_eq!(pre_sw[PK_LEN], 0);
        assert_eq!(pre_r3[PK_LEN], 1);

        // (2) digest 는 반드시 다름 BLAKE3 가 1 octet 차이를 전체 출력에 확산
        assert_ne!(
            digest_sw, digest_r3,
            "bus_kind 만 다른 두 pre 의 digest 가 같음 bus substitution 회귀"
        );
    }
}
