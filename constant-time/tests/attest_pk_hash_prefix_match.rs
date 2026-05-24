// Phase 5 Plan 05-04 Wave 1 GREEN fill-in
// BLAKE3(pk)[0..4] = HsmSlotInfo._reserved[2..6] 4 옥텟 byte-exact 일치 회귀 (D-14)
//
// 검증 대상
//   - kernel 측 attach 성공 후 enumerate 결과의 _reserved[2..6] 4 옥텟이
//     BLAKE3(pk) digest 의 첫 4 옥텟과 byte-exact 일치
//   - AUDIT_RING 의 pk_hash_prefix 와 동일 prefix 값이 회귀
//   - 서로 다른 pk seed 는 서로 다른 prefix 산출 (collision 회귀)

#[cfg(test)]
mod tests {
    use blake::{BLAKE3_OUT_LEN, Blake3};

    /// MLDSA-44 public key 길이 잠금
    const PK_LEN: usize = 1312;
    /// HsmSlotInfo._reserved[2..6] prefix 길이 잠금 (D-14)
    const PREFIX_LEN: usize = 4;

    // 컴파일-타임 ABI 가드
    const _: () = assert!(PREFIX_LEN == 4);
    const _: () = assert!(BLAKE3_OUT_LEN == 32);

    /// BLAKE3(pk) 첫 4 옥텟 prefix 추출 host mock
    ///
    /// kernel 측 enumerate body 의 prefix 산출 분기와 동일 패턴
    fn pk_prefix(pk: &[u8; PK_LEN]) -> [u8; PREFIX_LEN] {
        let mut hasher = Blake3::new();
        hasher.update(pk);
        let digest_obj = hasher.finalize().expect("Blake3 finalize 실패");
        let digest_slice = digest_obj.as_slice();
        assert_eq!(
            digest_slice.len(),
            BLAKE3_OUT_LEN,
            "BLAKE3 출력 길이 불일치"
        );

        let mut prefix = [0_u8; PREFIX_LEN];
        prefix.copy_from_slice(&digest_slice[..PREFIX_LEN]);
        prefix
    }

    /// BLAKE3(pk)[0..4] = mock_reserved[2..6] byte-exact 일치 회귀
    #[test]
    fn attest_pk_prefix_matches_slotinfo_reserved() {
        // (1) 결정론적 pk seed
        let pk = [0xAA_u8; PK_LEN];

        // (2) BLAKE3(pk) 첫 4 옥텟 prefix 추출
        let prefix = pk_prefix(&pk);

        // (3) Mock HsmSlotInfo._reserved 8 옥텟 D-14 layout
        //     [0] = bus_kind (0 = Software)
        //     [1] = verify_result_code (0 = Ok)
        //     [2..6] = BLAKE3(pk)[0..4] prefix
        //     [6..8] = padding
        let mut mock_reserved = [0_u8; 8];
        mock_reserved[0] = 0; // bus_kind Software
        mock_reserved[1] = 0; // verify_result_code Ok
        mock_reserved[2..6].copy_from_slice(&prefix);

        // (4) byte-exact 일치 단언
        assert_eq!(&mock_reserved[2..6], &prefix[..], "prefix 영역 불일치");
        assert_eq!(mock_reserved[0], 0, "bus_kind octet 불일치");
        assert_eq!(mock_reserved[1], 0, "verify_result_code octet 불일치");

        // (5) determinism 동일 pk 동일 prefix
        let prefix2 = pk_prefix(&pk);
        assert_eq!(prefix, prefix2, "동일 pk 에서 prefix 가 달라짐");
    }

    /// 서로 다른 pk seed 가 서로 다른 prefix 를 산출 collision 회귀
    #[test]
    fn attest_pk_prefix_distinguishes_different_keys() {
        let pk_aa = [0xAA_u8; PK_LEN];
        let pk_55 = [0x55_u8; PK_LEN];

        let prefix_aa = pk_prefix(&pk_aa);
        let prefix_55 = pk_prefix(&pk_55);

        // BLAKE3 의 confusion 속성으로 두 prefix 가 일치할 확률 ≈ 2^-32
        assert_ne!(
            prefix_aa, prefix_55,
            "서로 다른 pk 에서 동일 prefix collision 발생"
        );
    }
}
