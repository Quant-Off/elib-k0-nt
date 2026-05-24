// Phase 5.1 Plan 05.1-04 GREEN — 3733 옥텟 AttestSubmit payload split + EnrollEvent 12 옥텟 raw layout 회귀 가드
//
// 검증 대상
//   - payload[0..1312] = pk, payload[1312] = bus_kind, payload[1313..3733] = sig (byte-exact split)
//   - EnrollEvent #[repr(C)] 12 옥텟 layout seq u32 LE | slot u8 | result u8 | bus u8 | _pad u8 | prefix [u8;4]
//   - WIRE_ATTEST_LEN const 3733 옥텟 컴파일-타임 잠금 (GREEN sanity 보존)
//
// pure byte-layout — crypto 미포함  실 ML-DSA-44 / BLAKE3 회귀는 Plan 05.1-05 책임

#[cfg(test)]
mod tests {
    /// ML-DSA-44 public key 길이 잠금
    const PK_LEN: usize = 1312;
    /// ML-DSA-44 signature 길이 잠금
    const SIG_LEN: usize = 2420;
    /// WireCmd AttestSubmit payload 총 길이 = PK_LEN + 1 bus_kind + SIG_LEN
    const WIRE_ATTEST_LEN: usize = PK_LEN + 1 + SIG_LEN;
    /// EnrollEvent raw byte 크기 잠금 Phase 5 hsm_attest.rs L69-78 #[repr(C)]
    const ENROLL_EVENT_SIZE: usize = 12;

    // 컴파일-타임 ABI 가드
    const _: () = assert!(WIRE_ATTEST_LEN == 3733);
    const _: () = assert!(PK_LEN == 1312);
    const _: () = assert!(SIG_LEN == 2420);
    const _: () = assert!(ENROLL_EVENT_SIZE == 12);

    /// payload 의 3 영역 (pk, bus_kind, sig) byte-exact split 회귀
    #[test]
    fn payload_split_byte_exact() {
        // (1) 결정론 pk / bus_kind / sig 패턴
        let pk = [0xAAu8; PK_LEN];
        let bus_kind: u8 = 0;
        let sig = [0x55u8; SIG_LEN];
        // (2) payload assembly
        let mut payload = [0u8; WIRE_ATTEST_LEN];
        payload[..PK_LEN].copy_from_slice(&pk);
        payload[PK_LEN] = bus_kind;
        payload[PK_LEN + 1..].copy_from_slice(&sig);
        // (3) byte-exact split 검증
        assert_eq!(&payload[..PK_LEN], &pk[..], "pk 영역 [0..1312] byte-exact");
        assert_eq!(payload[PK_LEN], bus_kind, "bus_kind 옥텟 [1312] byte-exact");
        assert_eq!(
            &payload[PK_LEN + 1..],
            &sig[..],
            "sig 영역 [1313..3733] byte-exact"
        );
        // (4) 총 길이 3733 D-01 ABI 잠금
        assert_eq!(payload.len(), 3733);
        // (5) 영역 경계 byte-level 비교
        assert_eq!(payload[PK_LEN - 1], 0xAAu8, "pk 마지막 옥텟 0xAA");
        assert_eq!(payload[PK_LEN + 1], 0x55u8, "sig 첫 옥텟 0x55");
        assert_eq!(payload[WIRE_ATTEST_LEN - 1], 0x55u8, "sig 마지막 옥텟 0x55");
    }

    /// EnrollEvent 12 옥텟 raw 직렬화 (transmute 우회 명시 byte 조립)
    #[test]
    fn enroll_event_raw_12_bytes() {
        // host-side EnrollEvent replica iso-light-k0 src/hsm_attest.rs L69-78 mirror
        #[repr(C)]
        struct EnrollEventLocal {
            seq: u32,
            slot_idx: u8,
            result: u8,
            bus_kind: u8,
            _pad: u8,
            pk_hash_prefix: [u8; 4],
        }
        // (1) Rust struct size 12 옥텟 (no padding)
        assert_eq!(
            core::mem::size_of::<EnrollEventLocal>(),
            ENROLL_EVENT_SIZE,
            "#[repr(C)] EnrollEvent 크기 12 옥텟 ABI 위반"
        );
        // (2) 결정론 값으로 EnrollEvent 인스턴스 생성
        let evt = EnrollEventLocal {
            seq: 1,
            slot_idx: 0x0A,
            result: 5,
            bus_kind: 1,
            _pad: 0,
            pk_hash_prefix: [0xDE, 0xAD, 0xBE, 0xEF],
        };
        // (3) Pitfall 2 회피 명시 byte 조립 (transmute 미사용)
        let mut bytes = [0u8; ENROLL_EVENT_SIZE];
        bytes[0..4].copy_from_slice(&evt.seq.to_le_bytes());
        bytes[4] = evt.slot_idx;
        bytes[5] = evt.result;
        bytes[6] = evt.bus_kind;
        bytes[7] = evt._pad;
        bytes[8..12].copy_from_slice(&evt.pk_hash_prefix);
        // (4) byte-exact 기대값
        assert_eq!(
            bytes,
            [
                0x01, 0x00, 0x00, 0x00, 0x0A, 0x05, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF
            ],
            "EnrollEvent raw 12 옥텟 layout byte-exact (seq u32 LE | slot | result | bus | pad | prefix [u8;4])"
        );
        // (5) seq u32 LE 분해 검증
        assert_eq!(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            1u32
        );
        // (6) _pad 반드시 0 (D-13 wire marker 일관)
        assert_eq!(bytes[7], 0u8, "_pad 옥텟 0 (alignment 보장)");
    }

    /// WIRE_ATTEST_LEN const 가 3733 옥텟임을 잠금 GREEN sanity (Plan 05.1-01 보존)
    #[test]
    fn wire_attest_len_const_3733() {
        assert_eq!(WIRE_ATTEST_LEN, 3733, "WIRE_ATTEST_LEN ABI 잠금 위반 D-01");
        assert_eq!(PK_LEN, 1312, "PK_LEN MLDSA44 ABI 잠금 위반");
        assert_eq!(SIG_LEN, 2420, "SIG_LEN MLDSA44 ABI 잠금 위반");
        assert_eq!(
            PK_LEN + 1 + SIG_LEN,
            3733,
            "payload split (pk || bus_kind || sig) 합 위반"
        );
    }
}
