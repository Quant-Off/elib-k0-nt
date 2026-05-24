// Phase 5.1 Plan 05.1-04 GREEN — WireCmd Status 응답 payload byte-exact roundtrip 회귀 가드
//
// 검증 대상
//   - payload[0..2] = written u16 LE
//   - payload[2..6] = total u32 LE
//   - payload[6..8] = reserved [0,0]
//   - payload[8..8+12*written] = EnrollEvent[..written] byte-exact
//   - empty ring 시 payload_len = 8, written = 0
//   - full ring 시 payload 8 + 12*32 = 392 옥텟 wire frame fit (RESEARCH §1.3 Pitfall 4)
//
// audit_snapshot 직렬화 byte-exact  ring 자체 의미는 host-side mock

#[cfg(test)]
mod tests {
    /// AUDIT_RING 용량 Phase 5 D-13 lock
    const AUDIT_RING_CAPACITY: usize = 32;
    /// EnrollEvent 1 옥텟 크기
    const ENROLL_EVENT_SIZE: usize = 12;
    /// Status response payload 헤더 영역 written(2) + total(4) + reserved(2)
    const STATUS_PAYLOAD_HEADER: usize = 8;
    /// Status response payload 최대 길이 8 + 12*32 = 392 옥텟
    const STATUS_PAYLOAD_MAX: usize =
        STATUS_PAYLOAD_HEADER + ENROLL_EVENT_SIZE * AUDIT_RING_CAPACITY;
    /// wire frame 최대 길이 Phase 4 D-15 lock
    const WIRE_FRAME_MAX: usize = 4096;
    /// wire magic LWK0
    const WIRE_MAGIC: [u8; 4] = *b"LWK0";
    /// wire version v1
    const WIRE_VERSION: u16 = 0x0001;
    /// 응답 비트 마스크
    const WIRE_CMD_RESPONSE_BIT: u16 = 0x8000;
    /// Phase 5.1 신규 dispatcher Status
    const CMD_STATUS: u16 = 0x0080;
    /// 성공 status
    const STATUS_OK: u16 = 0;

    // 컴파일-타임 ABI 가드
    const _: () = assert!(AUDIT_RING_CAPACITY == 32);
    const _: () = assert!(ENROLL_EVENT_SIZE == 12);
    const _: () = assert!(STATUS_PAYLOAD_HEADER == 8);
    const _: () = assert!(STATUS_PAYLOAD_MAX == 392);
    const _: () = assert!(16 + STATUS_PAYLOAD_MAX <= WIRE_FRAME_MAX); // header 16 + payload 392 = 408 < 4096

    /// host-side EnrollEvent replica iso-light-k0 src/hsm_attest.rs L69-78 mirror
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct EnrollEventLocal {
        seq: u32,
        slot_idx: u8,
        result: u8,
        bus_kind: u8,
        _pad: u8,
        pk_hash_prefix: [u8; 4],
    }

    /// 16 옥텟 wire header 직렬화
    fn write_header(cmd: u16, req_id: u32, payload_len: u16, status: u16, out: &mut [u8; 16]) {
        out[0..4].copy_from_slice(&WIRE_MAGIC);
        out[4..6].copy_from_slice(&WIRE_VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&cmd.to_le_bytes());
        out[8..12].copy_from_slice(&req_id.to_le_bytes());
        out[12..14].copy_from_slice(&payload_len.to_le_bytes());
        out[14..16].copy_from_slice(&status.to_le_bytes());
    }

    /// 응답 frame 빌더
    fn build_response_frame(
        req_id: u32,
        cmd: u16,
        status: u16,
        payload: &[u8],
        out: &mut [u8; WIRE_FRAME_MAX],
    ) -> usize {
        let payload_len = payload.len() as u16;
        let mut hdr_bytes = [0u8; 16];
        write_header(
            cmd | WIRE_CMD_RESPONSE_BIT,
            req_id,
            payload_len,
            status,
            &mut hdr_bytes,
        );
        out[..16].copy_from_slice(&hdr_bytes);
        if !payload.is_empty() {
            out[16..16 + payload.len()].copy_from_slice(payload);
        }
        16 + payload.len()
    }

    /// host-side mock dispatcher iso-light-k0 src/bus.rs::handle_status L287-325 byte-level mirror
    /// events 는 호출자가 직접 채운 mock AUDIT_RING (host-side simulate)
    fn mock_handle_status(
        req_id: u32,
        payload: &[u8],
        events: &[EnrollEventLocal],
        total: u32,
        out: &mut [u8; WIRE_FRAME_MAX],
    ) -> usize {
        // (1) payload empty 정합성
        if !payload.is_empty() {
            // BadFrame leg — 본 plan 의 happy path 외 회귀 (사용 안함)
            let mut hdr = [0u8; 16];
            write_header(0xFFFF, req_id, 0, 1, &mut hdr);
            out[..16].copy_from_slice(&hdr);
            return 16;
        }
        let written = events.len();
        debug_assert!(written <= AUDIT_RING_CAPACITY);
        let payload_len = STATUS_PAYLOAD_HEADER + written * ENROLL_EVENT_SIZE;
        debug_assert!(payload_len <= STATUS_PAYLOAD_MAX);
        // (2) staging buffer 8 + 32 * 12 = 392 옥텟
        let mut staging = [0u8; STATUS_PAYLOAD_MAX];
        staging[0..2].copy_from_slice(&(written as u16).to_le_bytes());
        staging[2..6].copy_from_slice(&total.to_le_bytes());
        // staging[6..8] reserved 이미 0
        for i in 0..written {
            let off = STATUS_PAYLOAD_HEADER + i * ENROLL_EVENT_SIZE;
            // Pitfall 2 회피 명시 byte 조립
            staging[off..off + 4].copy_from_slice(&events[i].seq.to_le_bytes());
            staging[off + 4] = events[i].slot_idx;
            staging[off + 5] = events[i].result;
            staging[off + 6] = events[i].bus_kind;
            staging[off + 7] = events[i]._pad;
            staging[off + 8..off + 12].copy_from_slice(&events[i].pk_hash_prefix);
        }
        build_response_frame(req_id, CMD_STATUS, STATUS_OK, &staging[..payload_len], out)
    }

    /// Status response payload 5 events 채운 ring 직렬화 byte-exact roundtrip 회귀
    #[test]
    fn status_response_layout_roundtrip() {
        // (1) host-side mock AUDIT_RING 5 events
        let events = [
            EnrollEventLocal {
                seq: 1,
                slot_idx: 0,
                result: 1,
                bus_kind: 0,
                _pad: 0,
                pk_hash_prefix: [0x11, 0x22, 0x33, 0x44],
            },
            EnrollEventLocal {
                seq: 2,
                slot_idx: 1,
                result: 2,
                bus_kind: 1,
                _pad: 0,
                pk_hash_prefix: [0x55, 0x66, 0x77, 0x88],
            },
            EnrollEventLocal {
                seq: 3,
                slot_idx: 2,
                result: 5,
                bus_kind: 0,
                _pad: 0,
                pk_hash_prefix: [0x99, 0xAA, 0xBB, 0xCC],
            },
            EnrollEventLocal {
                seq: 4,
                slot_idx: 0xFE,
                result: 6,
                bus_kind: 1,
                _pad: 0,
                pk_hash_prefix: [0xDD, 0xEE, 0xFF, 0x00],
            },
            EnrollEventLocal {
                seq: 5,
                slot_idx: 0xFE,
                result: 5,
                bus_kind: 0,
                _pad: 0,
                pk_hash_prefix: [0xCA, 0xFE, 0xBA, 0xBE],
            },
        ];
        let total: u32 = 5;
        // (2) mock dispatcher 호출 (payload empty)
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = mock_handle_status(42, &[], &events, total, &mut out);
        // (3) frame 길이 = 16 header + 8 + 5*12 = 16 + 68 = 84
        assert_eq!(n, 16 + STATUS_PAYLOAD_HEADER + 5 * ENROLL_EVENT_SIZE);
        assert_eq!(n, 84, "5 events frame 총 84 옥텟");
        // (4) header byte-exact
        assert_eq!(&out[0..4], &WIRE_MAGIC);
        assert_eq!(u16::from_le_bytes([out[4], out[5]]), WIRE_VERSION);
        assert_eq!(
            u16::from_le_bytes([out[6], out[7]]),
            CMD_STATUS | WIRE_CMD_RESPONSE_BIT,
            "cmd Status | RESPONSE_BIT = 0x8080"
        );
        assert_eq!(
            u16::from_le_bytes([out[12], out[13]]),
            68u16,
            "payload_len 8 + 60"
        );
        assert_eq!(u16::from_le_bytes([out[14], out[15]]), STATUS_OK);
        // (5) payload header 8 옥텟 byte-exact
        assert_eq!(u16::from_le_bytes([out[16], out[17]]), 5u16, "written 5");
        assert_eq!(
            u32::from_le_bytes([out[18], out[19], out[20], out[21]]),
            5u32,
            "total 5"
        );
        assert_eq!(&out[22..24], &[0u8, 0u8], "reserved 2 옥텟 0");
        // (6) events byte-exact (5 events × 12 옥텟)
        for i in 0..5 {
            let off = 16 + STATUS_PAYLOAD_HEADER + i * ENROLL_EVENT_SIZE;
            assert_eq!(
                u32::from_le_bytes([out[off], out[off + 1], out[off + 2], out[off + 3]]),
                events[i].seq,
                "event {i} seq"
            );
            assert_eq!(out[off + 4], events[i].slot_idx, "event {i} slot_idx");
            assert_eq!(out[off + 5], events[i].result, "event {i} result");
            assert_eq!(out[off + 6], events[i].bus_kind, "event {i} bus_kind");
            assert_eq!(out[off + 7], events[i]._pad, "event {i} pad");
            assert_eq!(
                &out[off + 8..off + 12],
                &events[i].pk_hash_prefix,
                "event {i} prefix"
            );
        }
    }

    /// 빈 ring 시 Status response written=0 payload_len=8 회귀
    #[test]
    fn empty_audit_ring_zero_events() {
        // (1) 빈 events + total 0
        let events: [EnrollEventLocal; 0] = [];
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = mock_handle_status(99, &[], &events, 0u32, &mut out);
        // (2) frame 길이 16 header + 8 payload header = 24
        assert_eq!(n, 16 + STATUS_PAYLOAD_HEADER);
        assert_eq!(n, 24, "empty ring frame 24 옥텟");
        // (3) payload_len == 8 (header only)
        assert_eq!(
            u16::from_le_bytes([out[12], out[13]]),
            8u16,
            "payload_len 8"
        );
        // (4) written u16 == 0
        assert_eq!(u16::from_le_bytes([out[16], out[17]]), 0u16, "written 0");
        // (5) total u32 == 0
        assert_eq!(
            u32::from_le_bytes([out[18], out[19], out[20], out[21]]),
            0u32,
            "total 0"
        );
        // (6) reserved [0,0]
        assert_eq!(&out[22..24], &[0u8, 0u8]);
        // (7) cmd / status
        assert_eq!(
            u16::from_le_bytes([out[6], out[7]]),
            CMD_STATUS | WIRE_CMD_RESPONSE_BIT
        );
        assert_eq!(u16::from_le_bytes([out[14], out[15]]), STATUS_OK);
    }

    /// 가득 찬 ring 시 payload 최대 392 옥텟 wire frame fit 회귀 (Pitfall 4 future-proof)
    #[test]
    fn full_ring_max_392b() {
        // (1) AUDIT_RING_CAPACITY = 32 events 모두 채움
        let mut events = [EnrollEventLocal::default(); AUDIT_RING_CAPACITY];
        for i in 0..AUDIT_RING_CAPACITY {
            events[i] = EnrollEventLocal {
                seq: i as u32,
                slot_idx: (i & 0xFF) as u8,
                result: 5,
                bus_kind: (i & 0x01) as u8,
                _pad: 0,
                pk_hash_prefix: [(i & 0xFF) as u8, 0x00, 0x00, 0x00],
            };
        }
        let total: u32 = 32;
        // (2) mock dispatcher 호출
        let mut out = [0u8; WIRE_FRAME_MAX];
        let n = mock_handle_status(123, &[], &events, total, &mut out);
        // (3) payload_len == 8 + 12*32 == 392
        let expected_payload_len = STATUS_PAYLOAD_HEADER + AUDIT_RING_CAPACITY * ENROLL_EVENT_SIZE;
        assert_eq!(expected_payload_len, 392, "STATUS_PAYLOAD_MAX 392 옥텟");
        assert_eq!(
            u16::from_le_bytes([out[12], out[13]]) as usize,
            expected_payload_len,
            "payload_len byte-exact 392"
        );
        // (4) frame 총 길이 16 + 392 = 408
        assert_eq!(n, 16 + expected_payload_len);
        assert_eq!(n, 408, "full ring frame 408 옥텟");
        // (5) WIRE_FRAME_MAX 4096 fit 검증
        assert!(n <= WIRE_FRAME_MAX, "frame 408 <= WIRE_FRAME_MAX 4096");
        // (6) written u16 == 32
        assert_eq!(u16::from_le_bytes([out[16], out[17]]), 32u16, "written 32");
        // (7) 마지막 event byte-exact
        let last_off = 16 + STATUS_PAYLOAD_HEADER + 31 * ENROLL_EVENT_SIZE;
        assert_eq!(
            u32::from_le_bytes([
                out[last_off],
                out[last_off + 1],
                out[last_off + 2],
                out[last_off + 3]
            ]),
            31u32,
            "last event seq 31"
        );
        assert_eq!(out[last_off + 4], 31u8, "last event slot_idx 31");
    }
}
