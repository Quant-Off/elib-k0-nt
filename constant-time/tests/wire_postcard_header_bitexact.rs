// Phase 4 Plan 02 Wave 0 — postcard::to_slice 결과와 수동 write_header 결과가 byte-level
// 정확 일치 + 16 bytes 정확 회귀 가드 (D-15 / WIRE-04)
//
// 검증 대상
//   - WireFrameHeader 의 postcard fixint::le 직렬화 결과 byte 와 수동 write_header byte 가 정확 일치
//   - postcard::to_slice 의 출력 길이 == 16 (정수 LE 어댑터 적용 시 varint 비-사용 확인)
//   - postcard::from_bytes round-trip 결과가 원본 WireFrameHeader 와 PartialEq

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    // src/bus.rs::WireFrameHeader 정확 미러  postcard fixint::le 어댑터 적용
    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct WireFrameHeader {
        magic: [u8; 4],
        #[serde(with = "postcard::fixint::le")]
        version: u16,
        #[serde(with = "postcard::fixint::le")]
        cmd: u16,
        #[serde(with = "postcard::fixint::le")]
        req_id: u32,
        #[serde(with = "postcard::fixint::le")]
        payload_len: u16,
        #[serde(with = "postcard::fixint::le")]
        status: u16,
    }
    const _: () = assert!(core::mem::size_of::<WireFrameHeader>() == 16);
    const _: () = assert!(core::mem::align_of::<WireFrameHeader>() == 4);

    fn write_header(h: &WireFrameHeader, out: &mut [u8; 16]) {
        out[0..4].copy_from_slice(&h.magic);
        out[4..6].copy_from_slice(&h.version.to_le_bytes());
        out[6..8].copy_from_slice(&h.cmd.to_le_bytes());
        out[8..12].copy_from_slice(&h.req_id.to_le_bytes());
        out[12..14].copy_from_slice(&h.payload_len.to_le_bytes());
        out[14..16].copy_from_slice(&h.status.to_le_bytes());
    }

    #[test]
    fn postcard_to_slice_byte_equals_manual_write_header() {
        let hdr = WireFrameHeader {
            magic: *b"LWK0",
            version: 0x0001,
            cmd: 0x0010,
            req_id: 0xDEADBEEF,
            payload_len: 32,
            status: 0,
        };
        // (1) 수동 write_header 결과
        let mut manual16 = [0u8; 16];
        write_header(&hdr, &mut manual16);

        // (2) postcard::to_slice 결과
        let mut buf = [0u8; 32];
        let used = postcard::to_slice(&hdr, &mut buf).expect("postcard::to_slice 실패");
        assert_eq!(
            used.len(),
            16,
            "postcard fixint::le 출력 길이 16 bytes 불일치"
        );

        // (3) byte-level 정확 일치
        assert_eq!(
            used, &manual16,
            "postcard vs manual write_header byte 불일치"
        );

        // (4) round-trip  from_bytes 결과가 원본과 PartialEq
        let parsed: WireFrameHeader =
            postcard::from_bytes(used).expect("postcard::from_bytes 실패");
        assert_eq!(parsed, hdr, "round-trip 결과 불일치");
    }
}
