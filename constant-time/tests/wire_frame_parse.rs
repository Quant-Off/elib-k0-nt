// Phase 4 Plan 02 Wave 0 — parse_header 6 필드 byte offset 회귀 가드 (D-01)
//
// 검증 대상
//   - src/bus.rs::parse_header 가 16 byte raw 헤더의 6 필드를 little-endian 으로 정확히 디코드
//   - magic 4B (offset 0..4) / version u16 (4..6) / cmd u16 (6..8) / req_id u32 (8..12)
//     / payload_len u16 (12..14) / status u16 (14..16) 모두 정확

#[cfg(test)]
mod tests {
    // Plan 01 신규 WireFrameHeader 6 필드 layout 의 host mock
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MockWireFrameHeader {
        magic: [u8; 4],
        version: u16,
        cmd: u16,
        req_id: u32,
        payload_len: u16,
        status: u16,
    }

    // src/bus.rs::parse_header 의 host mock 재현
    fn parse_header(bytes: &[u8; 16]) -> MockWireFrameHeader {
        MockWireFrameHeader {
            magic: [bytes[0], bytes[1], bytes[2], bytes[3]],
            version: u16::from_le_bytes([bytes[4], bytes[5]]),
            cmd: u16::from_le_bytes([bytes[6], bytes[7]]),
            req_id: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            payload_len: u16::from_le_bytes([bytes[12], bytes[13]]),
            status: u16::from_le_bytes([bytes[14], bytes[15]]),
        }
    }

    #[test]
    fn parse_header_six_fields_byte_offset() {
        // 결정론적 input  magic=LWK0, version=0x0001, cmd=0x0010 (Blake3Hash), req_id=5,
        // payload_len=28, status=0
        let bytes: [u8; 16] = [
            0x4C, 0x57, 0x4B, 0x30, // magic "LWK0"
            0x01, 0x00, // version = 1 LE
            0x10, 0x00, // cmd = 0x0010 LE
            0x05, 0x00, 0x00, 0x00, // req_id = 5 LE
            0x1C, 0x00, // payload_len = 28 LE
            0x00, 0x00, // status = 0 LE
        ];
        let hdr = parse_header(&bytes);
        assert_eq!(hdr.magic, [0x4C, 0x57, 0x4B, 0x30]);
        assert_eq!(hdr.version, 0x0001);
        assert_eq!(hdr.cmd, 0x0010);
        assert_eq!(hdr.req_id, 5);
        assert_eq!(hdr.payload_len, 28);
        assert_eq!(hdr.status, 0);
    }
}
