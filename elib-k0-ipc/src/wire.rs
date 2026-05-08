use zeroize::Zeroize;

use crate::error::IpcError;
use crate::op::Op;

pub const MAGIC: u32 = 0xE1_1B_C0_DE;
pub const VER: u8 = 0x01;
pub const HEADER_LEN: usize = 4 + 1 + 2 + 4;
pub const MAX_FRAME: usize = 16_384;
pub const MAX_PAYLOAD: usize = MAX_FRAME - HEADER_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub op: Op,
    pub len: u32,
}

pub fn decode_header(frame: &[u8]) -> Result<Header, IpcError> {
    let magic_bytes = match frame.get(0..4) {
        Some(b) => b,
        None => return Err(IpcError::TruncatedFrame),
    };
    let magic_arr: [u8; 4] = match magic_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return Err(IpcError::TruncatedFrame),
    };
    if u32::from_le_bytes(magic_arr) != MAGIC {
        return Err(IpcError::MagicMismatch);
    }

    let ver = match frame.get(4) {
        Some(&v) => v,
        None => return Err(IpcError::TruncatedFrame),
    };
    if ver != VER {
        return Err(IpcError::VersionMismatch);
    }

    let op_bytes = match frame.get(5..7) {
        Some(b) => b,
        None => return Err(IpcError::TruncatedFrame),
    };
    let op_arr: [u8; 2] = match op_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return Err(IpcError::TruncatedFrame),
    };
    let op_value = u16::from_le_bytes(op_arr);
    let op = match Op::from_u16(op_value) {
        Ok(o) => o,
        Err(_) => return Err(IpcError::UnknownOp),
    };

    let len_bytes = match frame.get(7..11) {
        Some(b) => b,
        None => return Err(IpcError::TruncatedFrame),
    };
    let len_arr: [u8; 4] = match len_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return Err(IpcError::TruncatedFrame),
    };
    let len = u32::from_le_bytes(len_arr);

    if (len as usize) > MAX_PAYLOAD {
        return Err(IpcError::PayloadTooLong);
    }
    let frame_total = HEADER_LEN.saturating_add(len as usize);
    if frame.len() < frame_total {
        return Err(IpcError::TruncatedFrame);
    }

    Ok(Header { op, len })
}

pub fn encode_header(out: &mut [u8], op: Op, payload_len: u32) -> Result<usize, IpcError> {
    if (payload_len as usize) > MAX_PAYLOAD {
        return Err(IpcError::PayloadTooLong);
    }
    let total = HEADER_LEN.saturating_add(payload_len as usize);
    if out.len() < total {
        return Err(IpcError::PayloadTooLong);
    }

    let magic = MAGIC.to_le_bytes();
    let op_le = (op as u16).to_le_bytes();
    let len_le = payload_len.to_le_bytes();

    let header_arr: &mut [u8; HEADER_LEN] = match out.get_mut(0..HEADER_LEN) {
        Some(s) => match s.try_into() {
            Ok(a) => a,
            Err(_) => return Err(IpcError::PayloadTooLong),
        },
        None => return Err(IpcError::PayloadTooLong),
    };
    *header_arr = [
        magic[0], magic[1], magic[2], magic[3], VER, op_le[0], op_le[1], len_le[0], len_le[1],
        len_le[2], len_le[3],
    ];

    Ok(HEADER_LEN)
}

pub fn encode_error(out: &mut [u8], err: IpcError) -> usize {
    let header_arr: &mut [u8; HEADER_LEN] = match out.get_mut(0..HEADER_LEN) {
        Some(s) => match s.try_into() {
            Ok(a) => a,
            Err(_) => return 0,
        },
        None => return 0,
    };
    let magic = MAGIC.to_le_bytes();
    let err_le = (err as u16).to_le_bytes();
    let len_le = 0u32.to_le_bytes();
    *header_arr = [
        magic[0], magic[1], magic[2], magic[3], VER, err_le[0], err_le[1], len_le[0], len_le[1],
        len_le[2], len_le[3],
    ];
    HEADER_LEN
}

/// IPC 와이어 버퍼용 RAII zeroize newtype 입니다.
///
/// `[u8; MAX_FRAME]` (16 KiB) 를 감싸며 `Drop` 에서 휘발성 쓰기로 전체 backing
/// storage 를 소거합니다. 디스패처는 본 newtype 의 stack-frame scope 종료 시점에
/// per-IPC-iteration zeroize 가 자동 보장되며, 명시적 `wire_*.zeroize()` 호출이
/// 불필요합니다.
///
/// # Security Note
/// - `Drop` 시 `[u8; MAX_FRAME].zeroize()` (blanket impl in `zeroize` crate) 호출 →
///   휘발성 쓰기 + compiler/memory barrier + black_box 가 LTO/opt-level=z 환경에서도
///   소거 코드 elision 을 방지합니다.
/// - `Deref` / `DerefMut` / `AsRef` 미구현 — 호출자는 `as_slice` / `as_mut_slice` /
///   `as_array` / `as_mut_array` 중 명시적 view 를 선택해야 합니다 (Phase 2 와의
///   일관성).
/// - `Clone` / `Copy` 미구현 — 16 KiB 스택 복제 + 사본 zeroize 책임 누락 위험을 차단.
/// - `Default` 는 `Self::new()` 로 위임되며 모두 0 으로 초기화 — 비밀이 아닌 빈
///   버퍼이므로 implicit-default 가 안전합니다.
pub struct SecureFrameBuffer([u8; MAX_FRAME]);

impl SecureFrameBuffer {
    /// 모두 0 으로 초기화된 새 버퍼를 생성합니다.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self([0u8; MAX_FRAME])
    }

    /// 내부 버퍼 전체에 대한 슬라이스 view 입니다.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// 내부 버퍼 전체에 대한 가변 슬라이스 view 입니다.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// 내부 버퍼 전체에 대한 고정-길이 배열 view 입니다.
    #[inline]
    pub fn as_array(&self) -> &[u8; MAX_FRAME] {
        &self.0
    }

    /// 내부 버퍼 전체에 대한 가변 고정-길이 배열 view 입니다.
    #[inline]
    pub fn as_mut_array(&mut self) -> &mut [u8; MAX_FRAME] {
        &mut self.0
    }
}

impl Default for SecureFrameBuffer {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for SecureFrameBuffer {
    #[inline]
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecureFrameBuffer {
    #[inline]
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_header(op: Op, len: u32) -> [u8; HEADER_LEN] {
        let magic = MAGIC.to_le_bytes();
        let op_le = (op as u16).to_le_bytes();
        let len_le = len.to_le_bytes();
        [
            magic[0], magic[1], magic[2], magic[3], VER, op_le[0], op_le[1], len_le[0], len_le[1],
            len_le[2], len_le[3],
        ]
    }

    /// 빈 frame 입력에 대해 TruncatedFrame 반환되는지 검증 (가장 작은 입력).
    #[test]
    fn test_wire_truncated_no_bytes() {
        let result = decode_header(&[]);
        assert!(
            matches!(result, Err(IpcError::TruncatedFrame)),
            "expected TruncatedFrame, got {:?}",
            result
        );
    }

    /// MAGIC 4 바이트 중 3 바이트만 있는 부분 입력에 TruncatedFrame 반환.
    #[test]
    fn test_wire_truncated_partial_magic() {
        let result = decode_header(&[0xDE, 0xC0, 0x1B]);
        assert!(
            matches!(result, Err(IpcError::TruncatedFrame)),
            "expected TruncatedFrame, got {:?}",
            result
        );
    }

    /// MAGIC 만 있고 VER 없음 — TruncatedFrame.
    #[test]
    fn test_wire_truncated_no_ver() {
        let m = MAGIC.to_le_bytes();
        let result = decode_header(&m);
        assert!(
            matches!(result, Err(IpcError::TruncatedFrame)),
            "expected TruncatedFrame, got {:?}",
            result
        );
    }

    /// MAGIC + VER 만 있고 OP 없음 (5 바이트) — TruncatedFrame.
    #[test]
    fn test_wire_truncated_no_op() {
        let m = MAGIC.to_le_bytes();
        let frame = [m[0], m[1], m[2], m[3], VER];
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::TruncatedFrame)),
            "expected TruncatedFrame, got {:?}",
            result
        );
    }

    /// MAGIC + VER + OP 만 있고 LEN 없음 (7 바이트) — TruncatedFrame.
    #[test]
    fn test_wire_truncated_no_len() {
        let m = MAGIC.to_le_bytes();
        let op_le = (Op::SignKeygenEd25519 as u16).to_le_bytes();
        let frame = [m[0], m[1], m[2], m[3], VER, op_le[0], op_le[1]];
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::TruncatedFrame)),
            "expected TruncatedFrame, got {:?}",
            result
        );
    }

    /// 11 바이트 헤더가 LEN=100 을 선언했지만 실제 페이로드가 50 바이트뿐 — TruncatedFrame.
    #[test]
    fn test_wire_truncated_partial_payload() {
        let header = make_valid_header(Op::SignKeygenEd25519, 100);
        let mut frame = [0u8; HEADER_LEN + 50];
        let dst = match frame.get_mut(..HEADER_LEN) {
            Some(s) => s,
            None => unreachable!(),
        };
        dst.copy_from_slice(&header);
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::TruncatedFrame)),
            "expected TruncatedFrame, got {:?}",
            result
        );
    }

    /// 모두 0 인 11 바이트 frame 은 MAGIC 위반.
    #[test]
    fn test_wire_magic_mismatch_zero() {
        let frame = [0u8; HEADER_LEN];
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::MagicMismatch)),
            "expected MagicMismatch, got {:?}",
            result
        );
    }

    /// MAGIC 끝 바이트가 1 비트 다름 — MagicMismatch.
    #[test]
    fn test_wire_magic_mismatch_off_by_one() {
        let bad_magic: u32 = MAGIC ^ 0x01;
        let bm = bad_magic.to_le_bytes();
        let mut frame = make_valid_header(Op::SignKeygenEd25519, 0);
        let dst = match frame.get_mut(..4) {
            Some(s) => s,
            None => unreachable!(),
        };
        dst.copy_from_slice(&bm);
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::MagicMismatch)),
            "expected MagicMismatch, got {:?}",
            result
        );
    }

    /// VER=0 (legal MAGIC, illegal version) — VersionMismatch.
    #[test]
    fn test_wire_version_mismatch_zero() {
        let mut frame = make_valid_header(Op::SignKeygenEd25519, 0);
        let dst = match frame.get_mut(4) {
            Some(b) => b,
            None => unreachable!(),
        };
        *dst = 0x00;
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::VersionMismatch)),
            "expected VersionMismatch, got {:?}",
            result
        );
    }

    /// VER=2 (future version, not yet supported) — VersionMismatch.
    #[test]
    fn test_wire_version_mismatch_future() {
        let mut frame = make_valid_header(Op::SignKeygenEd25519, 0);
        let dst = match frame.get_mut(4) {
            Some(b) => b,
            None => unreachable!(),
        };
        *dst = 0x02;
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::VersionMismatch)),
            "expected VersionMismatch, got {:?}",
            result
        );
    }

    /// 0x0001 (낮은 unmapped) — UnknownOp.
    #[test]
    fn test_wire_unknown_op_low() {
        let m = MAGIC.to_le_bytes();
        let frame = [
            m[0], m[1], m[2], m[3], VER, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::UnknownOp)),
            "expected UnknownOp, got {:?}",
            result
        );
    }

    /// 0xFFFF (catch-all) — UnknownOp.
    #[test]
    fn test_wire_unknown_op_high() {
        let m = MAGIC.to_le_bytes();
        let frame = [
            m[0], m[1], m[2], m[3], VER, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::UnknownOp)),
            "expected UnknownOp, got {:?}",
            result
        );
    }

    /// 0x10_FF (SignKeygen family 안의 unmapped 알고리즘) — UnknownOp.
    #[test]
    fn test_wire_unknown_op_in_gap() {
        let m = MAGIC.to_le_bytes();
        let frame = [
            m[0], m[1], m[2], m[3], VER, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::UnknownOp)),
            "expected UnknownOp, got {:?}",
            result
        );
    }

    /// LEN = MAX_PAYLOAD + 1 — PayloadTooLong.
    #[test]
    fn test_wire_payload_too_long_max_frame_plus_one() {
        let frame = make_valid_header(Op::SignKeygenEd25519, (MAX_PAYLOAD as u32) + 1);
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::PayloadTooLong)),
            "expected PayloadTooLong, got {:?}",
            result
        );
    }

    /// LEN = u32::MAX — PayloadTooLong (saturating add 회피, 명시적 거부).
    #[test]
    fn test_wire_payload_too_long_max_u32() {
        let frame = make_valid_header(Op::SignKeygenEd25519, u32::MAX);
        let result = decode_header(&frame);
        assert!(
            matches!(result, Err(IpcError::PayloadTooLong)),
            "expected PayloadTooLong, got {:?}",
            result
        );
    }

    /// LEN = MAX_PAYLOAD (boundary case — 정상 통과해야 함).
    #[test]
    fn test_wire_payload_at_max_payload_decodes_ok() {
        // 16373 byte payload — 본 테스트는 stack 에 16384 byte 전체 frame 을 만들어야 함.
        let mut frame = [0u8; MAX_FRAME];
        let header = make_valid_header(Op::SignKeygenEd25519, MAX_PAYLOAD as u32);
        let dst = match frame.get_mut(..HEADER_LEN) {
            Some(s) => s,
            None => unreachable!(),
        };
        dst.copy_from_slice(&header);
        let result = decode_header(&frame);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
        let Ok(h) = result else { unreachable!() };
        assert_eq!(h.op, Op::SignKeygenEd25519);
        assert_eq!(h.len, MAX_PAYLOAD as u32);
    }

    /// LEN = 0 (header-only frame for SignKeygenEd25519 — semantically wrong but
    /// header parser 자체는 통과; payload 의 의미 검증은 dispatcher 책임).
    #[test]
    fn test_wire_header_only_frame_decodes_ok() {
        let frame = make_valid_header(Op::SignKeygenEd25519, 0);
        let result = decode_header(&frame);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
        let Ok(h) = result else { unreachable!() };
        assert_eq!(h.op, Op::SignKeygenEd25519);
        assert_eq!(h.len, 0);
    }

    /// encode_header / decode_header round-trip — well-formed encode 가 well-formed decode.
    #[test]
    fn test_wire_encode_decode_roundtrip() {
        let mut buf = [0u8; HEADER_LEN + 32];
        let enc_result = encode_header(&mut buf, Op::SignKeygenEd25519, 32);
        assert!(
            enc_result.is_ok(),
            "encode_header failed: {:?}",
            enc_result.err()
        );
        let Ok(n) = enc_result else { unreachable!() };
        assert_eq!(n, HEADER_LEN);
        // header_only 가 아니라 payload 를 32 바이트 더 채워야 LEN 검증 통과.
        let dec_result = decode_header(&buf);
        assert!(dec_result.is_ok(), "expected Ok, got {:?}", dec_result);
        let Ok(h) = dec_result else { unreachable!() };
        assert_eq!(h.op, Op::SignKeygenEd25519);
        assert_eq!(h.len, 32);
    }

    /// SecureFrameBuffer::Drop 가 내부 [u8; MAX_FRAME] backing storage 를 zeroize
    /// 경로로 소거함을 검증. Drop 본문은 self.0.zeroize() 와 동일하므로 명시적
    /// Zeroize 호출이 동등한 검증을 제공합니다.
    #[test]
    fn secure_frame_buffer_zeroize_clears_interior() {
        let mut buf = SecureFrameBuffer::new();
        buf.as_mut_array().fill(0xAB);
        assert!(
            buf.as_slice().iter().all(|&b| b == 0xAB),
            "사전조건: 모든 바이트 0xAB"
        );
        Zeroize::zeroize(&mut buf);
        assert!(
            buf.as_slice().iter().all(|&b| b == 0),
            "Zeroize 후 모든 바이트 0"
        );
    }

    /// SecureFrameBuffer::new() 가 모두 0 으로 초기화됨을 검증.
    #[test]
    fn secure_frame_buffer_new_is_zero() {
        let buf = SecureFrameBuffer::new();
        assert!(
            buf.as_slice().iter().all(|&b| b == 0),
            "new() 직후 모든 바이트 0"
        );
    }

    /// SecureFrameBuffer::Default 가 SecureFrameBuffer::new() 와 동등함을 검증.
    #[test]
    fn secure_frame_buffer_default_is_new() {
        let buf: SecureFrameBuffer = Default::default();
        assert!(
            buf.as_slice().iter().all(|&b| b == 0),
            "Default 직후 모든 바이트 0"
        );
    }
}
