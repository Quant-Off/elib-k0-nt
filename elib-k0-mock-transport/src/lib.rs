#![cfg_attr(not(test), no_std)]

use elib_k0_ipc::{HEADER_LEN, IpcError, MAX_FRAME, MAX_PAYLOAD, Op, Transport, encode_header};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockError {
    NoPendingRequest,
    BufferTooSmall,
}

pub struct MockTransport {
    pending_request: [u8; MAX_FRAME],
    request_len: usize,
    pending_response: [u8; MAX_FRAME],
    response_len: usize,
}

impl MockTransport {
    pub const fn new() -> Self {
        Self {
            pending_request: [0u8; MAX_FRAME],
            request_len: 0,
            pending_response: [0u8; MAX_FRAME],
            response_len: 0,
        }
    }

    pub fn client_send(&mut self, req: &[u8]) -> Result<(), MockError> {
        if req.len() > MAX_FRAME {
            return Err(MockError::BufferTooSmall);
        }
        let dst = match self.pending_request.get_mut(..req.len()) {
            Some(s) => s,
            None => return Err(MockError::BufferTooSmall),
        };
        dst.copy_from_slice(req);
        self.request_len = req.len();
        Ok(())
    }

    pub fn client_recv(&self, out: &mut [u8]) -> Result<usize, MockError> {
        if out.len() < self.response_len {
            return Err(MockError::BufferTooSmall);
        }
        let src = match self.pending_response.get(..self.response_len) {
            Some(s) => s,
            None => return Err(MockError::BufferTooSmall),
        };
        let dst = match out.get_mut(..self.response_len) {
            Some(s) => s,
            None => return Err(MockError::BufferTooSmall),
        };
        dst.copy_from_slice(src);
        Ok(self.response_len)
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for MockTransport {
    type Error = MockError;

    fn round_trip(&mut self, send: &[u8], recv: &mut [u8]) -> Result<usize, Self::Error> {
        if !send.is_empty() {
            if send.len() > MAX_FRAME {
                return Err(MockError::BufferTooSmall);
            }
            let dst = match self.pending_response.get_mut(..send.len()) {
                Some(s) => s,
                None => return Err(MockError::BufferTooSmall),
            };
            dst.copy_from_slice(send);
            self.response_len = send.len();
        }
        if self.request_len == 0 {
            return Err(MockError::NoPendingRequest);
        }
        if recv.len() < self.request_len {
            return Err(MockError::BufferTooSmall);
        }
        let n = self.request_len;
        let src = match self.pending_request.get(..n) {
            Some(s) => s,
            None => return Err(MockError::BufferTooSmall),
        };
        let dst = match recv.get_mut(..n) {
            Some(s) => s,
            None => return Err(MockError::BufferTooSmall),
        };
        dst.copy_from_slice(src);
        self.request_len = 0;
        Ok(n)
    }
}

pub fn encode_op_to_wire(op: Op, payload: &[u8], out: &mut [u8]) -> Result<usize, IpcError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(IpcError::PayloadTooLong);
    }
    let header_n = encode_header(out, op, payload.len() as u32)?;
    if header_n != HEADER_LEN {
        return Err(IpcError::MalformedRequest);
    }
    let total = HEADER_LEN.saturating_add(payload.len());
    if out.len() < total {
        return Err(IpcError::PayloadTooLong);
    }
    let body = match out.get_mut(HEADER_LEN..total) {
        Some(s) => s,
        None => return Err(IpcError::PayloadTooLong),
    };
    body.copy_from_slice(payload);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MockTransport happy path: client_send -> round_trip -> client_recv 가 byte-identity.
    #[test]
    fn mock_transport_happy_path() {
        let mut t = MockTransport::new();
        let req: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        t.client_send(&req).expect("client_send");
        let mut recv_buf = [0u8; MAX_FRAME];
        let resp: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x05];
        let n = t.round_trip(&resp, &mut recv_buf).expect("round_trip");
        assert_eq!(n, req.len());
        assert_eq!(&recv_buf[..n], &req);
        let mut out_buf = [0u8; MAX_FRAME];
        let m = t.client_recv(&mut out_buf).expect("client_recv");
        assert_eq!(m, resp.len());
        assert_eq!(&out_buf[..m], &resp);
    }

    /// pending_request 비어있을 때 round_trip 호출 시 NoPendingRequest 반환.
    #[test]
    fn mock_transport_no_pending_request() {
        let mut t = MockTransport::new();
        let mut recv_buf = [0u8; MAX_FRAME];
        match t.round_trip(&[], &mut recv_buf) {
            Err(MockError::NoPendingRequest) => {}
            other => panic!("expected NoPendingRequest, got {:?}", other),
        }
    }

    /// recv 버퍼가 request 보다 작을 때 BufferTooSmall.
    #[test]
    fn mock_transport_recv_buffer_too_small() {
        let mut t = MockTransport::new();
        let req: [u8; 100] = [0xAAu8; 100];
        t.client_send(&req).expect("client_send");
        let mut small = [0u8; 50];
        match t.round_trip(&[], &mut small) {
            Err(MockError::BufferTooSmall) => {}
            other => panic!("expected BufferTooSmall, got {:?}", other),
        }
    }

    /// round_trip 이 pending_request 를 consume — 두 번째 호출은 NoPendingRequest.
    #[test]
    fn mock_transport_request_consumed_after_round_trip() {
        let mut t = MockTransport::new();
        let req: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        t.client_send(&req).expect("client_send");
        let mut recv_buf = [0u8; MAX_FRAME];
        t.round_trip(&[], &mut recv_buf).expect("first round_trip");
        match t.round_trip(&[], &mut recv_buf) {
            Err(MockError::NoPendingRequest) => {}
            other => panic!("expected NoPendingRequest after consume, got {:?}", other),
        }
    }

    /// encode_op_to_wire 가 well-formed wire frame 을 만들고 decode_header 로 다시 파싱 가능.
    #[test]
    fn encode_op_to_wire_roundtrips_through_decode_header() {
        use elib_k0_ipc::{MAGIC, VER, decode_header};
        let mut buf = [0u8; MAX_FRAME];
        let payload: [u8; 32] = [0x42u8; 32];
        let n = encode_op_to_wire(Op::SignKeygenEd25519, &payload, &mut buf)
            .expect("encode_op_to_wire");
        assert_eq!(n, HEADER_LEN + payload.len());
        let h = match decode_header(&buf[..n]) {
            Ok(h) => h,
            Err(e) => panic!("decode_header failed: {:?}", e),
        };
        assert_eq!(h.op, Op::SignKeygenEd25519);
        assert_eq!(h.len, payload.len() as u32);
        assert_eq!(&buf[HEADER_LEN..n], &payload);
        let magic_arr: [u8; 4] = buf[..4].try_into().unwrap();
        assert_eq!(u32::from_le_bytes(magic_arr), MAGIC);
        assert_eq!(buf[4], VER);
    }

    /// payload 가 MAX_PAYLOAD 초과 시 PayloadTooLong 반환.
    #[test]
    fn encode_op_to_wire_payload_too_long() {
        let mut buf = [0u8; MAX_FRAME];
        let big = [0u8; MAX_PAYLOAD + 1];
        match encode_op_to_wire(Op::SignKeygenEd25519, &big, &mut buf) {
            Err(IpcError::PayloadTooLong) => {}
            other => panic!("expected PayloadTooLong, got {:?}", other),
        }
    }

    /// Default::default() 가 new() 인스턴스와 동등.
    #[test]
    fn mock_transport_default_matches_new() {
        let a: MockTransport = Default::default();
        let b: MockTransport = MockTransport::new();
        assert_eq!(a.request_len, b.request_len);
        assert_eq!(a.response_len, b.response_len);
        assert!(a.pending_request.iter().all(|&x| x == 0));
        assert!(b.pending_request.iter().all(|&x| x == 0));
    }
}
