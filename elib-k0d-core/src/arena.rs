use elib_k0_ipc::Op;
use zeroize::Zeroize;

pub struct RequestArena {
    pub op: Op,
    pub msg_len: u16,
    pub sk: [u8; 4896],
    pub pk: [u8; 2592],
    pub msg: [u8; 1024],
    pub sig: [u8; 4627],
    pub ctx: [u8; 255],
    pub rnd: [u8; 32],
    pub shared_secret: [u8; 32],
    pub ct: [u8; 1568],
}

impl RequestArena {
    pub const fn new() -> Self {
        Self {
            op: Op::SignKeygenEd25519,
            msg_len: 0,
            sk: [0u8; 4896],
            pk: [0u8; 2592],
            msg: [0u8; 1024],
            sig: [0u8; 4627],
            ctx: [0u8; 255],
            rnd: [0u8; 32],
            shared_secret: [0u8; 32],
            ct: [0u8; 1568],
        }
    }
}

impl Default for RequestArena {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for RequestArena {
    fn zeroize(&mut self) {
        // op 는 #[repr(u16)] 메타데이터이며 비밀 아님 — 단순 재할당으로 sentinel 설정.
        self.op = Op::SignKeygenEd25519;
        self.msg_len.zeroize();
        self.sk.zeroize();
        self.pk.zeroize();
        self.msg.zeroize();
        self.sig.zeroize();
        self.ctx.zeroize();
        self.rnd.zeroize();
        self.shared_secret.zeroize();
        self.ct.zeroize();
    }
}

impl Drop for RequestArena {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RequestArena 의 모든 byte-array 필드 + msg_len 가 zeroize() 호출 후 0 으로 소거되는지 검증 (DMN-03 base).
    #[test]
    fn request_arena_zeroize_clears_all_fields() {
        let mut arena = RequestArena::new();
        arena.sk.fill(0xAA);
        arena.pk.fill(0xBB);
        arena.sig.fill(0xCC);
        arena.msg.fill(0xDD);
        arena.msg_len = 0xBEEF;
        arena.ctx.fill(0xEE);
        arena.rnd.fill(0xFF);
        arena.shared_secret.fill(0x11);
        arena.ct.fill(0x22);

        arena.zeroize();

        assert!(arena.sk.iter().all(|&b| b == 0), "arena.sk 미소거");
        assert!(arena.pk.iter().all(|&b| b == 0), "arena.pk 미소거");
        assert!(arena.sig.iter().all(|&b| b == 0), "arena.sig 미소거");
        assert!(arena.msg.iter().all(|&b| b == 0), "arena.msg 미소거");
        assert_eq!(arena.msg_len, 0, "arena.msg_len 미소거");
        assert!(arena.ctx.iter().all(|&b| b == 0), "arena.ctx 미소거");
        assert!(arena.rnd.iter().all(|&b| b == 0), "arena.rnd 미소거");
        assert!(
            arena.shared_secret.iter().all(|&b| b == 0),
            "arena.shared_secret 미소거"
        );
        assert!(arena.ct.iter().all(|&b| b == 0), "arena.ct 미소거");
    }

    /// zeroize() 후 op 필드는 sentinel 값 (SignKeygenEd25519) 유지 — invalid discriminant 회피.
    #[test]
    fn request_arena_zeroize_preserves_op_sentinel() {
        let mut arena = RequestArena::new();
        arena.op = Op::SignEd25519;
        arena.zeroize();
        assert_eq!(arena.op, Op::SignKeygenEd25519);
    }
}
