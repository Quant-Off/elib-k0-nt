use constant_time::{Choice, CtEqOps};
use zeroize::Zeroize;

pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buffer: [u8; 16],
    buffer_len: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut clamped = [0u8; 16];
        clamped.copy_from_slice(&key[..16]);

        clamped[3] &= 0x0f;
        clamped[7] &= 0x0f;
        clamped[11] &= 0x0f;
        clamped[15] &= 0x0f;
        clamped[4] &= 0xfc;
        clamped[8] &= 0xfc;
        clamped[12] &= 0xfc;

        let t0 = u32::from_le_bytes([clamped[0], clamped[1], clamped[2], clamped[3]]);
        let t1 = u32::from_le_bytes([clamped[4], clamped[5], clamped[6], clamped[7]]);
        let t2 = u32::from_le_bytes([clamped[8], clamped[9], clamped[10], clamped[11]]);
        let t3 = u32::from_le_bytes([clamped[12], clamped[13], clamped[14], clamped[15]]);

        let r0 = t0 & 0x03ff_ffff;
        let r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff;
        let r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff;
        let r3 = ((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff;
        let r4 = (t3 >> 8) & 0x03ff_ffff;

        clamped.zeroize();

        let pad0 = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        let pad1 = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        let pad2 = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        let pad3 = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

        Self {
            r: [r0, r1, r2, r3, r4],
            h: [0, 0, 0, 0, 0],
            pad: [pad0, pad1, pad2, pad3],
            buffer: [0u8; 16],
            buffer_len: 0,
        }
    }

    fn block(&mut self, m: &[u8], hibit: u32) {
        let s0 = u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
        let s1 = u32::from_le_bytes([m[4], m[5], m[6], m[7]]);
        let s2 = u32::from_le_bytes([m[8], m[9], m[10], m[11]]);
        let s3 = u32::from_le_bytes([m[12], m[13], m[14], m[15]]);

        let h0 = self.h[0].wrapping_add(s0 & 0x03ff_ffff);
        let h1 = self.h[1].wrapping_add(((s0 >> 26) | (s1 << 6)) & 0x03ff_ffff);
        let h2 = self.h[2].wrapping_add(((s1 >> 20) | (s2 << 12)) & 0x03ff_ffff);
        let h3 = self.h[3].wrapping_add(((s2 >> 14) | (s3 << 18)) & 0x03ff_ffff);
        let h4 = self.h[4].wrapping_add((s3 >> 8) | hibit);

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];

        let s1 = r1.wrapping_mul(5);
        let s2 = r2.wrapping_mul(5);
        let s3 = r3.wrapping_mul(5);
        let s4 = r4.wrapping_mul(5);

        let d0 = (h0 as u64)
            .wrapping_mul(r0 as u64)
            .wrapping_add((h1 as u64).wrapping_mul(s4 as u64))
            .wrapping_add((h2 as u64).wrapping_mul(s3 as u64))
            .wrapping_add((h3 as u64).wrapping_mul(s2 as u64))
            .wrapping_add((h4 as u64).wrapping_mul(s1 as u64));

        let d1 = (h0 as u64)
            .wrapping_mul(r1 as u64)
            .wrapping_add((h1 as u64).wrapping_mul(r0 as u64))
            .wrapping_add((h2 as u64).wrapping_mul(s4 as u64))
            .wrapping_add((h3 as u64).wrapping_mul(s3 as u64))
            .wrapping_add((h4 as u64).wrapping_mul(s2 as u64));

        let d2 = (h0 as u64)
            .wrapping_mul(r2 as u64)
            .wrapping_add((h1 as u64).wrapping_mul(r1 as u64))
            .wrapping_add((h2 as u64).wrapping_mul(r0 as u64))
            .wrapping_add((h3 as u64).wrapping_mul(s4 as u64))
            .wrapping_add((h4 as u64).wrapping_mul(s3 as u64));

        let d3 = (h0 as u64)
            .wrapping_mul(r3 as u64)
            .wrapping_add((h1 as u64).wrapping_mul(r2 as u64))
            .wrapping_add((h2 as u64).wrapping_mul(r1 as u64))
            .wrapping_add((h3 as u64).wrapping_mul(r0 as u64))
            .wrapping_add((h4 as u64).wrapping_mul(s4 as u64));

        let d4 = (h0 as u64)
            .wrapping_mul(r4 as u64)
            .wrapping_add((h1 as u64).wrapping_mul(r3 as u64))
            .wrapping_add((h2 as u64).wrapping_mul(r2 as u64))
            .wrapping_add((h3 as u64).wrapping_mul(r1 as u64))
            .wrapping_add((h4 as u64).wrapping_mul(r0 as u64));

        let mut c: u32;
        let mut h0 = d0 as u32 & 0x03ff_ffff;
        c = (d0 >> 26) as u32;

        let d1 = d1.wrapping_add(c as u64);
        let mut h1 = d1 as u32 & 0x03ff_ffff;
        c = (d1 >> 26) as u32;

        let d2 = d2.wrapping_add(c as u64);
        let h2 = d2 as u32 & 0x03ff_ffff;
        c = (d2 >> 26) as u32;

        let d3 = d3.wrapping_add(c as u64);
        let h3 = d3 as u32 & 0x03ff_ffff;
        c = (d3 >> 26) as u32;

        let d4 = d4.wrapping_add(c as u64);
        let h4 = d4 as u32 & 0x03ff_ffff;
        c = (d4 >> 26) as u32;

        h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 = h1.wrapping_add(c);

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
        self.h[4] = h4;
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        if self.buffer_len > 0 {
            let want = 16 - self.buffer_len;
            let have = data.len().min(want);
            self.buffer[self.buffer_len..self.buffer_len + have].copy_from_slice(&data[..have]);
            self.buffer_len += have;
            offset = have;

            if self.buffer_len == 16 {
                let buf = self.buffer;
                self.block(&buf, 1 << 24);
                self.buffer_len = 0;
            }
        }

        while offset + 16 <= data.len() {
            self.block(&data[offset..offset + 16], 1 << 24);
            offset += 16;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        if self.buffer_len > 0 {
            self.buffer[self.buffer_len] = 0x01;
            for i in (self.buffer_len + 1)..16 {
                self.buffer[i] = 0;
            }
            let buf = self.buffer;
            self.block(&buf, 0);
        }

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c = h1 >> 26;
        h1 &= 0x03ff_ffff;
        h2 = h2.wrapping_add(c);
        c = h2 >> 26;
        h2 &= 0x03ff_ffff;
        h3 = h3.wrapping_add(c);
        c = h3 >> 26;
        h3 &= 0x03ff_ffff;
        h4 = h4.wrapping_add(c);
        c = h4 >> 26;
        h4 &= 0x03ff_ffff;
        h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 = h1.wrapping_add(c);

        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x03ff_ffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x03ff_ffff;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x03ff_ffff;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x03ff_ffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mask = (g4 >> 31).wrapping_sub(1);
        let nmask = !mask;

        h0 = (h0 & nmask) | (g0 & mask);
        h1 = (h1 & nmask) | (g1 & mask);
        h2 = (h2 & nmask) | (g2 & mask);
        h3 = (h3 & nmask) | (g3 & mask);
        h4 = (h4 & nmask) | (g4 & mask);

        let f0 = (h0 | (h1 << 26)) as u64 + self.pad[0] as u64;
        let f1 = ((h1 >> 6) | (h2 << 20)) as u64 + self.pad[1] as u64 + (f0 >> 32);
        let f2 = ((h2 >> 12) | (h3 << 14)) as u64 + self.pad[2] as u64 + (f1 >> 32);
        let f3 = ((h3 >> 18) | (h4 << 8)) as u64 + self.pad[3] as u64 + (f2 >> 32);

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());

        self.h.zeroize();
        self.r.zeroize();
        self.pad.zeroize();
        self.buffer.zeroize();

        tag
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.h.zeroize();
        self.r.zeroize();
        self.pad.zeroize();
        self.buffer.zeroize();
        self.buffer_len.zeroize();
    }
}

pub fn poly1305_verify(tag1: &[u8; 16], tag2: &[u8; 16]) -> bool {
    let mut eq = Choice::from_u8(1);
    for i in 0..16 {
        eq &= CtEqOps::eq(&tag1[i], &tag2[i]);
    }
    eq.unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    /// Poly1305 의 r, h, pad, buffer 모두 비밀 데이터.
    /// Drop 후 모든 필드가 0 으로 소거되는지 검증.
    #[test]
    fn test_poly1305_zeroize_on_drop() {
        let key = [0x77u8; 32];
        let mut storage: MaybeUninit<Poly1305> = MaybeUninit::uninit();

        unsafe {
            storage.write(Poly1305::new(&key));
            // update 로 h 를 0 이 아닌 값으로 진행시킴
            (*storage.as_mut_ptr()).update(&[0x33u8; 16]);

            let r_ptr = &raw const (*storage.as_ptr()).r as *const u32;
            let h_ptr = &raw const (*storage.as_ptr()).h as *const u32;
            let pad_ptr = &raw const (*storage.as_ptr()).pad as *const u32;
            let buf_ptr = &raw const (*storage.as_ptr()).buffer as *const u8;

            let pre_r = core::slice::from_raw_parts(r_ptr, 5);
            let pre_h = core::slice::from_raw_parts(h_ptr, 5);
            let pre_pad = core::slice::from_raw_parts(pad_ptr, 4);
            assert!(pre_r.iter().any(|&w| w != 0), "Poly1305 r 가 비어 있음");
            assert!(pre_h.iter().any(|&w| w != 0), "Poly1305 h 가 비어 있음");
            assert!(pre_pad.iter().any(|&w| w != 0), "Poly1305 pad 가 비어 있음");

            storage.assume_init_drop();

            let post_r = core::slice::from_raw_parts(r_ptr, 5);
            let post_h = core::slice::from_raw_parts(h_ptr, 5);
            let post_pad = core::slice::from_raw_parts(pad_ptr, 4);
            let post_buf = core::slice::from_raw_parts(buf_ptr, 16);
            assert!(post_r.iter().all(|&w| w == 0), "Poly1305 r 미소거");
            assert!(post_h.iter().all(|&w| w == 0), "Poly1305 h 미소거");
            assert!(post_pad.iter().all(|&w| w == 0), "Poly1305 pad 미소거");
            assert!(post_buf.iter().all(|&b| b == 0), "Poly1305 buffer 미소거");
        }
    }

    #[test]
    fn test_poly1305_rfc8439_vector() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];

        let msg = b"Cryptographic Forum Research Group";

        let expected_tag: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];

        let mut poly = Poly1305::new(&key);
        poly.update(msg);
        let tag = poly.finalize();

        assert_eq!(tag, expected_tag);
    }

    #[test]
    fn test_poly1305_verify_constant_time() {
        let tag1: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let tag2: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let tag3: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17];

        assert!(poly1305_verify(&tag1, &tag2));
        assert!(!poly1305_verify(&tag1, &tag3));
    }
}
