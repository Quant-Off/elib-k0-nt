use crate::{Digest, SHA512State};
use constant_time::{Choice, CtEqOps, CtGreeter, CtSelOps};
use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

const SHA_512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

impl SHA512State {
    pub(crate) fn new(is_384: bool) -> Self {
        // 초기 해시 값 — FIPS 180-4 §5.3.4 (SHA-512) 및 §5.3.5 (SHA-384)
        // 모든 값은 64비트이며, SHA-256/SHA-224의 32비트 상수는 여기서 사용하면 안 됨
        let state: [u64; 8] = if is_384 {
            [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ]
        } else {
            [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ]
        };
        Self {
            state,
            buffer: [0u8; 128],
            buffer_len: 0,
            total_len: 0,
            is_384,
        }
    }

    fn process_block(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];

        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                block[i * 8],
                block[i * 8 + 1],
                block[i * 8 + 2],
                block[i * 8 + 3],
                block[i * 8 + 4],
                block[i * 8 + 5],
                block[i * 8 + 6],
                block[i * 8 + 7],
            ]);
        }
        for i in 16..80 {
            // σ0(x) = ROTR1(x)  ⊕ ROTR8(x)  ⊕ SHR7(x)
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            // σ1(x) = ROTR19(x) ⊕ ROTR61(x) ⊕ SHR6(x)
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..80 {
            // Σ1(e) = ROTR14(e) ⊕ ROTR18(e) ⊕ ROTR41(e)
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA_512_K[i])
                .wrapping_add(w[i]);

            // Σ0(a) = ROTR28(a) ⊕ ROTR34(a) ⊕ ROTR39(a)
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);

        for item in &mut w {
            unsafe {
                write_volatile(item, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.total_len = self
            .total_len
            .wrapping_add((data.len() as u64).wrapping_mul(8));

        let mut i = 0usize;
        while i < data.len() {
            let fill: usize = 128 - self.buffer_len;
            let remain: usize = data.len() - i;

            // CT min(remain, fill): 메시지 길이는 SHA-2의 공개 정보임
            //   select(a, b, choice) -> choice==1일 때 b, choice==0일 때 a
            //   is_ge==1 (remain >= fill) -> fill   (현재 블록 완료)
            //   is_ge==0 (remain <  fill) -> remain (남은 것을 가져옴)
            let is_ge: Choice = CtGreeter::gt(&remain, &fill) | CtEqOps::eq(&remain, &fill);
            let chunk_len: usize = usize::select(&remain, &fill, is_ge);

            self.buffer[self.buffer_len..self.buffer_len + chunk_len]
                .copy_from_slice(&data[i..i + chunk_len]);
            self.buffer_len += chunk_len;
            i += chunk_len;

            if self.buffer_len == 128 {
                let block = self.buffer;
                self.process_block(&block);
                for b in &mut self.buffer {
                    unsafe {
                        write_volatile(b, 0);
                    }
                }
                compiler_fence(Ordering::SeqCst);
                self.buffer_len = 0;
            }
        }
    }

    pub(crate) fn finalize(mut self) -> Digest {
        let buf_len = self.buffer_len;

        // 필수 0x80 패딩 바이트 추가
        // buffer[buf_len+1 ..]는 이미 0임 (update의 각 블록 이후 삭제됨)
        self.buffer[buf_len] = 0x80;
        self.buffer_len += 1;

        // CT: 패딩된 데이터가 16바이트 길이 필드를 위한 공간을 남겨두는지 확인
        // 이 블록(위치 112-127)에서
        //   SHA-512 블록 = 128바이트, 메시지 길이는 마지막 16바이트를 차지함
        //   needs_extra == 1  -> buffer_len > 112: 길이는 두 번째 블록으로 가야 함
        //   needs_extra == 0  -> buffer_len ≤ 112: 길이는 이 블록에 맞음
        let needs_extra: Choice = CtGreeter::gt(&self.buffer_len, &112usize);
        let not_extra: Choice = !needs_extra;

        // SHA-512는 128비트 메시지 길이 필드를 사용함 (FIPS 180-4 §5.1.2)
        // 상위 64비트는 2^64비트보다 짧은 메시지의 경우 항상 0임
        let total_len_bytes = self.total_len.to_be_bytes();

        // 블록1
        // 항상 현재 버퍼 내용과 동일
        // !needs_extra일 때, [112..128]에 128비트 길이 필드 주입
        //   [112..120] = 0x00..00         (상위 64비트, 항상 0)
        //   [120..128] = total_len BE u64 (하위 64비트)
        //
        //   select(a, b, choice) -> choice==1일 때 b, choice==0일 때 a
        //   not_extra==1 -> 길이 값 주입
        //   not_extra==0 -> 버퍼 내용 유지
        let mut block1 = self.buffer;
        for j in 0..8usize {
            let orig_hi = block1[112 + j];
            let orig_lo = block1[120 + j];
            block1[112 + j] = u8::select(&orig_hi, &0u8, not_extra);
            block1[120 + j] = u8::select(&orig_lo, &total_len_bytes[j], not_extra);
        }
        self.process_block(&block1);

        let mut state_b1 = self.state;

        // 블록2
        // 데이터 길이에 따른 분기를 피하기 위해 무조건 처리
        // needs_extra == 1일 때만 의미 있음
        let mut block2 = [0u8; 128];
        block2[120..128].copy_from_slice(&total_len_bytes);
        self.process_block(&block2);

        // CT 상태 선택:
        //   needs_extra==1 -> self.state 유지 (블록2 이후)
        //   needs_extra==0 -> state_b1으로 되돌림
        //
        //   select(a, b, choice) -> choice==1일 때 b, choice==0일 때 a
        for (state_val, b1_val) in self.state.iter_mut().zip(state_b1.iter()) {
            *state_val = u64::select(b1_val, state_val, needs_extra);
        }

        // 다이제스트 빌드
        // SHA-384: 6 워드 × 8 바이트 = 48 바이트
        // SHA-512: 8 워드 × 8 바이트 = 64 바이트
        let digest_len = if self.is_384 { 48usize } else { 64usize };
        let mut bytes = [0u8; 64];
        for i in 0..8usize {
            let word_bytes = self.state[i].to_be_bytes(); // [u8; 8]
            bytes[i * 8..i * 8 + 8].copy_from_slice(&word_bytes);
        }
        // SHA-384에서 사용되지 않는 7번째 및 8번째 워드를 읽기 전에 삭제
        // bytes[48..64]는 SHA-384의 as_bytes()를 통해 노출되지 않지만, 0으로 만드는 것은
        // 메모리에 상주하는 시간을 제한함
        if self.is_384 {
            for b in &mut bytes[48..64] {
                unsafe {
                    write_volatile(b, 0);
                }
            }
        }

        for b in &mut block1 {
            unsafe {
                write_volatile(b, 0);
            }
        }
        for b in &mut block2 {
            unsafe {
                write_volatile(b, 0);
            }
        }
        for s in &mut state_b1 {
            unsafe {
                write_volatile(s, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);

        // 여기서 `self`가 드롭됨 -> SHA512State::Drop이 state, buffer, total_len을 0으로 만듦
        // 호출자가 `bytes` 사용을 마치면 Digest::Drop이 이를 0으로 만듦
        Digest {
            bytes,
            len: digest_len,
        }
    }
}
