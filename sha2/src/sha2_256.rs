use crate::{Digest, SHA256State};
use constant_time::{Choice, CtEqOps, CtGreeter, CtSelOps};
use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

const SHA_256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl SHA256State {
    pub(crate) fn new(is_224: bool) -> Self {
        let state = if is_224 {
            [
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
                0xbefa4fa4,
            ]
        } else {
            [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ]
        };
        Self {
            state,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
            is_224,
        }
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];

        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA_256_K[i])
                .wrapping_add(w[i]);

            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
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

        // 확장된 메시지 스케줄을 안전하게 삭제
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
            let fill: usize = 64 - self.buffer_len;
            let remain: usize = data.len() - i;

            // CT min(remain, fill): 이번 반복에서 복사할 청크
            // 메시지 길이는 SHA-2의 공개 정보이므로 is_ge 분기는 안전함
            // 구현 일관성을 위해 CT 연산 사용
            //   select(a, b, choice) -> choice==1일 때 b, choice==0일 때 a
            //   is_ge==1 (remain >= fill) -> fill   (현재 블록 완료)
            //   is_ge==0 (remain <  fill) -> remain (남은 것을 가져옴)
            let is_ge: Choice = CtGreeter::gt(&remain, &fill) | CtEqOps::eq(&remain, &fill);
            let chunk_len: usize = usize::select(&remain, &fill, is_ge);

            self.buffer[self.buffer_len..self.buffer_len + chunk_len]
                .copy_from_slice(&data[i..i + chunk_len]);
            self.buffer_len += chunk_len;
            i += chunk_len;

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.process_block(&block);
                // 버퍼 지우기, 펜스 후 buffer_len == 0
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

        // CT: 패딩된 데이터가 8바이트 길이 필드를 위한 공간을 남겨두는지 확인
        // 이 블록(위치 56-63)에서
        //   needs_extra == 1  -> buffer_len > 56: 길이는 두 번째 블록으로 가야 함
        //   needs_extra == 0  -> buffer_len ≤ 56: 길이는 이 블록에 맞음
        let needs_extra: Choice = CtGreeter::gt(&self.buffer_len, &56usize);
        let not_extra: Choice = !needs_extra;

        let total_len_bytes = self.total_len.to_be_bytes();

        // 블록1
        // 항상 현재 버퍼 내용과 동일
        // !needs_extra일 때, [56..64]에 8바이트 메시지 길이 필드 주입
        // needs_extra일 때, 해당 바이트를 그대로 둠 (0 또는 실제 데이터)
        //
        //   select(a, b, choice) -> choice==1일 때 b, choice==0일 때 a
        //   not_extra==1 -> total_len_bytes[j]  (길이 주입)
        //   not_extra==0 -> orig                (버퍼 내용 유지)
        let mut block1 = self.buffer;
        for j in 0..8usize {
            let orig = block1[56 + j];
            block1[56 + j] = u8::select(&orig, &total_len_bytes[j], not_extra);
        }
        self.process_block(&block1);

        // block1 이후 상태를 저장하여 !needs_extra 경로에서 복원할 수 있도록 함
        let mut state_b1 = self.state;

        // 블록2
        // 항상 처리됨, needs_extra == 1일 때만 의미 있음
        // needs_extra == 0일 때는 추가 작업이지만, 데이터 길이에 따른 분기를 피하기 위해
        // 무조건 수행
        let mut block2 = [0u8; 64];
        block2[56..64].copy_from_slice(&total_len_bytes);
        self.process_block(&block2);

        // CT 상태 선택:
        //   needs_extra==1 -> 두 블록 모두 필요 -> self.state 유지 (블록2 이후)
        //   needs_extra==0 -> 블록1만 필요  -> state_b1으로 되돌림
        //
        //   select(a, b, choice) -> choice==1일 때 b, choice==0일 때 a
        //   needs_extra==1 -> self.state[i]
        //   needs_extra==0 -> state_b1[i]
        for (state_val, b1_val) in self.state.iter_mut().zip(state_b1.iter()) {
            *state_val = u32::select(b1_val, state_val, needs_extra);
        }

        // 다이제스트 빌드
        let digest_len = if self.is_224 { 28usize } else { 32usize };
        let mut bytes = [0u8; 64];
        for i in 0..8usize {
            let word_bytes = self.state[i].to_be_bytes();
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word_bytes);
        }
        // SHA-224에서 사용되지 않는 8번째 워드를 읽기 전에 삭제
        // (digest_len == 28은 bytes[28..32]가 as_bytes()를 통해 노출되지 않음을 의미하지만,
        // 여기서 0으로 만드는 것은 메모리에 상주하는 시간을 제한함)
        if self.is_224 {
            for b in &mut bytes[28..32] {
                unsafe {
                    write_volatile(b, 0);
                }
            }
        }

        // 반환하기 전에 모든 임시 변수 삭제
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

        // 여기서 `self`가 드롭됨 -> SHA256State::Drop이 state, buffer,
        // total_len을 0으로 만듦, 호출자가 `bytes` 사용을 마치면
        // Digest::Drop이 이를 0으로 만듦
        Digest {
            bytes,
            len: digest_len,
        }
    }
}
