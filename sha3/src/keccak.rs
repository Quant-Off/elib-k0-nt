use crate::{Digest, KeccakState, MAX_RATE_BYTES};
use constant_time::{Choice, CtEqOps, CtGreeter, CtSelOps};
use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

// Keccak-f[1600] 상수
const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

// ρ 회전 오프셋, 플랫 레인 인덱스(x + 5*y)로 인덱싱됨
const RHO_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

// π 순열 대상: PI_INDICES[i]는 레인 i가 이동하는 위치
const PI_INDICES: [usize; 25] = [
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
];

impl KeccakState {
    pub(crate) fn new(rate_bits: usize, domain: u8) -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; MAX_RATE_BYTES],
            buffer_len: 0,
            rate_bytes: rate_bits / 8,
            domain,
        }
    }

    // Keccak-f[1600] — 24라운드 순열
    pub(crate) fn keccak_f1600(state: &mut [u64; 25]) {
        let mut tmp = [0u64; 25];

        for &rc in &KECCAK_ROUND_CONSTANTS {
            // θ (Theta)
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for i in 0..25 {
                state[i] ^= d[i % 5];
            }

            // ρ + π (결합)
            for i in 0..25 {
                tmp[PI_INDICES[i]] = state[i].rotate_left(RHO_OFFSETS[i]);
            }

            // χ (Chi)
            for y in 0..5 {
                let base = y * 5;
                for x in 0..5 {
                    state[base + x] =
                        tmp[base + x] ^ (!tmp[base + (x + 1) % 5] & tmp[base + (x + 2) % 5]);
                }
            }

            // ι (Iota)
            state[0] ^= rc;
        }

        // 스택에서 중간 상태 지우기
        for item in &mut tmp {
            unsafe {
                write_volatile(item, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }

    // 흡수
    // `block[..rate_bytes]`를 상태 레인에 XOR한 다음 순열 적용
    // 모든 SHA-3 / SHAKE 속도는 8바이트의 정확한 배수
    fn absorb_block(&mut self, block: &[u8]) {
        let rate_words = block.len() / 8;
        for i in 0..rate_words {
            let o = i * 8;
            let word = u64::from_le_bytes([
                block[o],
                block[o + 1],
                block[o + 2],
                block[o + 3],
                block[o + 4],
                block[o + 5],
                block[o + 6],
                block[o + 7],
            ]);
            self.state[i] ^= word;
        }
        Self::keccak_f1600(&mut self.state);
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;
        while i < data.len() {
            let fill: usize = self.rate_bytes - self.buffer_len;
            let remain: usize = data.len() - i;

            // CT min(remain, fill)
            // 메시지 길이는 SHA-3의 공개 정보, CT 연산은 sha2 크레이트와의
            // 구현 일관성을 위해 사용됨
            //   select(a, b, choice) → choice==1일 때 b, choice==0일 때 a
            //   is_ge==1 (remain >= fill) → fill   (현재 블록 완료)
            //   is_ge==0 (remain <  fill) → remain (남은 것을 가져옴)
            let is_ge: Choice = CtGreeter::gt(&remain, &fill) | CtEqOps::eq(&remain, &fill);
            let chunk_len: usize = usize::select(&remain, &fill, is_ge);

            self.buffer[self.buffer_len..self.buffer_len + chunk_len]
                .copy_from_slice(&data[i..i + chunk_len]);
            self.buffer_len += chunk_len;
            i += chunk_len;

            if self.buffer_len == self.rate_bytes {
                // 빌림 충돌을 피하기 위해 버퍼를 스택에 복사한 다음 흡수
                let mut block = self.buffer;
                self.absorb_block(&block[..self.rate_bytes]);
                for b in &mut block {
                    unsafe {
                        write_volatile(b, 0);
                    }
                }
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

    // 패딩
    // FIPS 202 다중 속도 패딩(10*1)을 SHA-3 / SHAKE 도메인 접미사와 함께 적용한 다음,
    // 패딩된 블록을 흡수
    //
    // 바이트 정렬된 입력의 경우 패딩된 블록은 항상 정확히 하나의 추가 스펀지 호출에 맞음
    // 추가 블록 CT 분기가 필요 없음
    //
    // 레이아웃 (buffer_len = L, rate_bytes = R):
    //   [0 .. L-1] : 버퍼링된 메시지 바이트
    //   [L]        : 도메인 접미사 (SHA-3의 경우 0x06, SHAKE의 경우 0x1f)
    //   [L+1 .. R-2]: 0x00 패딩
    //   [R-1]      : 0x80  (패딩 끝 "1" 비트)
    //
    // L == R-1일 때: block[R-1] = domain ^ 0x80 = domain | 0x80
    //   (비트 겹침 없음: 0x06 = 0b0000_0110, 0x1f = 0b0001_1111, 0x80 = 0b1000_0000)
    pub(crate) fn pad(&mut self) {
        let rate = self.rate_bytes;
        let mut block = [0u8; MAX_RATE_BYTES];
        block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        block[self.buffer_len] = self.domain;
        block[rate - 1] ^= 0x80;
        self.absorb_block(&block[..rate]);
        for b in &mut block {
            unsafe {
                write_volatile(b, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
        self.buffer_len = 0;
    }

    // 스퀴즈
    // 상태에서 정확히 `output_len` 바이트를 스퀴즈 (단일 패스)
    // 모든 고정 출력 SHA-3 변형에 대해 한 번의 스퀴즈로 충분
    //   SHA3-512: output=64 ≤ rate=72  ✓   SHA3-224: output=28 ≤ rate=144 ✓
    //   SHA3-384: output=48 ≤ rate=104 ✓   SHA3-256: output=32 ≤ rate=136 ✓
    fn squeeze_fixed(&self, output_len: usize, out: &mut [u8; 64]) {
        let full_words = output_len / 8;
        let rem_bytes = output_len % 8;
        for i in 0..full_words {
            let word_bytes = self.state[i].to_le_bytes();
            out[i * 8..i * 8 + 8].copy_from_slice(&word_bytes);
        }
        if rem_bytes > 0 {
            let word_bytes = self.state[full_words].to_le_bytes();
            out[full_words * 8..full_words * 8 + rem_bytes]
                .copy_from_slice(&word_bytes[..rem_bytes]);
        }
    }

    // 호출자가 제공한 버퍼로 스퀴즈, 다중 블록 XOF 출력을 위해 다시 순열 적용
    fn squeeze_into(&mut self, out: &mut [u8]) {
        let output_len = out.len();
        let rate_words = self.rate_bytes / 8;
        let mut pos = 0usize;
        while pos < output_len {
            for word_idx in 0..rate_words {
                if pos >= output_len {
                    break;
                }
                let word_bytes = self.state[word_idx].to_le_bytes();
                let remain: usize = output_len - pos;
                // CT take = min(remain, 8)
                let is_ge: Choice = CtGreeter::gt(&remain, &8usize) | CtEqOps::eq(&remain, &8usize);
                let take: usize = usize::select(&remain, &8usize, is_ge);
                out[pos..pos + take].copy_from_slice(&word_bytes[..take]);
                pos += take;
            }
            if pos < output_len {
                Self::keccak_f1600(&mut self.state);
            }
        }
    }

    // 공개 완료 진입점
    pub(crate) fn finalize_fixed(mut self, output_len: usize) -> Digest {
        self.pad();
        let mut bytes = [0u8; 64];
        self.squeeze_fixed(output_len, &mut bytes);
        // 여기서 `self`가 드롭됨 → KeccakState::Drop이 상태와 버퍼를 0으로 만듦
        Digest {
            bytes,
            len: output_len,
        }
    }

    pub(crate) fn finalize_xof(mut self, out: &mut [u8]) {
        self.pad();
        self.squeeze_into(out);
        // 여기서 `self`가 드롭됨 → KeccakState::Drop이 상태와 버퍼를 0으로 만듦
    }
}
