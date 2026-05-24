//! BLAKE3 코어 구현 모듈입니다.
//! BLAKE3 명세(https://github.com/BLAKE3-team/BLAKE3-specs)를 준수합니다.

use zeroize::{Secret, Zeroize};

use crate::{HashError, SecureBuffer};

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
pub const OUT_LEN: usize = 32;

/// BLAKE3 해시 상태 구조체입니다.
///
/// # Security Note
/// 키워드와 CV 스택은 `Secret`으로 보호되어 Drop 시 자동 소거됩니다.
/// 키드 모드(`new_keyed`)는 키를 IV로 변환하므로 키 바이트가 스택에 노출되지 않습니다.
pub struct Blake3 {
    chunk_state: ChunkState,
    key_words: Secret<[u32; 8]>,
    cv_stack: Secret<[[u32; 8]; 54]>,
    cv_stack_len: usize,
    flags: u32,
}

impl Blake3 {
    /// 표준 BLAKE3 인스턴스를 생성하는 함수입니다.
    pub fn new() -> Self {
        Self {
            chunk_state: ChunkState::new(&IV, 0, 0),
            key_words: Secret::new(IV),
            cv_stack: Secret::new([[0u32; 8]; 54]),
            cv_stack_len: 0,
            flags: 0,
        }
    }

    /// 키드 BLAKE3 인스턴스를 생성하는 함수입니다.
    ///
    /// # Arguments
    /// `key` — 정확히 32바이트
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        let key_words = words_from_le_bytes_32(key);
        Self {
            chunk_state: ChunkState::new(&key_words, 0, KEYED_HASH),
            key_words: Secret::new(key_words),
            cv_stack: Secret::new([[0u32; 8]; 54]),
            cv_stack_len: 0,
            flags: KEYED_HASH,
        }
    }

    /// 데이터를 공급하는 함수입니다.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.push_cv(chunk_cv);
                self.merge_cv_stack(total_chunks);
                self.chunk_state =
                    ChunkState::new(self.key_words.expose(), total_chunks, self.flags);
            }
            let take = (CHUNK_LEN - self.chunk_state.len()).min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// 32바이트 해시를 SecureBuffer로 반환하는 함수입니다.
    pub fn finalize(self) -> Result<SecureBuffer, HashError> {
        self.finalize_xof(OUT_LEN)
    }

    /// 임의 길이 출력을 SecureBuffer로 반환하는 함수입니다.
    ///
    /// # Security Note
    /// XOF 출력은 ROOT 플래그와 카운터 모드로 무제한 확장됩니다.
    pub fn finalize_xof(self, out_len: usize) -> Result<SecureBuffer, HashError> {
        let mut output = self.chunk_state.output();
        let mut parent_nodes = self.cv_stack_len;
        while parent_nodes > 0 {
            parent_nodes -= 1;
            let left_cv: Secret<[u32; 8]> = Secret::new(self.cv_stack.expose()[parent_nodes]);
            let right_cv: Secret<[u32; 8]> = output.chaining_value();
            output = parent_output(&left_cv, &right_cv, self.key_words.expose(), self.flags);
            // left_cv, right_cv Drop at iteration end → volatile-zero
        }
        let mut result = SecureBuffer::new_owned(out_len)?;
        output.root_output_bytes(result.as_mut_slice());
        // self 와 output 은 스코프 종료 시 각자의 Drop 으로 소거됨
        Ok(result)
    }

    fn push_cv(&mut self, cv: Secret<[u32; 8]>) {
        // BLAKE3 명세상 cv_stack 최대 깊이는 ceil(log2(2^54)) = 54
        // 16 EiB 입력 한계를 넘어서면 push가 OOB panic. zero-trust 회귀 가드
        debug_assert!(
            self.cv_stack_len < 54,
            "Blake3 cv_stack 깊이 한계 초과 입력 한계 16 EiB 도달"
        );
        self.cv_stack.expose_mut()[self.cv_stack_len] = *cv.expose();
        self.cv_stack_len += 1;
        // cv Drop runs at end of body → volatile-zero of the consumed Secret
    }

    fn pop_cv(&mut self) -> Secret<[u32; 8]> {
        debug_assert!(self.cv_stack_len > 0, "Blake3 cv_stack pop underflow");
        self.cv_stack_len -= 1;
        Secret::new(self.cv_stack.expose()[self.cv_stack_len])
    }

    fn merge_cv_stack(&mut self, total_chunks: u64) {
        let post_merge_len = total_chunks.count_ones() as usize;
        while self.cv_stack_len > post_merge_len {
            let right: Secret<[u32; 8]> = self.pop_cv();
            let left: Secret<[u32; 8]> = self.pop_cv();
            let parent = parent_cv(&left, &right, self.key_words.expose(), self.flags);
            self.push_cv(parent);
            // left, right Drop here (Secret volatile-zero); push_cv consumed parent.
        }
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for Blake3 {
    #[inline]
    fn zeroize(&mut self) {
        self.key_words.zeroize();
        self.cv_stack.zeroize();
        self.chunk_state.zeroize();
        self.flags.zeroize();
        self.cv_stack_len.zeroize();
    }
}

impl Drop for Blake3 {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

//
// ChunkState
//

struct ChunkState {
    chaining_value: Secret<[u32; 8]>,
    chunk_counter: u64,
    buf: Secret<[u8; BLOCK_LEN]>,
    buf_len: usize,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            chaining_value: Secret::new(*key_words),
            chunk_counter,
            buf: Secret::new([0u8; BLOCK_LEN]),
            buf_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.buf_len
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.buf_len == BLOCK_LEN {
                let block_words = words_from_le_bytes_64(self.buf.expose());
                let new_cv: Secret<[u32; 8]> = first_8_words(compress(
                    self.chaining_value.expose(),
                    block_words.expose(),
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                ));
                self.chaining_value
                    .expose_mut()
                    .copy_from_slice(new_cv.expose());
                self.blocks_compressed += 1;
                self.buf.zeroize();
                self.buf_len = 0;
                drop(block_words);
                // new_cv Drop here → volatile-zero
            }
            let take = (BLOCK_LEN - self.buf_len).min(input.len());
            self.buf.expose_mut()[self.buf_len..self.buf_len + take]
                .copy_from_slice(&input[..take]);
            self.buf_len += take;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let mut block_words = words_from_le_bytes_64(self.buf.expose());
        // 버퍼 끝 이후 부분은 이미 0이어야 하지만 명시적으로 보장
        let used_words = self.buf_len.div_ceil(4);
        for w in block_words.expose_mut()[used_words..].iter_mut() {
            w.zeroize();
        }
        Output {
            input_chaining_value: Secret::new(*self.chaining_value.expose()),
            block_words,
            counter: self.chunk_counter,
            block_len: self.buf_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

impl Zeroize for ChunkState {
    #[inline]
    fn zeroize(&mut self) {
        self.chaining_value.zeroize();
        self.buf.zeroize();
        self.chunk_counter.zeroize();
        self.buf_len.zeroize();
        self.blocks_compressed.zeroize();
        self.flags.zeroize();
    }
}

//
// Output
//

struct Output {
    input_chaining_value: Secret<[u32; 8]>,
    block_words: Secret<[u32; 16]>,
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> Secret<[u32; 8]> {
        first_8_words(compress(
            self.input_chaining_value.expose(),
            self.block_words.expose(),
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_output_bytes(&self, out: &mut [u8]) {
        let mut counter = 0u64;
        let mut pos = 0;
        while pos < out.len() {
            let words = compress(
                self.input_chaining_value.expose(),
                self.block_words.expose(),
                counter,
                self.block_len,
                self.flags | ROOT,
            );
            for word in words.expose().iter() {
                let bytes = word.to_le_bytes();
                let take = (out.len() - pos).min(4);
                out[pos..pos + take].copy_from_slice(&bytes[..take]);
                pos += take;
                if pos >= out.len() {
                    return;
                }
            }
            counter += 1;
        }
    }
}

//
// 내부 헬퍼
//

#[inline(always)]
fn g3(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g3(state, 0, 4, 8, 12, m[0], m[1]);
    g3(state, 1, 5, 9, 13, m[2], m[3]);
    g3(state, 2, 6, 10, 14, m[4], m[5]);
    g3(state, 3, 7, 11, 15, m[6], m[7]);
    g3(state, 0, 5, 10, 15, m[8], m[9]);
    g3(state, 1, 6, 11, 12, m[10], m[11]);
    g3(state, 2, 7, 8, 13, m[12], m[13]);
    g3(state, 3, 4, 9, 14, m[14], m[15]);
}

fn compress(cv: &[u32; 8], bw: &[u32; 16], counter: u64, bl: u32, flags: u32) -> Secret<[u32; 16]> {
    let mut state = Secret::new([
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        bl,
        flags,
    ]);
    let mut m: Secret<[u32; 16]> = Secret::new(*bw);
    for _ in 0..7 {
        round(state.expose_mut(), m.expose());
        let permuted: Secret<[u32; 16]> =
            Secret::new(core::array::from_fn(|i| m.expose()[MSG_PERMUTATION[i]]));
        m.expose_mut().copy_from_slice(permuted.expose());
        // permuted Drop runs at end of iteration → volatile-zero
    }
    let st = state.expose_mut();
    for i in 0..8 {
        st[i] ^= st[i + 8];
        st[i + 8] ^= cv[i];
    }
    // m 은 함수 종료 시 Secret::Drop 으로 소거됨
    state
}

fn parent_output(
    left_cv: &Secret<[u32; 8]>,
    right_cv: &Secret<[u32; 8]>,
    key_words: &[u32; 8],
    flags: u32,
) -> Output {
    let mut block_words = Secret::new([0u32; 16]);
    {
        let bw = block_words.expose_mut();
        bw[..8].copy_from_slice(left_cv.expose());
        bw[8..].copy_from_slice(right_cv.expose());
    }
    Output {
        input_chaining_value: Secret::new(*key_words),
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: flags | PARENT,
    }
}

fn parent_cv(
    left_cv: &Secret<[u32; 8]>,
    right_cv: &Secret<[u32; 8]>,
    key_words: &[u32; 8],
    flags: u32,
) -> Secret<[u32; 8]> {
    parent_output(left_cv, right_cv, key_words, flags).chaining_value()
}

fn first_8_words(x: Secret<[u32; 16]>) -> Secret<[u32; 8]> {
    Secret::new(core::array::from_fn(|i| x.expose()[i]))
    // x 는 함수 종료 시 Secret::Drop 으로 소거됨
}

fn words_from_le_bytes_64(bytes: &[u8; BLOCK_LEN]) -> Secret<[u32; 16]> {
    Secret::new(core::array::from_fn(|i| {
        let s = i * 4;
        u32::from_le_bytes([bytes[s], bytes[s + 1], bytes[s + 2], bytes[s + 3]])
    }))
}

fn words_from_le_bytes_32(bytes: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| {
        let s = i * 4;
        u32::from_le_bytes([bytes[s], bytes[s + 1], bytes[s + 2], bytes[s + 3]])
    })
}
