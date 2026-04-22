const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

#[inline]
fn gf128_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = x;

    for i in 0..128 {
        let bit = ((y >> (127 - i)) & 1) as u8;
        let mask = (bit as u128).wrapping_neg();
        z ^= v & mask;

        let lsb = (v & 1) as u8;
        v >>= 1;
        let r_mask = (lsb as u128).wrapping_neg();
        v ^= R & r_mask;
    }
    z
}

pub struct GHash {
    h: u128,
    state: u128,
}

impl GHash {
    #[must_use]
    pub fn new(h: &[u8; 16]) -> Self {
        Self {
            h: u128::from_be_bytes(*h),
            state: 0,
        }
    }

    pub fn update(&mut self, block: &[u8; 16]) {
        let x = u128::from_be_bytes(*block);
        self.state = gf128_mul(self.state ^ x, self.h);
    }

    pub fn update_padded(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(16);
        for chunk in chunks.by_ref() {
            let block: [u8; 16] = chunk.try_into().unwrap();
            self.update(&block);
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut block = [0u8; 16];
            block[..remainder.len()].copy_from_slice(remainder);
            self.update(&block);
        }
    }

    #[must_use]
    pub fn finalize(self) -> [u8; 16] {
        self.state.to_be_bytes()
    }

    pub fn reset(&mut self) {
        self.state = 0;
    }
}

impl Drop for GHash {
    fn drop(&mut self) {
        unsafe {
            core::ptr::write_volatile(&mut self.h, 0);
            core::ptr::write_volatile(&mut self.state, 0);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghash_basic() {
        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let data: [u8; 16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        let expected: [u8; 16] = [
            0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x62, 0x88, 0x2c, 0x85, 0xb0, 0x68, 0x53, 0x53,
            0xde, 0xb7,
        ];

        let mut ghash = GHash::new(&h);
        ghash.update(&data);
        let result = ghash.finalize();
        assert_eq!(result, expected);
    }

    #[test]
    fn gf128_mul_test() {
        let a: u128 = 0x0388_dace_60b6_a392_f328_c2b9_71b2_fe78;
        let b: u128 = 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2e;
        let expected: u128 = 0x5e2e_c746_9170_6288_2c85_b068_5353_deb7;
        assert_eq!(gf128_mul(a, b), expected);
    }
}
