use crate::sbox::sub_word;

const NK: usize = 8;
const NB: usize = 4;
const NR: usize = 14;

const RCON: [u32; 7] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
];

#[inline]
fn rot_word(w: u32) -> u32 {
    w.rotate_left(8)
}

pub fn expand_key(key: &[u8; 32]) -> [u32; NB * (NR + 1)] {
    let mut w = [0u32; NB * (NR + 1)];

    for i in 0..NK {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    for i in NK..(NB * (NR + 1)) {
        let mut temp = w[i - 1];
        if i % NK == 0 {
            temp = sub_word(rot_word(temp)) ^ RCON[i / NK - 1];
        } else if i % NK == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - NK] ^ temp;
    }

    w
}

pub fn zeroize_round_keys(keys: &mut [u32; NB * (NR + 1)]) {
    for k in keys.iter_mut() {
        unsafe {
            core::ptr::write_volatile(k, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
