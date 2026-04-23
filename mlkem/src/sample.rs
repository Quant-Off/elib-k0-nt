use crate::params::{N, Q};
use crate::poly::{Poly, PolyVec};
use sha3::{SHAKE128, SHAKE256, XOF};

pub fn rej_uniform(r: &mut [i16], ctr_start: usize, buf: &[u8]) -> usize {
    let mut ctr = ctr_start;
    let mut pos = 0;
    let buflen = buf.len();
    let len = r.len();

    while ctr < len && pos + 3 <= buflen {
        let d1 = ((buf[pos] as u16) | ((buf[pos + 1] as u16) << 8)) & 0x0FFF;
        let d2 = ((buf[pos + 1] as u16 >> 4) | ((buf[pos + 2] as u16) << 4)) & 0x0FFF;
        pos += 3;

        if d1 < Q {
            r[ctr] = d1 as i16;
            ctr += 1;
        }
        if ctr < len && d2 < Q {
            r[ctr] = d2 as i16;
            ctr += 1;
        }
    }
    ctr
}

pub fn poly_cbd(r: &mut Poly, buf: &[u8], eta: usize) {
    match eta {
        2 => poly_cbd2(r, buf),
        3 => poly_cbd3(r, buf),
        _ => panic!("unsupported eta"),
    }
}

fn poly_cbd2(r: &mut Poly, buf: &[u8]) {
    for i in 0..(N / 8) {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        let mut d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            r.coeffs[8 * i + j] = a - b;
        }
    }
}

fn poly_cbd3(r: &mut Poly, buf: &[u8]) {
    for i in 0..(N / 4) {
        let t =
            (buf[3 * i] as u32) | ((buf[3 * i + 1] as u32) << 8) | ((buf[3 * i + 2] as u32) << 16);
        let mut d = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for j in 0..4 {
            let a = ((d >> (6 * j)) & 0x7) as i16;
            let b = ((d >> (6 * j + 3)) & 0x7) as i16;
            r.coeffs[4 * i + j] = a - b;
        }
    }
}

pub fn sample_ntt(seed: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut r = Poly::new();

    let mut xof = SHAKE128::new();
    xof.update(seed);
    xof.update(&[i, j]);
    let mut buf = [0u8; 504];
    xof.finalize_into(&mut buf);

    let mut ctr = rej_uniform(&mut r.coeffs, 0, &buf);

    if ctr < N {
        let mut xof2 = SHAKE128::new();
        xof2.update(seed);
        xof2.update(&[i, j]);
        let mut buf2 = [0u8; 672];
        xof2.finalize_into(&mut buf2);
        ctr = rej_uniform(&mut r.coeffs, ctr, &buf2[504..]);
    }

    if ctr < N {
        let mut xof3 = SHAKE128::new();
        xof3.update(seed);
        xof3.update(&[i, j]);
        let mut buf3 = [0u8; 840];
        xof3.finalize_into(&mut buf3);
        rej_uniform(&mut r.coeffs, ctr, &buf3[672..]);
    }

    r
}

pub fn sample_poly_cbd(seed: &[u8; 32], nonce: u8, eta: usize) -> Poly {
    let mut r = Poly::new();
    let buflen = eta * N / 4;
    let mut buf = [0u8; 192];

    let mut prf = SHAKE256::new();
    prf.update(seed);
    prf.update(&[nonce]);
    prf.finalize_into(&mut buf[..buflen]);

    poly_cbd(&mut r, &buf[..buflen], eta);
    r
}

pub fn gen_matrix<const K: usize>(seed: &[u8; 32], transposed: bool) -> [[Poly; K]; K] {
    core::array::from_fn(|i| {
        core::array::from_fn(|j| {
            if transposed {
                sample_ntt(seed, j as u8, i as u8)
            } else {
                sample_ntt(seed, i as u8, j as u8)
            }
        })
    })
}

pub fn sample_noise<const K: usize>(seed: &[u8; 32], nonce: u8, eta: usize) -> PolyVec<K> {
    let mut r = PolyVec::new();
    for (i, p) in r.vec.iter_mut().enumerate() {
        *p = sample_poly_cbd(seed, nonce + i as u8, eta);
    }
    r
}
