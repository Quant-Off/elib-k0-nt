use crate::ntt::{invntt, ntt, poly_basemul};
use crate::params::{N, Q};
use crate::reduce::{barrett_reduce, csubq, freeze};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct Poly {
    pub coeffs: [i16; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Poly {
    fn drop(&mut self) {
        self.coeffs.zeroize();
    }
}

impl Poly {
    #[inline]
    pub const fn new() -> Self {
        Self { coeffs: [0i16; N] }
    }

    pub fn reduce(&mut self) {
        for c in &mut self.coeffs {
            *c = barrett_reduce(*c);
        }
    }

    #[allow(dead_code)]
    pub fn csubq(&mut self) {
        for coeff in &mut self.coeffs {
            *coeff = csubq(*coeff);
        }
    }

    pub fn add(&mut self, b: &Poly) {
        for (c, bc) in self.coeffs.iter_mut().zip(b.coeffs.iter()) {
            *c += bc;
        }
    }

    pub fn sub(&mut self, b: &Poly) {
        for (c, bc) in self.coeffs.iter_mut().zip(b.coeffs.iter()) {
            *c -= bc;
        }
    }

    pub fn ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    pub fn invntt(&mut self) {
        invntt(&mut self.coeffs);
    }

    pub fn basemul_acc(&mut self, a: &Poly, b: &Poly) {
        let mut tmp = [0i16; N];
        poly_basemul(&mut tmp, &a.coeffs, &b.coeffs);
        for (c, t) in self.coeffs.iter_mut().zip(tmp.iter()) {
            *c += t;
        }
    }

    pub fn apply_mont(&mut self) {
        const F: i16 = 1353;
        for c in &mut self.coeffs {
            *c = crate::ntt::fqmul(*c, F);
        }
    }
}

pub struct PolyVec<const K: usize> {
    pub vec: [Poly; K],
}

impl<const K: usize> Default for PolyVec<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const K: usize> Drop for PolyVec<K> {
    fn drop(&mut self) {
        for p in &mut self.vec {
            p.coeffs.zeroize();
        }
    }
}

impl<const K: usize> PolyVec<K> {
    pub const fn new() -> Self {
        Self {
            vec: [const { Poly::new() }; K],
        }
    }

    pub fn reduce(&mut self) {
        for p in &mut self.vec {
            p.reduce();
        }
    }

    #[allow(dead_code)]
    pub fn csubq(&mut self) {
        for p in &mut self.vec {
            p.csubq();
        }
    }

    pub fn add(&mut self, b: &PolyVec<K>) {
        for (p, bp) in self.vec.iter_mut().zip(b.vec.iter()) {
            p.add(bp);
        }
    }

    pub fn ntt(&mut self) {
        for p in &mut self.vec {
            p.ntt();
        }
    }

    pub fn invntt(&mut self) {
        for p in &mut self.vec {
            p.invntt();
        }
    }

    pub fn pointwise_acc(&self, b: &PolyVec<K>) -> Poly {
        let mut r = Poly::new();
        for (sp, bp) in self.vec.iter().zip(b.vec.iter()) {
            r.basemul_acc(sp, bp);
        }
        r.reduce();
        r
    }
}

pub fn compress(a: u16, d: usize) -> u16 {
    let t = (((a as u32) << d) + (Q as u32 / 2)) / (Q as u32);
    (t & ((1 << d) - 1)) as u16
}

pub fn decompress(a: u16, d: usize) -> u16 {
    (((a as u32) * (Q as u32) + (1 << (d - 1))) >> d) as u16
}

#[allow(clippy::needless_range_loop)]
pub fn poly_compress(r: &mut [u8], a: &Poly, d: usize) {
    let mut t = [0u16; 8];
    match d {
        4 => {
            for i in 0..(N / 2) {
                for j in 0..2 {
                    let c = freeze(a.coeffs[2 * i + j]) as u16;
                    t[j] = compress(c, 4);
                }
                r[i] = (t[0] | (t[1] << 4)) as u8;
            }
        }
        5 => {
            for i in 0..(N / 8) {
                for j in 0..8 {
                    let c = freeze(a.coeffs[8 * i + j]) as u16;
                    t[j] = compress(c, 5);
                }
                r[5 * i] = (t[0] | (t[1] << 5)) as u8;
                r[5 * i + 1] = ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7)) as u8;
                r[5 * i + 2] = ((t[3] >> 1) | (t[4] << 4)) as u8;
                r[5 * i + 3] = ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6)) as u8;
                r[5 * i + 4] = ((t[6] >> 2) | (t[7] << 3)) as u8;
            }
        }
        _ => panic!("unsupported d"),
    }
}

#[allow(clippy::needless_range_loop)]
pub fn poly_decompress(r: &mut Poly, a: &[u8], d: usize) {
    match d {
        4 => {
            for (i, &byte) in a.iter().enumerate().take(N / 2) {
                r.coeffs[2 * i] = decompress((byte & 0x0F) as u16, 4) as i16;
                r.coeffs[2 * i + 1] = decompress((byte >> 4) as u16, 4) as i16;
            }
        }
        5 => {
            let mut t = [0u8; 8];
            for i in 0..(N / 8) {
                t[0] = a[5 * i];
                t[1] = (a[5 * i] >> 5) | (a[5 * i + 1] << 3);
                t[2] = a[5 * i + 1] >> 2;
                t[3] = (a[5 * i + 1] >> 7) | (a[5 * i + 2] << 1);
                t[4] = (a[5 * i + 2] >> 4) | (a[5 * i + 3] << 4);
                t[5] = a[5 * i + 3] >> 1;
                t[6] = (a[5 * i + 3] >> 6) | (a[5 * i + 4] << 2);
                t[7] = a[5 * i + 4] >> 3;
                for (j, &tv) in t.iter().enumerate() {
                    r.coeffs[8 * i + j] = decompress((tv & 0x1F) as u16, 5) as i16;
                }
            }
        }
        _ => panic!("unsupported d"),
    }
}

#[allow(clippy::needless_range_loop)]
pub fn polyvec_compress<const K: usize>(r: &mut [u8], a: &PolyVec<K>, du: usize) {
    let mut t = [0u16; 4];
    match du {
        10 => {
            let mut idx = 0;
            for p in a.vec.iter() {
                for j in 0..(N / 4) {
                    for (k, tv) in t.iter_mut().enumerate() {
                        let c = freeze(p.coeffs[4 * j + k]) as u16;
                        *tv = compress(c, 10);
                    }
                    r[idx] = t[0] as u8;
                    r[idx + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                    r[idx + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                    r[idx + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                    r[idx + 4] = (t[3] >> 2) as u8;
                    idx += 5;
                }
            }
        }
        11 => {
            let mut idx = 0;
            for p in a.vec.iter() {
                for j in 0..(N / 8) {
                    let mut tt = [0u16; 8];
                    for (k, tv) in tt.iter_mut().enumerate() {
                        let c = freeze(p.coeffs[8 * j + k]) as u16;
                        *tv = compress(c, 11);
                    }
                    r[idx] = tt[0] as u8;
                    r[idx + 1] = ((tt[0] >> 8) | (tt[1] << 3)) as u8;
                    r[idx + 2] = ((tt[1] >> 5) | (tt[2] << 6)) as u8;
                    r[idx + 3] = (tt[2] >> 2) as u8;
                    r[idx + 4] = ((tt[2] >> 10) | (tt[3] << 1)) as u8;
                    r[idx + 5] = ((tt[3] >> 7) | (tt[4] << 4)) as u8;
                    r[idx + 6] = ((tt[4] >> 4) | (tt[5] << 7)) as u8;
                    r[idx + 7] = (tt[5] >> 1) as u8;
                    r[idx + 8] = ((tt[5] >> 9) | (tt[6] << 2)) as u8;
                    r[idx + 9] = ((tt[6] >> 6) | (tt[7] << 5)) as u8;
                    r[idx + 10] = (tt[7] >> 3) as u8;
                    idx += 11;
                }
            }
        }
        _ => panic!("unsupported du"),
    }
}

#[allow(clippy::needless_range_loop)]
pub fn polyvec_decompress<const K: usize>(r: &mut PolyVec<K>, a: &[u8], du: usize) {
    match du {
        10 => {
            let mut idx = 0;
            for p in r.vec.iter_mut() {
                for j in 0..(N / 4) {
                    let t0 = (a[idx] as u16) | ((a[idx + 1] as u16) << 8);
                    let t1 = ((a[idx + 1] as u16) >> 2) | ((a[idx + 2] as u16) << 6);
                    let t2 = ((a[idx + 2] as u16) >> 4) | ((a[idx + 3] as u16) << 4);
                    let t3 = ((a[idx + 3] as u16) >> 6) | ((a[idx + 4] as u16) << 2);
                    p.coeffs[4 * j] = decompress(t0 & 0x3FF, 10) as i16;
                    p.coeffs[4 * j + 1] = decompress(t1 & 0x3FF, 10) as i16;
                    p.coeffs[4 * j + 2] = decompress(t2 & 0x3FF, 10) as i16;
                    p.coeffs[4 * j + 3] = decompress(t3 & 0x3FF, 10) as i16;
                    idx += 5;
                }
            }
        }
        11 => {
            let mut idx = 0;
            for p in r.vec.iter_mut() {
                for j in 0..(N / 8) {
                    let b = &a[idx..idx + 11];
                    let t0 = (b[0] as u16) | ((b[1] as u16) << 8);
                    let t1 = ((b[1] as u16) >> 3) | ((b[2] as u16) << 5);
                    let t2 = ((b[2] as u16) >> 6) | ((b[3] as u16) << 2) | ((b[4] as u16) << 10);
                    let t3 = ((b[4] as u16) >> 1) | ((b[5] as u16) << 7);
                    let t4 = ((b[5] as u16) >> 4) | ((b[6] as u16) << 4);
                    let t5 = ((b[6] as u16) >> 7) | ((b[7] as u16) << 1) | ((b[8] as u16) << 9);
                    let t6 = ((b[8] as u16) >> 2) | ((b[9] as u16) << 6);
                    let t7 = ((b[9] as u16) >> 5) | ((b[10] as u16) << 3);
                    p.coeffs[8 * j] = decompress(t0 & 0x7FF, 11) as i16;
                    p.coeffs[8 * j + 1] = decompress(t1 & 0x7FF, 11) as i16;
                    p.coeffs[8 * j + 2] = decompress(t2 & 0x7FF, 11) as i16;
                    p.coeffs[8 * j + 3] = decompress(t3 & 0x7FF, 11) as i16;
                    p.coeffs[8 * j + 4] = decompress(t4 & 0x7FF, 11) as i16;
                    p.coeffs[8 * j + 5] = decompress(t5 & 0x7FF, 11) as i16;
                    p.coeffs[8 * j + 6] = decompress(t6 & 0x7FF, 11) as i16;
                    p.coeffs[8 * j + 7] = decompress(t7 & 0x7FF, 11) as i16;
                    idx += 11;
                }
            }
        }
        _ => panic!("unsupported du"),
    }
}
