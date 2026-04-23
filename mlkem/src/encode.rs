use crate::params::{N, Q};
use crate::poly::{Poly, PolyVec};
use crate::reduce::freeze;

pub fn poly_tobytes(r: &mut [u8], a: &Poly) {
    for i in 0..(N / 2) {
        let t0 = freeze(a.coeffs[2 * i]) as u16;
        let t1 = freeze(a.coeffs[2 * i + 1]) as u16;
        r[3 * i] = t0 as u8;
        r[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        r[3 * i + 2] = (t1 >> 4) as u8;
    }
}

pub fn poly_frombytes(r: &mut Poly, a: &[u8]) {
    for i in 0..(N / 2) {
        r.coeffs[2 * i] = ((a[3 * i] as u16) | ((a[3 * i + 1] as u16 & 0x0F) << 8)) as i16;
        r.coeffs[2 * i + 1] = ((a[3 * i + 1] as u16 >> 4) | ((a[3 * i + 2] as u16) << 4)) as i16;
    }
}

pub fn polyvec_tobytes<const K: usize>(r: &mut [u8], a: &PolyVec<K>) {
    const POLYBYTES: usize = N * 3 / 2;
    for (i, p) in a.vec.iter().enumerate() {
        poly_tobytes(&mut r[i * POLYBYTES..(i + 1) * POLYBYTES], p);
    }
}

pub fn polyvec_frombytes<const K: usize>(r: &mut PolyVec<K>, a: &[u8]) {
    const POLYBYTES: usize = N * 3 / 2;
    for (i, p) in r.vec.iter_mut().enumerate() {
        poly_frombytes(p, &a[i * POLYBYTES..(i + 1) * POLYBYTES]);
    }
}

pub fn poly_frommsg(r: &mut Poly, msg: &[u8; 32]) {
    for (i, &byte) in msg.iter().enumerate().take(N / 8) {
        for j in 0..8 {
            let bit = (byte >> j) & 1;
            r.coeffs[8 * i + j] = -(bit as i16) & ((Q as i16 + 1) / 2);
        }
    }
}

pub fn poly_tomsg(r: &mut [u8; 32], a: &Poly) {
    for (i, byte) in r.iter_mut().enumerate().take(N / 8) {
        *byte = 0;
        for j in 0..8 {
            let t = freeze(a.coeffs[8 * i + j]) as u16;
            let d = ((((t as u32) << 1) + Q as u32 / 2) / Q as u32) & 1;
            *byte |= (d as u8) << j;
        }
    }
}
