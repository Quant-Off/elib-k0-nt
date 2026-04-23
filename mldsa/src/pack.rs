use crate::Q;
use crate::field::{Fq, signed_to_fq};
use crate::ntt::N;
use crate::poly::{Poly, PolyVec};
use constant_time::{Choice, CtSelOps};

#[inline(always)]
pub fn bitlen(n: u32) -> usize {
    (u32::BITS - n.leading_zeros()) as usize
}

#[inline(always)]
fn fq_to_signed_ct(fq_val: i32, upper_bound: i32) -> i32 {
    let probe = fq_val.wrapping_sub(upper_bound).wrapping_sub(1);
    let is_nonneg = Choice::from_u8(((probe >> 31) & 1) as u8);
    let as_negative = fq_val.wrapping_sub(Q);
    i32::select(&as_negative, &fq_val, is_nonneg)
}

pub fn simple_bit_pack(w: &Poly, b: usize, out: &mut [u8]) {
    let mask: u64 = if b >= 64 { u64::MAX } else { (1u64 << b) - 1 };
    let mut buf: u64 = 0;
    let mut bits: usize = 0;
    let mut idx: usize = 0;

    for coeff in &w.coeffs {
        buf |= (coeff.0 as u64 & mask) << bits;
        bits += b;
        while bits >= 8 {
            out[idx] = buf as u8;
            idx += 1;
            buf >>= 8;
            bits -= 8;
        }
    }
}

pub fn simple_bit_unpack(v: &[u8], b: usize) -> Poly {
    let mask: u64 = if b >= 64 { u64::MAX } else { (1u64 << b) - 1 };
    let mut poly = Poly::new_zero();
    let mut buf: u64 = 0;
    let mut bits: usize = 0;
    let mut idx: usize = 0;

    for i in 0..N {
        while bits < b {
            buf |= (v[idx] as u64) << bits;
            idx += 1;
            bits += 8;
        }
        poly.coeffs[i] = Fq::new((buf & mask) as i32);
        buf >>= b;
        bits -= b;
    }
    poly
}

pub fn bit_pack(w: &Poly, a: i32, b: i32, out: &mut [u8]) {
    let bw = bitlen((a + b) as u32);
    let mask: u64 = if bw >= 64 { u64::MAX } else { (1u64 << bw) - 1 };
    let mut buf: u64 = 0;
    let mut bits: usize = 0;
    let mut idx: usize = 0;

    for coeff in &w.coeffs {
        let signed = fq_to_signed_ct(coeff.0, b);
        let encoded = (a as i64 + signed as i64) as u64;
        buf |= (encoded & mask) << bits;
        bits += bw;
        while bits >= 8 {
            out[idx] = buf as u8;
            idx += 1;
            buf >>= 8;
            bits -= 8;
        }
    }
}

pub fn bit_unpack(v: &[u8], a: i32, b: i32) -> Poly {
    let bw = bitlen((a + b) as u32);
    let mask: u64 = if bw >= 64 { u64::MAX } else { (1u64 << bw) - 1 };
    let mut poly = Poly::new_zero();
    let mut buf: u64 = 0;
    let mut bits: usize = 0;
    let mut idx: usize = 0;

    for i in 0..N {
        while bits < bw {
            buf |= (v[idx] as u64) << bits;
            idx += 1;
            bits += 8;
        }
        let encoded = (buf & mask) as i32;
        buf >>= bw;
        bits -= bw;

        let signed = encoded - a;
        poly.coeffs[i] = Fq::new(signed_to_fq(signed));
    }
    poly
}

pub fn hint_bit_pack<const K: usize>(h: &PolyVec<K>, omega: usize, out: &mut [u8]) {
    for b in out.iter_mut() {
        *b = 0;
    }

    let mut index: usize = 0;
    for i in 0..K {
        for j in 0..N {
            if h.vec[i].coeffs[j].0 != 0 {
                out[index] = j as u8;
                index += 1;
            }
        }
        out[omega + i] = index as u8;
    }
}

pub fn hint_bit_unpack<const K: usize>(y: &[u8], omega: usize) -> Option<PolyVec<K>> {
    if y.len() != omega + K {
        return None;
    }

    let mut h = PolyVec::<K>::new_zero();
    let mut index: usize = 0;

    for i in 0..K {
        let limit = y[omega + i] as usize;
        if limit < index || limit > omega {
            return None;
        }

        let first = index;
        while index < limit {
            if index > first && y[index] <= y[index - 1] {
                return None;
            }
            h.vec[i].coeffs[y[index] as usize] = Fq::new(1);
            index += 1;
        }
    }

    for &b in &y[index..omega] {
        if b != 0 {
            return None;
        }
    }

    Some(h)
}

pub fn polyvec_bit_pack_eta<const D: usize>(vec: &PolyVec<D>, eta: i32, out: &mut [u8]) {
    let bw = bitlen((2 * eta) as u32);
    let bpp = 32 * bw;
    for i in 0..D {
        bit_pack(&vec.vec[i], eta, eta, &mut out[i * bpp..(i + 1) * bpp]);
    }
}

pub fn polyvec_bit_unpack_eta<const D: usize>(v: &[u8], eta: i32) -> PolyVec<D> {
    let bw = bitlen((2 * eta) as u32);
    let bpp = 32 * bw;
    let mut vec = PolyVec::<D>::new_zero();
    for i in 0..D {
        vec.vec[i] = bit_unpack(&v[i * bpp..(i + 1) * bpp], eta, eta);
    }
    vec
}

pub fn polyvec_bit_pack_t0<const D: usize>(vec: &PolyVec<D>, out: &mut [u8]) {
    const A: i32 = (1 << 12) - 1;
    const B: i32 = 1 << 12;
    const BPP: usize = 32 * 13;
    for i in 0..D {
        bit_pack(&vec.vec[i], A, B, &mut out[i * BPP..(i + 1) * BPP]);
    }
}

pub fn polyvec_bit_unpack_t0<const D: usize>(v: &[u8]) -> PolyVec<D> {
    const A: i32 = (1 << 12) - 1;
    const B: i32 = 1 << 12;
    const BPP: usize = 32 * 13;
    let mut vec = PolyVec::<D>::new_zero();
    for i in 0..D {
        vec.vec[i] = bit_unpack(&v[i * BPP..(i + 1) * BPP], A, B);
    }
    vec
}

pub fn polyvec_bit_pack_z<const D: usize>(vec: &PolyVec<D>, gamma1: i32, out: &mut [u8]) {
    let a = gamma1 - 1;
    let bw = bitlen((a + gamma1) as u32);
    let bpp = 32 * bw;
    for i in 0..D {
        bit_pack(&vec.vec[i], a, gamma1, &mut out[i * bpp..(i + 1) * bpp]);
    }
}

pub fn polyvec_bit_unpack_z<const D: usize>(v: &[u8], gamma1: i32) -> PolyVec<D> {
    let a = gamma1 - 1;
    let bw = bitlen((a + gamma1) as u32);
    let bpp = 32 * bw;
    let mut vec = PolyVec::<D>::new_zero();
    for i in 0..D {
        vec.vec[i] = bit_unpack(&v[i * bpp..(i + 1) * bpp], a, gamma1);
    }
    vec
}

pub fn polyvec_simple_bit_pack_w1<const D: usize>(vec: &PolyVec<D>, gamma2: i32, out: &mut [u8]) {
    let max_coeff = (Q - 1) / (2 * gamma2) - 1;
    let bw = bitlen(max_coeff as u32);
    let bpp = 32 * bw;
    for i in 0..D {
        simple_bit_pack(&vec.vec[i], bw, &mut out[i * bpp..(i + 1) * bpp]);
    }
}

pub fn poly_simple_bit_pack_t1(w: &Poly, out: &mut [u8]) {
    simple_bit_pack(w, 10, out);
}

pub fn poly_simple_bit_unpack_t1(v: &[u8]) -> Poly {
    simple_bit_unpack(v, 10)
}
