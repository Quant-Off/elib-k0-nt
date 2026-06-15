use crate::error::Error;
use crate::field::{Fq, fq_to_signed};
use crate::keys::{PrivateKey, PublicKey, pk_decode, sk_decode};
use crate::ntt::N;
use crate::pack::{
    bitlen, hint_bit_pack, hint_bit_unpack, poly_simple_bit_pack_t1, polyvec_bit_pack_z,
    polyvec_bit_unpack_z, polyvec_simple_bit_pack_w1,
};
use crate::poly::{Poly, PolyVec};
use crate::sample::{expand_a, expand_mask, sample_in_ball};
use crate::{D, Q};
use sha3::{SHAKE256, XOF};
use zeroize::{Secret, Zeroize};

fn inf_norm_vec<const DIM: usize>(v: &PolyVec<DIM>) -> i32 {
    let mut max = 0i32;
    for i in 0..DIM {
        for j in 0..N {
            let s = fq_to_signed(v.vec[i].coeffs[j].0).abs();
            if s > max {
                max = s;
            }
        }
    }
    max
}

fn polyvec_neg<const DIM: usize>(v: &PolyVec<DIM>) -> PolyVec<DIM> {
    let mut r = PolyVec::<DIM>::new_zero();
    for i in 0..DIM {
        for j in 0..N {
            let c = v.vec[i].coeffs[j].0;
            r.vec[i].coeffs[j] = Fq::new(if c == 0 { 0 } else { Q - c });
        }
    }
    r
}

fn poly_mul_polyvec<const DIM: usize>(c: &Poly, v: &PolyVec<DIM>) -> PolyVec<DIM> {
    let mut r = PolyVec::<DIM>::new_zero();
    for i in 0..DIM {
        r.vec[i] = c.pointwise_montgomery(&v.vec[i]);
    }
    r
}

fn polyvec_scale_2d<const K: usize>(t1: &PolyVec<K>) -> PolyVec<K> {
    let mut r = PolyVec::<K>::new_zero();
    for i in 0..K {
        for j in 0..N {
            let v = t1.vec[i].coeffs[j].0 as i64;
            r.vec[i].coeffs[j] = Fq::new(((v << D) % Q as i64) as i32);
        }
    }
    r
}

fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    let alpha = 2 * gamma2;
    let r_plus = r % Q;

    let mut r0 = r_plus % alpha;
    if r0 > gamma2 {
        r0 -= alpha;
    }

    if r_plus - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r_plus - r0) / alpha, r0)
    }
}

fn high_bits_vec<const DIM: usize>(w: &PolyVec<DIM>, gamma2: i32) -> PolyVec<DIM> {
    let mut r = PolyVec::<DIM>::new_zero();
    for i in 0..DIM {
        for j in 0..N {
            let (r1, _) = decompose(w.vec[i].coeffs[j].0, gamma2);
            r.vec[i].coeffs[j] = Fq::new(r1);
        }
    }
    r
}

fn low_bits_vec<const DIM: usize>(w: &PolyVec<DIM>, gamma2: i32) -> PolyVec<DIM> {
    let mut r = PolyVec::<DIM>::new_zero();
    for i in 0..DIM {
        for j in 0..N {
            let (_, r0) = decompose(w.vec[i].coeffs[j].0, gamma2);
            let fq = if r0 < 0 { r0 + Q } else { r0 };
            r.vec[i].coeffs[j] = Fq::new(fq);
        }
    }
    r
}

#[inline(always)]
fn make_hint_coeff(z_fq: i32, r_fq: i32, gamma2: i32) -> i32 {
    let (r1, _) = decompose(r_fq, gamma2);
    let rz = ((r_fq as i64 + z_fq as i64).rem_euclid(Q as i64)) as i32;
    let (v1, _) = decompose(rz, gamma2);
    if r1 != v1 { 1 } else { 0 }
}

fn make_hint_vec<const K: usize>(
    z: &PolyVec<K>,
    r: &PolyVec<K>,
    gamma2: i32,
) -> (PolyVec<K>, usize) {
    let mut h = PolyVec::<K>::new_zero();
    let mut count = 0usize;
    for i in 0..K {
        for j in 0..N {
            let bit = make_hint_coeff(z.vec[i].coeffs[j].0, r.vec[i].coeffs[j].0, gamma2);
            h.vec[i].coeffs[j] = Fq::new(bit);
            count += bit as usize;
        }
    }
    (h, count)
}

#[inline(always)]
fn use_hint_coeff(h: i32, r_fq: i32, gamma2: i32) -> i32 {
    let m = (Q - 1) / (2 * gamma2);
    let (r1, r0) = decompose(r_fq, gamma2);
    if h == 1 {
        if r0 > 0 {
            (r1 + 1).rem_euclid(m)
        } else {
            (r1 - 1).rem_euclid(m)
        }
    } else {
        r1
    }
}

fn use_hint_vec<const K: usize>(h: &PolyVec<K>, r: &PolyVec<K>, gamma2: i32) -> PolyVec<K> {
    let mut w1 = PolyVec::<K>::new_zero();
    for i in 0..K {
        for j in 0..N {
            let bit = h.vec[i].coeffs[j].0;
            let v = use_hint_coeff(bit, r.vec[i].coeffs[j].0, gamma2);
            w1.vec[i].coeffs[j] = Fq::new(v);
        }
    }
    w1
}

fn w1_encode<const K: usize>(w1: &PolyVec<K>, gamma2: i32, out: &mut [u8]) {
    polyvec_simple_bit_pack_w1::<K>(w1, gamma2, out);
}

fn w1_bytes_len<const K: usize>(gamma2: i32) -> usize {
    let max_coeff = (Q - 1) / (2 * gamma2) - 1;
    let bw = bitlen(max_coeff as u32);
    K * 32 * bw
}

fn sig_encode<const K: usize, const L: usize, const LAMBDA: usize, const SIG_LEN: usize>(
    c_tilde: &[u8],
    z: &PolyVec<L>,
    h: &PolyVec<K>,
    gamma1: i32,
    omega: usize,
) -> [u8; SIG_LEN] {
    let c_tilde_len = LAMBDA / 4;
    let z_bw = bitlen((2 * gamma1 - 1) as u32);
    let z_bpp = 32 * z_bw;
    let z_total = L * z_bpp;
    let h_total = omega + K;

    let mut sig = [0u8; SIG_LEN];
    let mut off = 0;

    sig[off..off + c_tilde_len].copy_from_slice(c_tilde);
    off += c_tilde_len;

    polyvec_bit_pack_z::<L>(z, gamma1, &mut sig[off..off + z_total]);
    off += z_total;

    hint_bit_pack::<K>(h, omega, &mut sig[off..off + h_total]);

    sig
}

fn sig_decode<const K: usize, const L: usize, const LAMBDA: usize, const SIG_LEN: usize>(
    sig: &[u8; SIG_LEN],
    gamma1: i32,
    omega: usize,
) -> Option<([u8; 64], PolyVec<L>, PolyVec<K>)> {
    let c_tilde_len = LAMBDA / 4;
    let z_bw = bitlen((2 * gamma1 - 1) as u32);
    let z_bpp = 32 * z_bw;
    let z_total = L * z_bpp;
    let h_total = omega + K;

    if SIG_LEN != c_tilde_len + z_total + h_total {
        return None;
    }

    let mut off = 0;

    let mut c_tilde = [0u8; 64];
    c_tilde[..c_tilde_len].copy_from_slice(&sig[off..off + c_tilde_len]);
    off += c_tilde_len;

    let z: PolyVec<L> = polyvec_bit_unpack_z(&sig[off..off + z_total], gamma1);
    off += z_total;

    let h: PolyVec<K> = hint_bit_unpack(&sig[off..off + h_total], omega)?;

    Some((c_tilde, z, h))
}

pub fn sign_internal<
    const K: usize,
    const L: usize,
    const ETA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const BETA: i32,
    const OMEGA: usize,
    const LAMBDA: usize,
    const TAU: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
>(
    sk_bytes: &[u8; SK_LEN],
    m_prime: &[u8],
    rnd: &[u8; 32],
) -> Result<[u8; SIG_LEN], Error> {
    let sk: PrivateKey<K, L> = sk_decode::<K, L, ETA, SK_LEN>(sk_bytes);

    let mut s1_hat = sk.s1;
    s1_hat.ntt();
    let mut s2_hat = sk.s2;
    s2_hat.ntt();
    let mut t0_hat = sk.t0;
    t0_hat.ntt();

    let a_hat = expand_a::<K, L>(&sk.rho)?;

    let mut shake_mu = SHAKE256::new();
    shake_mu.update(&sk.tr);
    shake_mu.update(m_prime);
    let mut mu = Secret::new([0u8; 64]);
    shake_mu.finalize_into(mu.expose_mut());

    let mut shake_rho_pp = SHAKE256::new();
    shake_rho_pp.update(sk.k_seed.expose());
    shake_rho_pp.update(rnd);
    shake_rho_pp.update(mu.expose());
    let mut rho_pp = Secret::new([0u8; 64]);
    shake_rho_pp.finalize_into(rho_pp.expose_mut());

    let mut kappa: u16 = 0;
    const MAX_ITER: usize = 1000;

    let c_tilde_len = LAMBDA / 4;
    let w1_len = w1_bytes_len::<K>(GAMMA2);

    for _ in 0..MAX_ITER {
        let mut y = expand_mask::<L>(rho_pp.expose(), kappa, GAMMA1)?;

        let mut y_hat = y;
        y_hat.ntt();
        let mut w = a_hat.multiply_vector(&y_hat);
        w.intt();

        let w1 = high_bits_vec::<K>(&w, GAMMA2);

        let mut w1_bytes = [0u8; 1536];
        w1_encode::<K>(&w1, GAMMA2, &mut w1_bytes[..w1_len]);

        let mut shake_c = SHAKE256::new();
        shake_c.update(mu.expose());
        shake_c.update(&w1_bytes[..w1_len]);
        let mut c_tilde_buf = [0u8; 64];
        shake_c.finalize_into(&mut c_tilde_buf[..c_tilde_len]);

        let mut c_hat_poly = sample_in_ball(&c_tilde_buf[..c_tilde_len], TAU)?;
        c_hat_poly.ntt();
        let c_hat = &c_hat_poly;

        let mut cs1 = poly_mul_polyvec::<L>(c_hat, &s1_hat);
        cs1.intt();
        let mut z = y.add(&cs1);

        let mut cs2 = poly_mul_polyvec::<K>(c_hat, &s2_hat);
        cs2.intt();
        let mut w_minus_cs2 = w.sub(&cs2);
        let mut r0 = low_bits_vec::<K>(&w_minus_cs2, GAMMA2);

        if inf_norm_vec::<L>(&z) >= GAMMA1 - BETA || inf_norm_vec::<K>(&r0) >= GAMMA2 - BETA {
            kappa = kappa.wrapping_add(L as u16);
            y.zeroize();
            y_hat.zeroize();
            w.zeroize();
            cs1.zeroize();
            z.zeroize();
            cs2.zeroize();
            w_minus_cs2.zeroize();
            r0.zeroize();
            continue;
        }

        let mut ct0 = poly_mul_polyvec::<K>(c_hat, &t0_hat);
        ct0.intt();

        let mut neg_ct0 = polyvec_neg::<K>(&ct0);
        let mut w_minus_cs2_plus_ct0 = w_minus_cs2.add(&ct0);
        let (h, h_count) = make_hint_vec::<K>(&neg_ct0, &w_minus_cs2_plus_ct0, GAMMA2);

        if inf_norm_vec::<K>(&ct0) >= GAMMA2 || h_count > OMEGA {
            kappa = kappa.wrapping_add(L as u16);
            y.zeroize();
            y_hat.zeroize();
            w.zeroize();
            cs1.zeroize();
            z.zeroize();
            cs2.zeroize();
            w_minus_cs2.zeroize();
            r0.zeroize();
            ct0.zeroize();
            neg_ct0.zeroize();
            w_minus_cs2_plus_ct0.zeroize();
            continue;
        }

        let sig =
            sig_encode::<K, L, LAMBDA, SIG_LEN>(&c_tilde_buf[..c_tilde_len], &z, &h, GAMMA1, OMEGA);

        y.zeroize();
        y_hat.zeroize();
        w.zeroize();
        cs1.zeroize();
        z.zeroize();
        cs2.zeroize();
        w_minus_cs2.zeroize();
        r0.zeroize();
        ct0.zeroize();
        neg_ct0.zeroize();
        w_minus_cs2_plus_ct0.zeroize();
        s1_hat.zeroize();
        s2_hat.zeroize();
        t0_hat.zeroize();

        return Ok(sig);
    }

    s1_hat.zeroize();
    s2_hat.zeroize();
    t0_hat.zeroize();

    Err(Error::SigningFailed)
}

pub fn verify_internal<
    const K: usize,
    const L: usize,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const BETA: i32,
    const OMEGA: usize,
    const LAMBDA: usize,
    const TAU: usize,
    const PK_LEN: usize,
    const SIG_LEN: usize,
>(
    pk_bytes: &[u8; PK_LEN],
    m_prime: &[u8],
    sig: &[u8; SIG_LEN],
) -> Result<bool, Error> {
    let pk: PublicKey<K> = pk_decode::<K, PK_LEN>(pk_bytes);

    let (c_tilde, z, h) = match sig_decode::<K, L, LAMBDA, SIG_LEN>(sig, GAMMA1, OMEGA) {
        Some(v) => v,
        None => return Ok(false),
    };

    let c_tilde_len = LAMBDA / 4;

    let a_hat = expand_a::<K, L>(&pk.rho)?;

    let mut shake_tr = SHAKE256::new();
    shake_tr.update(&pk.rho);
    for i in 0..K {
        let mut t1_poly_bytes = [0u8; 320];
        poly_simple_bit_pack_t1(&pk.t1.vec[i], &mut t1_poly_bytes);
        shake_tr.update(&t1_poly_bytes);
    }
    let mut tr = [0u8; 64];
    shake_tr.finalize_into(&mut tr);

    let mut shake_mu = SHAKE256::new();
    shake_mu.update(&tr);
    shake_mu.update(m_prime);
    let mut mu = [0u8; 64];
    shake_mu.finalize_into(&mut mu);

    let mut c_hat_poly = sample_in_ball(&c_tilde[..c_tilde_len], TAU)?;
    c_hat_poly.ntt();
    let c_hat = &c_hat_poly;

    let mut z_hat = z;
    z_hat.ntt();
    let az_hat = a_hat.multiply_vector(&z_hat);

    let t1_scaled = polyvec_scale_2d::<K>(&pk.t1);
    let mut t1_hat = t1_scaled;
    t1_hat.ntt();
    let ct1_hat = poly_mul_polyvec::<K>(c_hat, &t1_hat);

    let mut w_approx_hat = az_hat.sub(&ct1_hat);
    w_approx_hat.intt();

    let w1_prime = use_hint_vec::<K>(&h, &w_approx_hat, GAMMA2);

    if inf_norm_vec::<L>(&z) >= GAMMA1 - BETA {
        return Ok(false);
    }

    let w1_len = w1_bytes_len::<K>(GAMMA2);
    let mut w1_bytes = [0u8; 1536];
    w1_encode::<K>(&w1_prime, GAMMA2, &mut w1_bytes[..w1_len]);

    let mut shake_c = SHAKE256::new();
    shake_c.update(&mu);
    shake_c.update(&w1_bytes[..w1_len]);
    let mut c_tilde_prime = [0u8; 64];
    shake_c.finalize_into(&mut c_tilde_prime[..c_tilde_len]);

    Ok(ct_eq_bytes(
        &c_tilde[..c_tilde_len],
        &c_tilde_prime[..c_tilde_len],
    ))
}
