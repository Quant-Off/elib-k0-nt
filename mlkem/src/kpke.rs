#![allow(clippy::too_many_arguments)]

use crate::encode::{poly_frommsg, poly_tomsg, polyvec_frombytes, polyvec_tobytes};
use crate::params::{N, SYMBYTES};
use crate::poly::{
    Poly, PolyVec, poly_compress, poly_decompress, polyvec_compress, polyvec_decompress,
};
use crate::sample::{gen_matrix, sample_noise, sample_poly_cbd};
use sha3::{SHA3, SHA3_512};
use zeroize::Zeroize;

const POLYBYTES: usize = N * 3 / 2;

pub fn keypair<const K: usize>(ek: &mut [u8], dk: &mut [u8], d: &[u8; 32], eta1: usize) {
    let mut hash_out = [0u8; 64];
    {
        let mut hasher = SHA3_512::new();
        hasher.update(d);
        hasher.update(&[K as u8]);
        let digest = hasher.finalize();
        hash_out.copy_from_slice(digest.as_bytes());
    }

    let rho: [u8; 32] = hash_out[..32].try_into().unwrap();
    let sigma: [u8; 32] = hash_out[32..64].try_into().unwrap();

    let a_hat = gen_matrix::<K>(&rho, false);

    let mut s: PolyVec<K> = sample_noise(&sigma, 0, eta1);
    let mut e: PolyVec<K> = sample_noise(&sigma, K as u8, eta1);

    s.ntt();
    e.ntt();

    let mut t_hat: PolyVec<K> = PolyVec::new();
    for (i, (t, ep)) in t_hat.vec.iter_mut().zip(e.vec.iter()).enumerate() {
        for (a_row, sp) in a_hat[i].iter().zip(s.vec.iter()) {
            t.basemul_acc(a_row, sp);
        }
        t.apply_mont();
        t.add(ep);
        t.reduce();
    }

    let polyvec_bytes = K * POLYBYTES;
    polyvec_tobytes(&mut ek[..polyvec_bytes], &t_hat);
    ek[polyvec_bytes..polyvec_bytes + SYMBYTES].copy_from_slice(&rho);

    polyvec_tobytes(&mut dk[..polyvec_bytes], &s);

    hash_out.zeroize();
}

pub fn encrypt<const K: usize>(
    ct: &mut [u8],
    pk: &[u8],
    msg: &[u8; 32],
    coins: &[u8; 32],
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
) {
    let polyvec_bytes = K * POLYBYTES;

    let mut t_hat: PolyVec<K> = PolyVec::new();
    polyvec_frombytes(&mut t_hat, &pk[..polyvec_bytes]);

    let rho: [u8; 32] = pk[polyvec_bytes..polyvec_bytes + SYMBYTES]
        .try_into()
        .unwrap();

    let at = gen_matrix::<K>(&rho, true);

    let mut r: PolyVec<K> = sample_noise(coins, 0, eta1);
    let e1: PolyVec<K> = sample_noise(coins, K as u8, eta2);
    let e2 = sample_poly_cbd(coins, (2 * K) as u8, eta2);

    r.ntt();

    let mut u: PolyVec<K> = PolyVec::new();
    for (i, up) in u.vec.iter_mut().enumerate() {
        for (at_row, rp) in at[i].iter().zip(r.vec.iter()) {
            up.basemul_acc(at_row, rp);
        }
    }
    u.invntt();
    u.add(&e1);
    u.reduce();

    let mut v = t_hat.pointwise_acc(&r);
    v.invntt();

    let mut m = Poly::new();
    poly_frommsg(&mut m, msg);

    v.add(&e2);
    v.add(&m);
    v.reduce();

    let du_bytes = K * N * du / 8;
    let dv_bytes = N * dv / 8;

    polyvec_compress(&mut ct[..du_bytes], &u, du);
    poly_compress(&mut ct[du_bytes..du_bytes + dv_bytes], &v, dv);
}

pub fn decrypt<const K: usize>(msg: &mut [u8; 32], ct: &[u8], sk: &[u8], du: usize, dv: usize) {
    let polyvec_bytes = K * POLYBYTES;
    let du_bytes = K * N * du / 8;
    let dv_bytes = N * dv / 8;

    let mut u: PolyVec<K> = PolyVec::new();
    polyvec_decompress(&mut u, &ct[..du_bytes], du);

    let mut v = Poly::new();
    poly_decompress(&mut v, &ct[du_bytes..du_bytes + dv_bytes], dv);

    let mut s: PolyVec<K> = PolyVec::new();
    polyvec_frombytes(&mut s, &sk[..polyvec_bytes]);

    u.ntt();
    let mut mp = s.pointwise_acc(&u);
    mp.invntt();

    v.sub(&mp);
    v.reduce();

    poly_tomsg(msg, &v);
}
