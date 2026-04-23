#![allow(clippy::too_many_arguments)]

use crate::kpke;
use crate::params::{N, SHAREDSECRETBYTES, SYMBYTES};
use constant_time::{Choice, CtEqOps, CtSelOps};
use sha3::{SHA3, SHA3_256, SHA3_512, SHAKE256, XOF};
use zeroize::Zeroize;

const POLYBYTES: usize = N * 3 / 2;

fn hash_h(input: &[u8]) -> [u8; 32] {
    let mut hasher = SHA3_256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn hash_g(input: &[u8]) -> [u8; 64] {
    let mut hasher = SHA3_512::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn kdf(ct: &[u8], ss_bar: &[u8; 32]) -> [u8; 32] {
    let mut hasher = SHAKE256::new();
    hasher.update(ss_bar);
    hasher.update(ct);
    let mut out = [0u8; 32];
    hasher.finalize_into(&mut out);
    out
}

pub fn keygen<const K: usize>(
    ek: &mut [u8],
    dk: &mut [u8],
    d: &[u8; 32],
    z: &[u8; 32],
    eta1: usize,
) {
    let polyvec_bytes = K * POLYBYTES;
    let ek_len = polyvec_bytes + SYMBYTES;

    kpke::keypair::<K>(&mut ek[..ek_len], &mut dk[..polyvec_bytes], d, eta1);

    dk[polyvec_bytes..polyvec_bytes + ek_len].copy_from_slice(&ek[..ek_len]);

    let h = hash_h(&ek[..ek_len]);
    dk[polyvec_bytes + ek_len..polyvec_bytes + ek_len + SYMBYTES].copy_from_slice(&h);

    dk[polyvec_bytes + ek_len + SYMBYTES..polyvec_bytes + ek_len + 2 * SYMBYTES].copy_from_slice(z);
}

pub fn encaps<const K: usize>(
    ct: &mut [u8],
    ss: &mut [u8; SHAREDSECRETBYTES],
    ek: &[u8],
    m: &[u8; 32],
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
) {
    let polyvec_bytes = K * POLYBYTES;
    let ek_len = polyvec_bytes + SYMBYTES;
    let ct_len = K * N * du / 8 + N * dv / 8;

    let h_ek = hash_h(&ek[..ek_len]);

    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..64].copy_from_slice(&h_ek);

    let g_out = hash_g(&g_input);
    let k_bar: [u8; 32] = g_out[..32].try_into().unwrap();
    let r: [u8; 32] = g_out[32..64].try_into().unwrap();

    kpke::encrypt::<K>(ct, &ek[..ek_len], m, &r, eta1, eta2, du, dv);

    *ss = kdf(&ct[..ct_len], &k_bar);

    g_input.zeroize();
}

pub fn decaps<const K: usize>(
    ss: &mut [u8; SHAREDSECRETBYTES],
    ct: &[u8],
    dk: &[u8],
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
) {
    let polyvec_bytes = K * POLYBYTES;
    let ek_len = polyvec_bytes + SYMBYTES;
    let ct_len = K * N * du / 8 + N * dv / 8;

    let sk = &dk[..polyvec_bytes];
    let ek = &dk[polyvec_bytes..polyvec_bytes + ek_len];
    let h_ek: [u8; 32] = dk[polyvec_bytes + ek_len..polyvec_bytes + ek_len + SYMBYTES]
        .try_into()
        .unwrap();
    let z: [u8; 32] = dk[polyvec_bytes + ek_len + SYMBYTES..polyvec_bytes + ek_len + 2 * SYMBYTES]
        .try_into()
        .unwrap();

    let mut m_prime = [0u8; 32];
    kpke::decrypt::<K>(&mut m_prime, ct, sk, du, dv);

    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..64].copy_from_slice(&h_ek);

    let g_out = hash_g(&g_input);
    let k_bar: [u8; 32] = g_out[..32].try_into().unwrap();
    let r: [u8; 32] = g_out[32..64].try_into().unwrap();

    let mut ct_prime = [0u8; 1568];
    kpke::encrypt::<K>(
        &mut ct_prime[..ct_len],
        ek,
        &m_prime,
        &r,
        eta1,
        eta2,
        du,
        dv,
    );

    let mut eq = Choice::from_u8(1);
    for i in 0..ct_len {
        eq &= CtEqOps::eq(&ct[i], &ct_prime[i]);
    }

    let k_bar_result = kdf(&ct[..ct_len], &k_bar);
    let z_result = kdf(&ct[..ct_len], &z);

    for i in 0..SHAREDSECRETBYTES {
        ss[i] = u8::select(&z_result[i], &k_bar_result[i], eq);
    }

    m_prime.zeroize();
    g_input.zeroize();
    ct_prime.zeroize();
}
