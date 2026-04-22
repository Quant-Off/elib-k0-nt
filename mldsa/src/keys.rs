use crate::Q;
use crate::error::Error;
use crate::field::Fq;
use crate::ntt::N;
use crate::pack::{
    bitlen, poly_simple_bit_pack_t1, poly_simple_bit_unpack_t1, polyvec_bit_pack_eta,
    polyvec_bit_pack_t0, polyvec_bit_unpack_eta, polyvec_bit_unpack_t0,
};
use crate::poly::PolyVec;
use crate::sample::{expand_a, expand_s};
use constant_time::{Choice, CtSelOps};
use sha3::{SHAKE256, XOF};

pub struct PublicKey<const K: usize> {
    pub rho: [u8; 32],
    pub t1: PolyVec<K>,
}

pub struct PrivateKey<const K: usize, const L: usize> {
    pub rho: [u8; 32],
    pub k_seed: [u8; 32],
    pub tr: [u8; 64],
    pub s1: PolyVec<L>,
    pub s2: PolyVec<K>,
    pub t0: PolyVec<K>,
}

#[inline(always)]
fn is_negative_ct(v: i32) -> Choice {
    Choice::from_u8(((v >> 31) & 1) as u8)
}

fn power2round_vec<const K: usize>(t: &PolyVec<K>) -> (PolyVec<K>, PolyVec<K>) {
    let mut t1 = PolyVec::<K>::new_zero();
    let mut t0 = PolyVec::<K>::new_zero();

    for i in 0..K {
        for j in 0..N {
            let a = t.vec[i].coeffs[j].0;
            let a1 = (a + 4095) >> 13;
            let a0 = a - (a1 << 13);

            let is_neg = is_negative_ct(a0);
            let a0_fq = i32::select(&a0, &(a0 + Q), is_neg);

            t1.vec[i].coeffs[j] = Fq::new(a1);
            t0.vec[i].coeffs[j] = Fq::new(a0_fq);
        }
    }

    (t1, t0)
}

pub fn keygen_internal<const K: usize, const L: usize, const ETA: i32>(
    xi: &[u8; 32],
) -> Result<(PublicKey<K>, PrivateKey<K, L>), Error> {
    let mut seed_input = [0u8; 34];
    seed_input[..32].copy_from_slice(xi);
    seed_input[32] = K as u8;
    seed_input[33] = L as u8;

    let mut shake = SHAKE256::new();
    shake.update(&seed_input);
    let mut expanded = [0u8; 128];
    shake.finalize_into(&mut expanded);

    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut k_seed = [0u8; 32];
    rho.copy_from_slice(&expanded[0..32]);
    rho_prime.copy_from_slice(&expanded[32..96]);
    k_seed.copy_from_slice(&expanded[96..128]);

    let a_hat = expand_a::<K, L>(&rho)?;
    let (mut s1, s2) = expand_s::<K, L, ETA>(&rho_prime)?;

    let s1_original = s1;
    s1.ntt();
    let mut t = a_hat.multiply_vector(&s1);
    t.intt();
    t = t.add(&s2);

    let (t1, t0) = power2round_vec(&t);

    let mut shake_tr = SHAKE256::new();
    shake_tr.update(&rho);
    for i in 0..K {
        let mut t1_poly_bytes = [0u8; 320];
        poly_simple_bit_pack_t1(&t1.vec[i], &mut t1_poly_bytes);
        shake_tr.update(&t1_poly_bytes);
    }
    let mut tr = [0u8; 64];
    shake_tr.finalize_into(&mut tr);

    let pk = PublicKey { rho, t1 };
    let sk = PrivateKey {
        rho,
        k_seed,
        tr,
        s1: s1_original,
        s2,
        t0,
    };

    Ok((pk, sk))
}

pub fn pk_encode<const K: usize, const PK_LEN: usize>(pk: &PublicKey<K>) -> [u8; PK_LEN] {
    let mut out = [0u8; PK_LEN];
    out[..32].copy_from_slice(&pk.rho);
    for i in 0..K {
        poly_simple_bit_pack_t1(&pk.t1.vec[i], &mut out[32 + i * 320..32 + (i + 1) * 320]);
    }
    out
}

pub fn pk_decode<const K: usize, const PK_LEN: usize>(pk_bytes: &[u8; PK_LEN]) -> PublicKey<K> {
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk_bytes[..32]);

    let mut t1 = PolyVec::<K>::new_zero();
    for i in 0..K {
        t1.vec[i] = poly_simple_bit_unpack_t1(&pk_bytes[32 + i * 320..32 + (i + 1) * 320]);
    }

    PublicKey { rho, t1 }
}

pub fn sk_encode<const K: usize, const L: usize, const ETA: i32, const SK_LEN: usize>(
    sk: &PrivateKey<K, L>,
) -> [u8; SK_LEN] {
    let eta_bw = bitlen((2 * ETA) as u32);
    let s1_len = L * 32 * eta_bw;
    let s2_len = K * 32 * eta_bw;
    let t0_len = K * 32 * 13;

    let mut out = [0u8; SK_LEN];
    let mut off = 0;

    out[off..off + 32].copy_from_slice(&sk.rho);
    off += 32;

    out[off..off + 32].copy_from_slice(&sk.k_seed);
    off += 32;

    out[off..off + 64].copy_from_slice(&sk.tr);
    off += 64;

    polyvec_bit_pack_eta::<L>(&sk.s1, ETA, &mut out[off..off + s1_len]);
    off += s1_len;

    polyvec_bit_pack_eta::<K>(&sk.s2, ETA, &mut out[off..off + s2_len]);
    off += s2_len;

    polyvec_bit_pack_t0::<K>(&sk.t0, &mut out[off..off + t0_len]);

    out
}

pub fn sk_decode<const K: usize, const L: usize, const ETA: i32, const SK_LEN: usize>(
    sk_bytes: &[u8; SK_LEN],
) -> PrivateKey<K, L> {
    let eta_bw = bitlen((2 * ETA) as u32);
    let s1_len = L * 32 * eta_bw;
    let s2_len = K * 32 * eta_bw;
    let t0_len = K * 32 * 13;

    let mut off = 0;

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&sk_bytes[off..off + 32]);
    off += 32;

    let mut k_seed = [0u8; 32];
    k_seed.copy_from_slice(&sk_bytes[off..off + 32]);
    off += 32;

    let mut tr = [0u8; 64];
    tr.copy_from_slice(&sk_bytes[off..off + 64]);
    off += 64;

    let s1: PolyVec<L> = polyvec_bit_unpack_eta(&sk_bytes[off..off + s1_len], ETA);
    off += s1_len;

    let s2: PolyVec<K> = polyvec_bit_unpack_eta(&sk_bytes[off..off + s2_len], ETA);
    off += s2_len;

    let t0: PolyVec<K> = polyvec_bit_unpack_t0(&sk_bytes[off..off + t0_len]);

    PrivateKey {
        rho,
        k_seed,
        tr,
        s1,
        s2,
        t0,
    }
}
