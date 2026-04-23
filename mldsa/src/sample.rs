use crate::Q;
use crate::error::Error;
use crate::field::Fq;
use crate::ntt::N;
use crate::poly::{Poly, PolyMatrix, PolyVec};
use sha3::{SHAKE128, SHAKE256, XOF};

pub fn expand_a<const K: usize, const L: usize>(rho: &[u8; 32]) -> Result<PolyMatrix<K, L>, Error> {
    let mut matrix = PolyMatrix::<K, L>::new_zero();

    for r in 0..K {
        for s in 0..L {
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(rho);
            seed[32] = s as u8;
            seed[33] = r as u8;
            matrix.rows[r][s] = rej_ntt_poly(&seed)?;
        }
    }

    Ok(matrix)
}

fn rej_ntt_poly(seed: &[u8; 34]) -> Result<Poly, Error> {
    let mut shake = SHAKE128::new();
    shake.update(seed);

    let mut buf = [0u8; 840];
    shake.finalize_into(&mut buf);

    let mut poly = Poly::new_zero();
    let mut count = 0;
    let mut i = 0;

    while count < N && i + 3 <= buf.len() {
        let b0 = buf[i] as u32;
        let b1 = buf[i + 1] as u32;
        let b2 = buf[i + 2] as u32;

        let val = b0 | (b1 << 8) | ((b2 & 0x7F) << 16);

        if val < Q as u32 {
            poly.coeffs[count] = Fq::new(val as i32);
            count += 1;
        }
        i += 3;
    }

    if count < N {
        return Err(Error::InternalError);
    }

    Ok(poly)
}

pub fn expand_s<const K: usize, const L: usize, const ETA: i32>(
    rho_prime: &[u8; 64],
) -> Result<(PolyVec<L>, PolyVec<K>), Error> {
    let mut s1 = PolyVec::<L>::new_zero();
    let mut s2 = PolyVec::<K>::new_zero();

    for r in 0..L {
        s1.vec[r] = rej_bounded_poly::<ETA>(rho_prime, r as u16)?;
    }

    for r in 0..K {
        s2.vec[r] = rej_bounded_poly::<ETA>(rho_prime, (r + L) as u16)?;
    }

    Ok((s1, s2))
}

fn rej_bounded_poly<const ETA: i32>(rho_prime: &[u8; 64], nonce: u16) -> Result<Poly, Error> {
    let mut seed = [0u8; 66];
    seed[..64].copy_from_slice(rho_prime);
    seed[64] = (nonce & 0xFF) as u8;
    seed[65] = (nonce >> 8) as u8;

    let mut shake = SHAKE256::new();
    shake.update(&seed);

    let buf_len = if ETA == 2 { 1024 } else { 768 };
    let mut buf = [0u8; 1024];
    shake.finalize_into(&mut buf[..buf_len]);

    let mut poly = Poly::new_zero();
    let mut count = 0;
    let mut i = 0;

    while count < N && i < buf_len {
        let z = buf[i];
        let z0 = (z & 0x0F) as i32;
        let z1 = (z >> 4) as i32;

        if z0 <= 2 * ETA {
            let mut val = ETA - z0;
            if val < 0 {
                val += Q;
            }
            poly.coeffs[count] = Fq::new(val);
            count += 1;
        }

        if count < N && z1 <= 2 * ETA {
            let mut val = ETA - z1;
            if val < 0 {
                val += Q;
            }
            poly.coeffs[count] = Fq::new(val);
            count += 1;
        }

        i += 1;
    }

    if count < N {
        return Err(Error::InternalError);
    }

    Ok(poly)
}

pub fn sample_in_ball(c_tilde: &[u8], tau: usize) -> Result<Poly, Error> {
    let buf_len = 8 + 256 + tau * 8;

    let mut shake = SHAKE256::new();
    shake.update(c_tilde);

    let mut buf = [0u8; 1024];
    let actual_len = if buf_len > 1024 { 1024 } else { buf_len };
    shake.finalize_into(&mut buf[..actual_len]);

    let mut signs: u64 = 0;
    for (k, &byte) in buf.iter().enumerate().take(8) {
        signs |= (byte as u64) << (8 * k);
    }

    let mut c = Poly::new_zero();
    let mut idx = 8usize;

    for i in (N - tau)..N {
        let j = loop {
            if idx >= actual_len {
                return Err(Error::InternalError);
            }
            let candidate = buf[idx] as usize;
            idx += 1;
            if candidate <= i {
                break candidate;
            }
        };

        c.coeffs[i] = c.coeffs[j];
        let sign_bit = (signs & 1) as i32;
        c.coeffs[j] = if sign_bit == 0 {
            Fq::new(1)
        } else {
            Fq::new(Q - 1)
        };
        signs >>= 1;
    }

    Ok(c)
}

pub fn expand_mask<const L: usize>(
    rho_pp: &[u8; 64],
    kappa: u16,
    gamma1: i32,
) -> Result<PolyVec<L>, Error> {
    use crate::pack::bit_unpack;
    use crate::pack::bitlen;

    let c = bitlen((2 * gamma1 - 1) as u32);
    let bpp = 32 * c;

    let mut y = PolyVec::<L>::new_zero();

    for i in 0..L {
        let nonce = kappa + i as u16;
        let mut seed = [0u8; 66];
        seed[..64].copy_from_slice(rho_pp);
        seed[64] = (nonce & 0xFF) as u8;
        seed[65] = (nonce >> 8) as u8;

        let mut shake = SHAKE256::new();
        shake.update(&seed);

        let mut buf = [0u8; 640];
        shake.finalize_into(&mut buf[..bpp]);

        y.vec[i] = bit_unpack(&buf[..bpp], gamma1 - 1, gamma1);
    }

    Ok(y)
}
