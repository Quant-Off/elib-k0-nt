//! FIPS 203 명세에 따른 모듈 격자 기반 키 캡슐화 메커니즘(ML-KEM) 구현 모듈입니다.
//!
//! ML-KEM은 양자내성 암호(PQC) 알고리즘으로, 격자 문제의 어려움에 기반하여
//! 양자 컴퓨터 공격에도 안전한 키 교환을 제공합니다.
//!
//! # Features
//! - ML-KEM-512: NIST 보안 카테고리 1 (128-bit 보안 강도)
//! - ML-KEM-768: NIST 보안 카테고리 3 (192-bit 보안 강도)
//! - ML-KEM-1024: NIST 보안 카테고리 5 (256-bit 보안 강도)
//! - `no_std` 환경 지원 (베어메탈, 임베디드)
//! - 민감 데이터 자동 소거 (`zeroize` 크레이트 활용)
//! - 상수 시간 연산 (`constant-time` 크레이트 활용)
//!
//! # Examples
//! ```rust,ignore
//! use mlkem::{mlkem768_keygen, mlkem768_encaps, mlkem768_decaps};
//!
//! // 1. 키 쌍 생성 (d, z는 32바이트 난수 시드)
//! let d = [0u8; 32]; // CSPRNG로 생성 필요
//! let z = [0u8; 32]; // CSPRNG로 생성 필요
//! let keypair = mlkem768_keygen(&d, &z);
//!
//! // 2. 캡슐화 (송신자: 공유 비밀 + 암호문 생성)
//! let m = [0u8; 32]; // CSPRNG로 생성 필요
//! let (ciphertext, shared_secret_enc) = mlkem768_encaps(&keypair.ek, &m);
//!
//! // 3. 역캡슐화 (수신자: 공유 비밀 복원)
//! let shared_secret_dec = mlkem768_decaps(&ciphertext, keypair.dk.expose());
//!
//! assert_eq!(shared_secret_enc.expose(), shared_secret_dec.expose());
//! ```
//!
//! # Security Note
//! - 시드 `d`, `z`, `m`은 반드시 암호학적으로 안전한 난수 생성기(CSPRNG)로 생성해야 합니다.
//! - 역캡슐화 키(`dk`)는 `Secret` 래퍼로 보호되며, 스코프 종료 시 자동 소거됩니다.
//! - 암호문 변조 시 암묵적 거부(implicit rejection)를 수행합니다.
//!
//! # Authors
//! Q. T. Felix

#![cfg_attr(not(test), no_std)]

mod encode;
mod kem;
mod kpke;
mod ntt;
mod params;
mod poly;
mod reduce;
mod sample;

use params::{MLKEM512, MLKEM768, MLKEM1024, SHAREDSECRETBYTES, ct_bytes, dk_bytes, ek_bytes};
use zeroize::Secret;

/// ML-KEM-512 캡슐화 키 바이트 크기 (800 bytes)
pub(crate) const MLKEM512_EK_BYTES: usize = ek_bytes(2);
/// ML-KEM-512 역캡슐화 키 바이트 크기 (1632 bytes)
pub(crate) const MLKEM512_DK_BYTES: usize = dk_bytes(2);
/// ML-KEM-512 암호문 바이트 크기 (768 bytes)
pub(crate) const MLKEM512_CT_BYTES: usize = ct_bytes(2, 10, 4);

/// ML-KEM-768 캡슐화 키 바이트 크기 (1184 bytes)
pub(crate) const MLKEM768_EK_BYTES: usize = ek_bytes(3);
/// ML-KEM-768 역캡슐화 키 바이트 크기 (2400 bytes)
pub(crate) const MLKEM768_DK_BYTES: usize = dk_bytes(3);
/// ML-KEM-768 암호문 바이트 크기 (1088 bytes)
pub(crate) const MLKEM768_CT_BYTES: usize = ct_bytes(3, 10, 4);

/// ML-KEM-1024 캡슐화 키 바이트 크기 (1568 bytes)
pub(crate) const MLKEM1024_EK_BYTES: usize = ek_bytes(4);
/// ML-KEM-1024 역캡슐화 키 바이트 크기 (3168 bytes)
pub(crate) const MLKEM1024_DK_BYTES: usize = dk_bytes(4);
/// ML-KEM-1024 암호문 바이트 크기 (1568 bytes)
pub(crate) const MLKEM1024_CT_BYTES: usize = ct_bytes(4, 11, 5);

/// ML-KEM-512 키 쌍 구조체
///
/// # Security Note
/// 역캡슐화 키 `dk`는 `Secret` 래퍼로 보호되어 스코프 종료 시 자동 소거됩니다.
pub struct MLKEM512KeyPair {
    /// 캡슐화 키 (공개 키)
    pub ek: [u8; MLKEM512_EK_BYTES],
    /// 역캡슐화 키 (비밀 키)
    pub dk: Secret<[u8; MLKEM512_DK_BYTES]>,
}

/// ML-KEM-768 키 쌍 구조체
///
/// # Security Note
/// 역캡슐화 키 `dk`는 `Secret` 래퍼로 보호되어 스코프 종료 시 자동 소거됩니다.
pub struct MLKEM768KeyPair {
    /// 캡슐화 키 (공개 키)
    pub ek: [u8; MLKEM768_EK_BYTES],
    /// 역캡슐화 키 (비밀 키)
    pub dk: Secret<[u8; MLKEM768_DK_BYTES]>,
}

/// ML-KEM-1024 키 쌍 구조체
///
/// # Security Note
/// 역캡슐화 키 `dk`는 `Secret` 래퍼로 보호되어 스코프 종료 시 자동 소거됩니다.
pub struct MLKEM1024KeyPair {
    /// 캡슐화 키 (공개 키)
    pub ek: [u8; MLKEM1024_EK_BYTES],
    /// 역캡슐화 키 (비밀 키)
    pub dk: Secret<[u8; MLKEM1024_DK_BYTES]>,
}

/// ML-KEM-512 키 쌍을 생성합니다.
///
/// # Arguments
/// - `d`: 32바이트 시드 (CSPRNG로 생성 필요)
/// - `z`: 32바이트 시드 (CSPRNG로 생성 필요)
///
/// # Security Note
/// `d`와 `z`는 반드시 암호학적으로 안전한 난수 생성기로 생성해야 합니다.
pub fn mlkem512_keygen(d: &[u8; 32], z: &[u8; 32]) -> MLKEM512KeyPair {
    let mut ek = [0u8; MLKEM512_EK_BYTES];
    let mut dk = [0u8; MLKEM512_DK_BYTES];
    kem::keygen::<2>(&mut ek, &mut dk, d, z, MLKEM512.eta1);
    MLKEM512KeyPair {
        ek,
        dk: Secret::new(dk),
    }
}

/// ML-KEM-512 캡슐화를 수행합니다.
///
/// # Arguments
/// - `ek`: 캡슐화 키 (공개 키)
/// - `m`: 32바이트 난수 (CSPRNG로 생성 필요)
///
/// # Returns
/// - 암호문과 공유 비밀 키의 튜플
pub fn mlkem512_encaps(
    ek: &[u8; MLKEM512_EK_BYTES],
    m: &[u8; 32],
) -> ([u8; MLKEM512_CT_BYTES], Secret<[u8; SHAREDSECRETBYTES]>) {
    let mut ct = [0u8; MLKEM512_CT_BYTES];
    let mut ss = [0u8; SHAREDSECRETBYTES];
    kem::encaps::<2>(
        &mut ct,
        &mut ss,
        ek,
        m,
        MLKEM512.eta1,
        MLKEM512.eta2,
        MLKEM512.du,
        MLKEM512.dv,
    );
    (ct, Secret::new(ss))
}

/// ML-KEM-512 역캡슐화를 수행합니다.
///
/// # Arguments
/// - `ct`: 암호문
/// - `dk`: 역캡슐화 키 (비밀 키)
///
/// # Returns
/// - 32바이트 공유 비밀 키
///
/// # Security Note
/// 암호문 변조 시 암묵적 거부(implicit rejection)를 수행합니다.
pub fn mlkem512_decaps(
    ct: &[u8; MLKEM512_CT_BYTES],
    dk: &[u8; MLKEM512_DK_BYTES],
) -> Secret<[u8; SHAREDSECRETBYTES]> {
    let mut ss = [0u8; SHAREDSECRETBYTES];
    kem::decaps::<2>(
        &mut ss,
        ct,
        dk,
        MLKEM512.eta1,
        MLKEM512.eta2,
        MLKEM512.du,
        MLKEM512.dv,
    );
    Secret::new(ss)
}

/// ML-KEM-768 키 쌍을 생성합니다.
///
/// # Arguments
/// - `d`: 32바이트 시드 (CSPRNG로 생성 필요)
/// - `z`: 32바이트 시드 (CSPRNG로 생성 필요)
///
/// # Security Note
/// `d`와 `z`는 반드시 암호학적으로 안전한 난수 생성기로 생성해야 합니다.
pub fn mlkem768_keygen(d: &[u8; 32], z: &[u8; 32]) -> MLKEM768KeyPair {
    let mut ek = [0u8; MLKEM768_EK_BYTES];
    let mut dk = [0u8; MLKEM768_DK_BYTES];
    kem::keygen::<3>(&mut ek, &mut dk, d, z, MLKEM768.eta1);
    MLKEM768KeyPair {
        ek,
        dk: Secret::new(dk),
    }
}

/// ML-KEM-768 캡슐화를 수행합니다.
///
/// # Arguments
/// - `ek`: 캡슐화 키 (공개 키)
/// - `m`: 32바이트 난수 (CSPRNG로 생성 필요)
///
/// # Returns
/// - 암호문과 공유 비밀 키의 튜플
pub fn mlkem768_encaps(
    ek: &[u8; MLKEM768_EK_BYTES],
    m: &[u8; 32],
) -> ([u8; MLKEM768_CT_BYTES], Secret<[u8; SHAREDSECRETBYTES]>) {
    let mut ct = [0u8; MLKEM768_CT_BYTES];
    let mut ss = [0u8; SHAREDSECRETBYTES];
    kem::encaps::<3>(
        &mut ct,
        &mut ss,
        ek,
        m,
        MLKEM768.eta1,
        MLKEM768.eta2,
        MLKEM768.du,
        MLKEM768.dv,
    );
    (ct, Secret::new(ss))
}

/// ML-KEM-768 역캡슐화를 수행합니다.
///
/// # Arguments
/// - `ct`: 암호문
/// - `dk`: 역캡슐화 키 (비밀 키)
///
/// # Returns
/// - 32바이트 공유 비밀 키
///
/// # Security Note
/// 암호문 변조 시 암묵적 거부(implicit rejection)를 수행합니다.
pub fn mlkem768_decaps(
    ct: &[u8; MLKEM768_CT_BYTES],
    dk: &[u8; MLKEM768_DK_BYTES],
) -> Secret<[u8; SHAREDSECRETBYTES]> {
    let mut ss = [0u8; SHAREDSECRETBYTES];
    kem::decaps::<3>(
        &mut ss,
        ct,
        dk,
        MLKEM768.eta1,
        MLKEM768.eta2,
        MLKEM768.du,
        MLKEM768.dv,
    );
    Secret::new(ss)
}

/// ML-KEM-1024 키 쌍을 생성합니다.
///
/// # Arguments
/// - `d`: 32바이트 시드 (CSPRNG로 생성 필요)
/// - `z`: 32바이트 시드 (CSPRNG로 생성 필요)
///
/// # Security Note
/// `d`와 `z`는 반드시 암호학적으로 안전한 난수 생성기로 생성해야 합니다.
pub fn mlkem1024_keygen(d: &[u8; 32], z: &[u8; 32]) -> MLKEM1024KeyPair {
    let mut ek = [0u8; MLKEM1024_EK_BYTES];
    let mut dk = [0u8; MLKEM1024_DK_BYTES];
    kem::keygen::<4>(&mut ek, &mut dk, d, z, MLKEM1024.eta1);
    MLKEM1024KeyPair {
        ek,
        dk: Secret::new(dk),
    }
}

/// ML-KEM-1024 캡슐화를 수행합니다.
///
/// # Arguments
/// - `ek`: 캡슐화 키 (공개 키)
/// - `m`: 32바이트 난수 (CSPRNG로 생성 필요)
///
/// # Returns
/// - 암호문과 공유 비밀 키의 튜플
pub fn mlkem1024_encaps(
    ek: &[u8; MLKEM1024_EK_BYTES],
    m: &[u8; 32],
) -> ([u8; MLKEM1024_CT_BYTES], Secret<[u8; SHAREDSECRETBYTES]>) {
    let mut ct = [0u8; MLKEM1024_CT_BYTES];
    let mut ss = [0u8; SHAREDSECRETBYTES];
    kem::encaps::<4>(
        &mut ct,
        &mut ss,
        ek,
        m,
        MLKEM1024.eta1,
        MLKEM1024.eta2,
        MLKEM1024.du,
        MLKEM1024.dv,
    );
    (ct, Secret::new(ss))
}

/// ML-KEM-1024 역캡슐화를 수행합니다.
///
/// # Arguments
/// - `ct`: 암호문
/// - `dk`: 역캡슐화 키 (비밀 키)
///
/// # Returns
/// - 32바이트 공유 비밀 키
///
/// # Security Note
/// 암호문 변조 시 암묵적 거부(implicit rejection)를 수행합니다.
pub fn mlkem1024_decaps(
    ct: &[u8; MLKEM1024_CT_BYTES],
    dk: &[u8; MLKEM1024_DK_BYTES],
) -> Secret<[u8; SHAREDSECRETBYTES]> {
    let mut ss = [0u8; SHAREDSECRETBYTES];
    kem::decaps::<4>(
        &mut ss,
        ct,
        dk,
        MLKEM1024.eta1,
        MLKEM1024.eta2,
        MLKEM1024.du,
        MLKEM1024.dv,
    );
    Secret::new(ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msg_encoding_roundtrip() {
        use crate::encode::{poly_frommsg, poly_tomsg};
        use crate::poly::Poly;

        let msg = [0xABu8; 32];
        let mut p = Poly::new();
        poly_frommsg(&mut p, &msg);

        println!("After frommsg [0..8]: {:?}", &p.coeffs[0..8]);

        let mut msg_out = [0u8; 32];
        poly_tomsg(&mut msg_out, &p);

        println!("Input:  {:?}", &msg[0..4]);
        println!("Output: {:?}", &msg_out[0..4]);
        assert_eq!(msg, msg_out, "Message encoding roundtrip failed");
    }

    #[test]
    fn test_ntt_invntt() {
        use crate::ntt::{invntt, ntt};
        use crate::params::N;
        use crate::reduce::montgomery_reduce;

        let mut a = [0i16; N];
        a[0] = 100;

        println!("Original [0..4]: {:?}", &a[0..4]);
        ntt(&mut a);
        println!("After NTT [0..4]: {:?}", &a[0..4]);
        invntt(&mut a);
        println!("After INVNTT [0..4]: {:?}", &a[0..4]);

        let expected = montgomery_reduce(100 * 1353);
        println!("Expected a[0] (100 * R): {}", expected);
    }

    #[test]
    fn test_kpke_manual() {
        use crate::encode::{poly_frommsg, poly_tomsg, polyvec_frombytes, polyvec_tobytes};
        use crate::params::N;
        use crate::poly::{
            Poly, PolyVec, poly_compress, poly_decompress, polyvec_compress, polyvec_decompress,
        };
        use crate::sample::gen_matrix;
        use sha3::{SHA3, SHA3_512};

        const K: usize = 2;
        const POLYBYTES: usize = N * 3 / 2;

        let d = [1u8; 32];
        let msg = [0xABu8; 32];

        let mut hasher = SHA3_512::new();
        hasher.update(&d);
        hasher.update(&[K as u8]);
        let digest = hasher.finalize();
        let mut hash_out = [0u8; 64];
        hash_out.copy_from_slice(digest.as_bytes());

        let rho: [u8; 32] = hash_out[..32].try_into().unwrap();

        let a_hat = gen_matrix::<K>(&rho, false);

        let mut s: PolyVec<K> = PolyVec::new();
        s.vec[0].coeffs[0] = 1;

        let mut e: PolyVec<K> = PolyVec::new();

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

        println!("t_hat[0] [0..4]: {:?}", &t_hat.vec[0].coeffs[0..4]);

        let mut ek = [0u8; 800];
        let mut sk = [0u8; 768];
        polyvec_tobytes(&mut ek[..K * POLYBYTES], &t_hat);
        ek[K * POLYBYTES..K * POLYBYTES + 32].copy_from_slice(&rho);
        polyvec_tobytes(&mut sk[..K * POLYBYTES], &s);

        let mut t_hat_loaded: PolyVec<K> = PolyVec::new();
        polyvec_frombytes(&mut t_hat_loaded, &ek[..K * POLYBYTES]);

        println!(
            "t_hat_loaded[0] [0..4]: {:?}",
            &t_hat_loaded.vec[0].coeffs[0..4]
        );

        let at = gen_matrix::<K>(&rho, true);

        let mut r: PolyVec<K> = PolyVec::new();
        r.vec[0].coeffs[0] = 1;

        r.ntt();

        let mut u: PolyVec<K> = PolyVec::new();
        for (i, up) in u.vec.iter_mut().enumerate() {
            for (at_row, rp) in at[i].iter().zip(r.vec.iter()) {
                up.basemul_acc(at_row, rp);
            }
        }
        u.invntt();
        u.reduce();

        println!("u[0] [0..4]: {:?}", &u.vec[0].coeffs[0..4]);

        let mut v = t_hat_loaded.pointwise_acc(&r);
        v.invntt();

        println!("t^T*r (before adding m) [0..4]: {:?}", &v.coeffs[0..4]);

        let mut m = Poly::new();
        poly_frommsg(&mut m, &msg);

        v.add(&m);
        v.reduce();

        println!("v after adding m [0..4]: {:?}", &v.coeffs[0..4]);

        let du = 10;
        let dv = 4;
        let du_bytes = K * N * du / 8;
        let dv_bytes = N * dv / 8;

        let mut ct = [0u8; 768];
        polyvec_compress(&mut ct[..du_bytes], &u, du);
        poly_compress(&mut ct[du_bytes..du_bytes + dv_bytes], &v, dv);

        let mut u_dec: PolyVec<K> = PolyVec::new();
        polyvec_decompress(&mut u_dec, &ct[..du_bytes], du);

        println!("u before compress [0]: {:?}", &u.vec[0].coeffs[0..4]);
        println!(
            "u_dec after decompress [0]: {:?}",
            &u_dec.vec[0].coeffs[0..4]
        );

        let mut v_dec = Poly::new();
        poly_decompress(&mut v_dec, &ct[du_bytes..du_bytes + dv_bytes], dv);

        println!("v before compress [0..4]: {:?}", &v.coeffs[0..4]);
        println!("v_dec after decompress [0..4]: {:?}", &v_dec.coeffs[0..4]);

        let mut s_loaded: PolyVec<K> = PolyVec::new();
        polyvec_frombytes(&mut s_loaded, &sk[..K * POLYBYTES]);

        u.ntt();
        let mut mp_exact = s_loaded.pointwise_acc(&u);
        mp_exact.invntt();
        println!(
            "s^T*u exact (no compression) [0..4]: {:?}",
            &mp_exact.coeffs[0..4]
        );

        u_dec.ntt();
        let mut mp = s_loaded.pointwise_acc(&u_dec);
        mp.invntt();

        println!(
            "s^T*u_dec (with compression) [0..4]: {:?}",
            &mp.coeffs[0..4]
        );

        v_dec.sub(&mp);
        v_dec.reduce();

        println!("v_dec - mp [0..4]: {:?}", &v_dec.coeffs[0..4]);

        let mut msg_out = [0u8; 32];
        poly_tomsg(&mut msg_out, &v_dec);

        println!("Input:  {:?}", &msg[0..8]);
        println!("Output: {:?}", &msg_out[0..8]);

        assert_eq!(msg, msg_out, "Manual K-PKE roundtrip failed");
    }

    #[test]
    fn test_kpke_roundtrip() {
        use crate::encode::poly_frommsg;
        use crate::kpke;
        use crate::params::N;
        use crate::poly::Poly;
        const POLYBYTES: usize = N * 3 / 2;
        const K: usize = 2;

        let d = [1u8; 32];
        let coins = [2u8; 32];
        let msg = [0xABu8; 32];

        let polyvec_bytes = K * POLYBYTES;
        let ek_len = polyvec_bytes + 32;
        let mut ek = [0u8; 800];
        let mut sk = [0u8; 768];

        kpke::keypair::<K>(&mut ek[..ek_len], &mut sk[..polyvec_bytes], &d, 3);

        let ct_len = K * N * 10 / 8 + N * 4 / 8;
        let mut ct = [0u8; 768];
        kpke::encrypt::<K>(&mut ct[..ct_len], &ek[..ek_len], &msg, &coins, 3, 2, 10, 4);

        let mut msg_dec = [0u8; 32];
        kpke::decrypt::<K>(&mut msg_dec, &ct[..ct_len], &sk[..polyvec_bytes], 10, 4);

        println!("Input msg:   {:?}", &msg[0..8]);
        println!("Decrypt msg: {:?}", &msg_dec[0..8]);

        let mut m_enc = Poly::new();
        poly_frommsg(&mut m_enc, &msg);
        println!("m_enc coeffs [0..8]: {:?}", &m_enc.coeffs[0..8]);

        let mut m_dec = Poly::new();
        poly_frommsg(&mut m_dec, &msg_dec);
        println!("m_dec coeffs [0..8]: {:?}", &m_dec.coeffs[0..8]);

        assert_eq!(msg, msg_dec, "K-PKE roundtrip failed");
    }

    #[test]
    fn test_mlkem512_roundtrip() {
        let d = [1u8; 32];
        let z = [2u8; 32];
        let m = [3u8; 32];

        let keypair = mlkem512_keygen(&d, &z);
        let (ct, ss_enc) = mlkem512_encaps(&keypair.ek, &m);
        let ss_dec = mlkem512_decaps(&ct, keypair.dk.expose());

        assert_eq!(ss_enc.expose(), ss_dec.expose());
    }

    #[test]
    fn test_mlkem768_roundtrip() {
        let d = [4u8; 32];
        let z = [5u8; 32];
        let m = [6u8; 32];

        let keypair = mlkem768_keygen(&d, &z);
        let (ct, ss_enc) = mlkem768_encaps(&keypair.ek, &m);
        let ss_dec = mlkem768_decaps(&ct, keypair.dk.expose());

        assert_eq!(ss_enc.expose(), ss_dec.expose());
    }

    #[test]
    fn test_mlkem1024_roundtrip() {
        let d = [7u8; 32];
        let z = [8u8; 32];
        let m = [9u8; 32];

        let keypair = mlkem1024_keygen(&d, &z);
        let (ct, ss_enc) = mlkem1024_encaps(&keypair.ek, &m);
        let ss_dec = mlkem1024_decaps(&ct, keypair.dk.expose());

        assert_eq!(ss_enc.expose(), ss_dec.expose());
    }
}
