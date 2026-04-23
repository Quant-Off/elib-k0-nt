#![allow(dead_code)]

pub const Q: u16 = 3329;
pub const N: usize = 256;

pub const SYMBYTES: usize = 32;
pub const SHAREDSECRETBYTES: usize = 32;

pub struct MLKEMParams {
    pub k: usize,
    pub eta1: usize,
    pub eta2: usize,
    pub du: usize,
    pub dv: usize,
}

pub const MLKEM512: MLKEMParams = MLKEMParams {
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
};

pub const MLKEM768: MLKEMParams = MLKEMParams {
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
};

pub const MLKEM1024: MLKEMParams = MLKEMParams {
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
};

pub const fn poly_bytes() -> usize {
    N * 12 / 8
}

pub const fn polyvec_bytes(k: usize) -> usize {
    k * poly_bytes()
}

pub const fn poly_compressed_bytes(d: usize) -> usize {
    N * d / 8
}

pub const fn polyvec_compressed_bytes(k: usize, du: usize) -> usize {
    k * poly_compressed_bytes(du)
}

pub const fn ek_bytes(k: usize) -> usize {
    polyvec_bytes(k) + SYMBYTES
}

pub const fn dk_bytes(k: usize) -> usize {
    polyvec_bytes(k) + ek_bytes(k) + 2 * SYMBYTES
}

pub const fn ct_bytes(k: usize, du: usize, dv: usize) -> usize {
    polyvec_compressed_bytes(k, du) + poly_compressed_bytes(dv)
}
