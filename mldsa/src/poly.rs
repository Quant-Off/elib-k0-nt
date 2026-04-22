use crate::field::Fq;
use crate::ntt::{N, intt, ntt};

#[derive(Clone, Copy)]
pub struct Poly {
    pub coeffs: [Fq; N],
}

impl Poly {
    pub const fn new_zero() -> Self {
        Self { coeffs: [Fq(0); N] }
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new_zero();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i].add(other.coeffs[i]);
        }
        result
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::new_zero();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i].sub(other.coeffs[i]);
        }
        result
    }

    pub fn pointwise_montgomery(&self, other: &Self) -> Self {
        let mut result = Self::new_zero();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i].mul(other.coeffs[i]);
        }
        result
    }

    #[inline(always)]
    pub fn ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    #[inline(always)]
    #[allow(dead_code)]
    pub fn intt(&mut self) {
        intt(&mut self.coeffs);
    }
}

#[derive(Clone, Copy)]
pub struct PolyVec<const D: usize> {
    pub vec: [Poly; D],
}

impl<const D: usize> PolyVec<D> {
    pub const fn new_zero() -> Self {
        Self {
            vec: [Poly::new_zero(); D],
        }
    }

    pub fn ntt(&mut self) {
        for i in 0..D {
            ntt(&mut self.vec[i].coeffs);
        }
    }

    pub fn intt(&mut self) {
        for i in 0..D {
            intt(&mut self.vec[i].coeffs);
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new_zero();
        for i in 0..D {
            result.vec[i] = self.vec[i].add(&other.vec[i]);
        }
        result
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::new_zero();
        for i in 0..D {
            result.vec[i] = self.vec[i].sub(&other.vec[i]);
        }
        result
    }
}

#[derive(Clone, Copy)]
pub struct PolyMatrix<const K: usize, const L: usize> {
    pub rows: [[Poly; L]; K],
}

impl<const K: usize, const L: usize> PolyMatrix<K, L> {
    pub const fn new_zero() -> Self {
        Self {
            rows: [[Poly::new_zero(); L]; K],
        }
    }

    pub fn multiply_vector(&self, s: &PolyVec<L>) -> PolyVec<K> {
        let mut t = PolyVec::<K>::new_zero();
        for i in 0..K {
            for j in 0..L {
                let term = self.rows[i][j].pointwise_montgomery(&s.vec[j]);
                t.vec[i] = t.vec[i].add(&term);
            }
        }
        t
    }
}
