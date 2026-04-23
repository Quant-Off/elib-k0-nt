use crate::{Q, Q_INV};
use constant_time::{Choice, CtGreeter, CtSelOps};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Default)]
pub struct Fq(pub i32);

impl Zeroize for Fq {
    #[inline(always)]
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Fq {
    #[inline(always)]
    pub const fn new(val: i32) -> Self {
        Self(val)
    }

    #[inline(always)]
    fn is_negative_ct(v: i32) -> Choice {
        Choice::from_u8(((v >> 31) & 1) as u8)
    }

    pub fn add(self, other: Self) -> Self {
        let sum = self.0 + other.0;
        let sub = sum - Q;
        let is_neg = Self::is_negative_ct(sub);
        Self(i32::select(&sub, &sum, is_neg))
    }

    pub fn sub(self, other: Self) -> Self {
        let diff = self.0 - other.0;
        let add = diff + Q;
        let is_neg = Self::is_negative_ct(diff);
        Self(i32::select(&diff, &add, is_neg))
    }

    pub fn mul(self, other: Self) -> Self {
        let prod = (self.0 as i64) * (other.0 as i64);
        let t = (prod as i32).wrapping_mul(Q_INV);
        let t_q = (t as i64) * (Q as i64);
        let u = ((prod - t_q) >> 32) as i32;

        let is_neg = Self::is_negative_ct(u);
        let u_plus_q = u + Q;
        Self(i32::select(&u, &u_plus_q, is_neg))
    }
}

#[inline(always)]
pub fn fq_to_signed(v: i32) -> i32 {
    let half = Q / 2;
    let is_greater = CtGreeter::gt(&v, &half);
    i32::select(&v, &(v - Q), is_greater)
}

#[inline(always)]
pub fn signed_to_fq(signed: i32) -> i32 {
    let is_neg = Fq::is_negative_ct(signed);
    let with_q = signed + Q;
    i32::select(&signed, &with_q, is_neg)
}
