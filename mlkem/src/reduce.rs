use crate::params::Q;

const QINV: i32 = 62209;

#[inline]
pub fn montgomery_reduce(a: i32) -> i16 {
    let t = (((a as i16) as i32) * QINV) as i16;
    let t32 = t as i32;
    ((a - t32 * Q as i32) >> 16) as i16
}

#[inline]
pub fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = 20159;
    let t = (V * a as i32 + (1 << 25)) >> 26;
    (a as i32 - t * Q as i32) as i16
}

#[inline]
pub fn csubq(a: i16) -> i16 {
    let r = a.wrapping_sub(Q as i16);
    r.wrapping_add((r >> 15) & (Q as i16))
}

#[inline]
pub fn freeze(a: i16) -> i16 {
    let r = barrett_reduce(a);
    let neg_mask = r >> 15;
    let r = r.wrapping_add(neg_mask & (Q as i16));
    csubq(r)
}
