use crate::params::N;
use crate::reduce::{barrett_reduce, montgomery_reduce};

const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

#[allow(dead_code)]
const ZETAS_INV: [i16; 128] = [
    1424, 653, 1328, 1094, 1606, 1010, 552, 1199, 106, 2776, 1148, 3185, 1628, 1462, 3313, 1887,
    1529, 3304, 958, 2424, 1823, 1109, 1330, 2319, 2312, 1438, 3126, 169, 3264, 2519, 2942, 1750,
    296, 1453, 1449, 2984, 2096, 3070, 1897, 1456, 3273, 3303, 107, 3097, 2242, 309, 2044, 1416,
    1166, 581, 876, 2326, 826, 1125, 3121, 1266, 1483, 2951, 1809, 2742, 2842, 1750, 2771, 2771,
    2819, 1806, 2131, 414, 2236, 686, 1738, 1822, 2874, 2480, 3210, 1769, 859, 1819, 3239, 2476,
    1469, 126, 2167, 1711, 2663, 3009, 3321, 516, 1785, 3047, 1491, 2036, 1015, 2777, 652, 1223,
    1758, 3124, 411, 1787, 608, 732, 1017, 2648, 3199, 1727, 1458, 2500, 383, 264, 2004, 573, 1468,
    1855, 2127, 962, 182, 1577, 622, 3158, 202, 287, 1422, 1493, 1812, 2970, 2571, 2285,
];

pub fn ntt(r: &mut [i16; N]) {
    let mut k: usize = 1;
    let mut len: usize = 128;
    while len >= 2 {
        let mut start: usize = 0;
        while start < N {
            let zeta = ZETAS[k] as i32;
            k += 1;
            let mut j = start;
            while j < start + len {
                let t = montgomery_reduce(zeta * r[j + len] as i32);
                r[j + len] = r[j] - t;
                r[j] += t;
                j += 1;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

pub fn invntt(r: &mut [i16; N]) {
    let mut k: usize = 127;
    let mut len: usize = 2;
    while len <= 128 {
        let mut start: usize = 0;
        while start < N {
            // Use same ZETAS array as forward NTT, accessed in reverse
            // The Kyber NTT structure is designed so this gives the inverse
            let zeta = ZETAS[k] as i32;
            k = k.wrapping_sub(1);
            let mut j = start;
            while j < start + len {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = montgomery_reduce(zeta * (r[j + len] - t) as i32);
                j += 1;
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    let f = 1441i32;
    for c in r.iter_mut() {
        *c = montgomery_reduce(f * *c as i32);
    }
}

pub fn basemul(r: &mut [i16; 2], a: &[i16; 2], b: &[i16; 2], zeta: i16) {
    let zeta32 = zeta as i32;
    r[0] = montgomery_reduce(a[1] as i32 * b[1] as i32);
    r[0] = montgomery_reduce(r[0] as i32 * zeta32);
    r[0] += montgomery_reduce(a[0] as i32 * b[0] as i32);
    r[1] = montgomery_reduce(a[0] as i32 * b[1] as i32);
    r[1] += montgomery_reduce(a[1] as i32 * b[0] as i32);
}

pub fn poly_basemul(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    for i in 0..N / 4 {
        let zeta = ZETAS[64 + i];
        let mut tmp = [0i16; 2];
        basemul(
            &mut tmp,
            &[a[4 * i], a[4 * i + 1]],
            &[b[4 * i], b[4 * i + 1]],
            zeta,
        );
        r[4 * i] = tmp[0];
        r[4 * i + 1] = tmp[1];
        basemul(
            &mut tmp,
            &[a[4 * i + 2], a[4 * i + 3]],
            &[b[4 * i + 2], b[4 * i + 3]],
            -zeta,
        );
        r[4 * i + 2] = tmp[0];
        r[4 * i + 3] = tmp[1];
    }
}

#[inline]
pub fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}
