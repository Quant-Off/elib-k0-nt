//! 위협적 입력에 대한 회귀 방어 테스트 모음임니다.
//!
//! 본 테스트 스위트는 두 가지 목적을 동시에 만족합니다.
//!
//! 1. **위협 입력 방어 검증**: 경계값 / 극단값 / 비대칭 입력에 대해 패닉
//!    또는 정의되지 않은 동작 (UB) 없이 결정론적 응답을 보장하는지 검증
//! 2. **MIRI 친화 functional test**: inline asm 미지원 환경에서도 cfg(miri)
//!    fallback 경로 (constant-time/src/internal.rs) 가 동일한 결과를 내는지
//!    intra-crate 회귀 검증
//!
//! 본 스위트는 timing 검증이 아니므로 release 빌드 / debug 빌드 / MIRI 모두에서
//! 동일한 결과를 산출해야 합니다.

use constant_time::{Choice, CtEqOps, CtGreeter, CtLess, CtSelOps};

//
// Choice::from_u8: u8 전 256 값에 대한 정확성
//

#[test]
fn threat_choice_from_u8_full_domain() {
    for v in 0u8..=255 {
        let c = Choice::from_u8(v);
        let expected = if v == 0 { 0u8 } else { 1u8 };
        assert_eq!(c.unwrap_u8(), expected, "from_u8({v})");
    }
}

#[test]
fn threat_choice_bitops_invariant() {
    // {0,1} 도메인을 벗어나지 않는지: 0/1 외 값이 나오면 후속 CT 연산이 깨짐
    for x in [0u8, 1].iter() {
        for y in [0u8, 1].iter() {
            let cx = Choice::from_u8(*x);
            let cy = Choice::from_u8(*y);
            let and = (cx & cy).unwrap_u8();
            let or = (cx | cy).unwrap_u8();
            let xor = (cx ^ cy).unwrap_u8();
            let not = (!cx).unwrap_u8();
            assert!(and <= 1, "AND 비트 도메인 위반 x={x} y={y}");
            assert!(or <= 1, "OR 비트 도메인 위반 x={x} y={y}");
            assert!(xor <= 1, "XOR 비트 도메인 위반 x={x} y={y}");
            assert!(not <= 1, "NOT 비트 도메인 위반 x={x}");
        }
    }
}

//
// 경계값: CtEqOps 모든 폭 (u8/u32/u64/u128 + signed)
//

#[test]
fn threat_eq_boundaries_unsigned() {
    let cases_u8: &[(u8, u8, u8)] = &[(0, 0, 1), (0xFF, 0xFF, 1), (0, 0xFF, 0), (0x7F, 0x80, 0)];
    for &(a, b, exp) in cases_u8 {
        assert_eq!(CtEqOps::eq(&a, &b).unwrap_u8(), exp, "u8 {a}=={b}");
    }
    let cases_u128: &[(u128, u128, u8)] = &[
        (0, 0, 1),
        (u128::MAX, u128::MAX, 1),
        (0, u128::MAX, 0),
        (1u128 << 64, 1u128 << 64, 1),
        ((1u128 << 64) | 1, 1u128 << 64, 0), // low half 만 다름
        (1u128 << 64, 1, 0),                 // high half 만 다름
    ];
    for &(a, b, exp) in cases_u128 {
        assert_eq!(CtEqOps::eq(&a, &b).unwrap_u8(), exp, "u128 a/b");
    }
}

#[test]
fn threat_eq_boundaries_signed() {
    let cases_i64: &[(i64, i64, u8)] = &[
        (0, 0, 1),
        (i64::MIN, i64::MIN, 1),
        (i64::MAX, i64::MAX, 1),
        (i64::MIN, i64::MAX, 0),
        (-1, 1, 0),
        (-1, -1, 1),
    ];
    for &(a, b, exp) in cases_i64 {
        assert_eq!(CtEqOps::eq(&a, &b).unwrap_u8(), exp, "i64 {a}=={b}");
    }
}

//
// 경계값: CtGreeter 부호별 ordering 정확성
//

#[test]
fn threat_gt_boundaries_unsigned() {
    let cases_u64: &[(u64, u64, u8)] = &[
        (0, 0, 0),
        (u64::MAX, 0, 1),
        (0, u64::MAX, 0),
        (u64::MAX, u64::MAX, 0),
        (1u64 << 63, (1u64 << 63) - 1, 1), // 최대 부호 비트 경계
    ];
    for &(a, b, exp) in cases_u64 {
        assert_eq!(CtGreeter::gt(&a, &b).unwrap_u8(), exp, "u64 {a}>{b}");
    }
    let cases_u128: &[(u128, u128, u8)] = &[
        (0, u128::MAX, 0),
        (u128::MAX, 0, 1),
        (1u128 << 127, (1u128 << 127) - 1, 1),
        ((1u128 << 64) | 5, 1u128 << 64, 1), // high 동일, low 비교
        (1u128 << 64, (1u128 << 64) | 5, 0),
    ];
    for &(a, b, exp) in cases_u128 {
        assert_eq!(CtGreeter::gt(&a, &b).unwrap_u8(), exp, "u128 gt");
    }
}

#[test]
fn threat_gt_boundaries_signed() {
    let cases_i64: &[(i64, i64, u8)] = &[
        (i64::MIN, i64::MAX, 0),
        (i64::MAX, i64::MIN, 1),
        (-1, 0, 0),
        (0, -1, 1),
        (i64::MIN, i64::MIN, 0),
        (i64::MAX, i64::MAX, 0),
    ];
    for &(a, b, exp) in cases_i64 {
        assert_eq!(CtGreeter::gt(&a, &b).unwrap_u8(), exp, "i64 {a}>{b}");
    }
    let cases_i128: &[(i128, i128, u8)] = &[
        (i128::MIN, i128::MAX, 0),
        (i128::MAX, i128::MIN, 1),
        (-1, 0, 0),
        (0, -1, 1),
        (-1, i128::MIN, 1),
        (i128::MIN, -1, 0),
    ];
    for &(a, b, exp) in cases_i128 {
        assert_eq!(CtGreeter::gt(&a, &b).unwrap_u8(), exp, "i128 gt");
    }
}

//
// CtLess: gt + eq 합성 정확성 회귀 가드
//

#[test]
fn threat_lt_consistency() {
    // a, b 모두에 대해 lt + eq + gt 의 합이 exactly 1 (3분할 보장)
    for a in 0u32..32 {
        for b in 0u32..32 {
            let lt = CtLess::lt(&a, &b).unwrap_u8();
            let eq = CtEqOps::eq(&a, &b).unwrap_u8();
            let gt = CtGreeter::gt(&a, &b).unwrap_u8();
            assert_eq!(
                lt + eq + gt,
                1,
                "삼분할 위반 a={a} b={b} lt={lt} eq={eq} gt={gt}"
            );
        }
    }
}

//
// CtSelOps: 모든 도메인 경계값 + swap 후 잔재 (functional 결과)
//

#[test]
fn threat_select_boundaries() {
    let c0 = Choice::from_u8(0);
    let c1 = Choice::from_u8(1);
    // select(a,b,0) == a, select(a,b,1) == b
    assert_eq!(u8::select(&0x12, &0xFE, c0), 0x12);
    assert_eq!(u8::select(&0x12, &0xFE, c1), 0xFE);
    assert_eq!(u128::select(&0, &u128::MAX, c0), 0);
    assert_eq!(u128::select(&0, &u128::MAX, c1), u128::MAX);
    assert_eq!(i128::select(&i128::MIN, &i128::MAX, c1), i128::MAX);
    assert_eq!(i128::select(&i128::MIN, &i128::MAX, c0), i128::MIN);
}

#[test]
fn threat_swap_functional() {
    // choice=0 → no-op, choice=1 → 교환
    let mut a = 0xDEAD_BEEF_u32;
    let mut b = 0xCAFE_BABE_u32;
    u32::swap(&mut a, &mut b, Choice::from_u8(0));
    assert_eq!((a, b), (0xDEAD_BEEF, 0xCAFE_BABE));
    u32::swap(&mut a, &mut b, Choice::from_u8(1));
    assert_eq!((a, b), (0xCAFE_BABE, 0xDEAD_BEEF));
    // 128-bit 경계
    let mut x = u128::MAX;
    let mut y = 0u128;
    u128::swap(&mut x, &mut y, Choice::from_u8(1));
    assert_eq!((x, y), (0, u128::MAX));
}

//
// 비대칭 / 위협 패턴 (Hamming weight 극단, 부호 비트 교차 등)
//

#[test]
fn threat_extreme_hamming_weight() {
    // 전부 1 / 전부 0 / 교차 패턴이 eq/gt 에서 의도된 결과를 내는지
    let patterns: &[u64] = &[
        0,
        u64::MAX,
        0xAAAA_AAAA_AAAA_AAAA,
        0x5555_5555_5555_5555,
        0xF0F0_F0F0_F0F0_F0F0,
        0x0F0F_0F0F_0F0F_0F0F,
    ];
    for &a in patterns {
        for &b in patterns {
            let eq = CtEqOps::eq(&a, &b).unwrap_u8();
            let exp_eq = (a == b) as u8;
            assert_eq!(eq, exp_eq, "eq HW 위반 a={a:#x} b={b:#x}");
            let gt = CtGreeter::gt(&a, &b).unwrap_u8();
            let exp_gt = (a > b) as u8;
            assert_eq!(gt, exp_gt, "gt HW 위반 a={a:#x} b={b:#x}");
        }
    }
}
