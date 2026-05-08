use crate::error::IpcError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Op {
    // 0x10NN — SignKeygen family
    SignKeygenEd25519 = 0x10_01,
    SignKeygenEd448 = 0x10_02,
    SignKeygenMLDSA44 = 0x10_03,
    SignKeygenMLDSA65 = 0x10_04,
    SignKeygenMLDSA87 = 0x10_05,
    // 0x11NN — Sign family
    SignEd25519 = 0x11_01,
    SignEd448 = 0x11_02,
    SignMLDSA44 = 0x11_03,
    SignMLDSA65 = 0x11_04,
    SignMLDSA87 = 0x11_05,
    // 0x12NN — Verify family
    VerifyEd25519 = 0x12_01,
    VerifyEd448 = 0x12_02,
    VerifyMLDSA44 = 0x12_03,
    VerifyMLDSA65 = 0x12_04,
    VerifyMLDSA87 = 0x12_05,
    // 0x20NN — KexKeygen family
    KexKeygenX25519 = 0x20_01,
    KexKeygenX448 = 0x20_02,
    KexKeygenMLKEM512 = 0x20_03,
    KexKeygenMLKEM768 = 0x20_04,
    KexKeygenMLKEM1024 = 0x20_05,
    KexKeygenX25519MLKEM768 = 0x20_06,
    // 0x21NN — Encaps family (X25519/X448 의 derive_shared 시맨틱은 Phase 5 결정 — D-07)
    EncapsX25519 = 0x21_01,
    EncapsX448 = 0x21_02,
    EncapsMLKEM512 = 0x21_03,
    EncapsMLKEM768 = 0x21_04,
    EncapsMLKEM1024 = 0x21_05,
    EncapsX25519MLKEM768 = 0x21_06,
    // 0x22NN — Decaps family
    DecapsX25519 = 0x22_01,
    DecapsX448 = 0x22_02,
    DecapsMLKEM512 = 0x22_03,
    DecapsMLKEM768 = 0x22_04,
    DecapsMLKEM1024 = 0x22_05,
    DecapsX25519MLKEM768 = 0x22_06,
}

impl Op {
    pub const fn from_u16(v: u16) -> Result<Self, IpcError> {
        match v {
            0x10_01 => Ok(Op::SignKeygenEd25519),
            0x10_02 => Ok(Op::SignKeygenEd448),
            0x10_03 => Ok(Op::SignKeygenMLDSA44),
            0x10_04 => Ok(Op::SignKeygenMLDSA65),
            0x10_05 => Ok(Op::SignKeygenMLDSA87),
            0x11_01 => Ok(Op::SignEd25519),
            0x11_02 => Ok(Op::SignEd448),
            0x11_03 => Ok(Op::SignMLDSA44),
            0x11_04 => Ok(Op::SignMLDSA65),
            0x11_05 => Ok(Op::SignMLDSA87),
            0x12_01 => Ok(Op::VerifyEd25519),
            0x12_02 => Ok(Op::VerifyEd448),
            0x12_03 => Ok(Op::VerifyMLDSA44),
            0x12_04 => Ok(Op::VerifyMLDSA65),
            0x12_05 => Ok(Op::VerifyMLDSA87),
            0x20_01 => Ok(Op::KexKeygenX25519),
            0x20_02 => Ok(Op::KexKeygenX448),
            0x20_03 => Ok(Op::KexKeygenMLKEM512),
            0x20_04 => Ok(Op::KexKeygenMLKEM768),
            0x20_05 => Ok(Op::KexKeygenMLKEM1024),
            0x20_06 => Ok(Op::KexKeygenX25519MLKEM768),
            0x21_01 => Ok(Op::EncapsX25519),
            0x21_02 => Ok(Op::EncapsX448),
            0x21_03 => Ok(Op::EncapsMLKEM512),
            0x21_04 => Ok(Op::EncapsMLKEM768),
            0x21_05 => Ok(Op::EncapsMLKEM1024),
            0x21_06 => Ok(Op::EncapsX25519MLKEM768),
            0x22_01 => Ok(Op::DecapsX25519),
            0x22_02 => Ok(Op::DecapsX448),
            0x22_03 => Ok(Op::DecapsMLKEM512),
            0x22_04 => Ok(Op::DecapsMLKEM768),
            0x22_05 => Ok(Op::DecapsMLKEM1024),
            0x22_06 => Ok(Op::DecapsX25519MLKEM768),
            _ => Err(IpcError::UnknownOp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Op::from_u16 이 v1 의 33 OP 코드 모두를 valid 로 인식하고
    /// unmapped u16 값에 UnknownOp 반환하는지 검증 (D-06 wire ABI day-one freeze).
    /// B-03/B-04 Strategy A: panic!/unwrap/expect 미사용; assert! + matches! + assert_eq! 만 사용.
    #[test]
    fn op_from_u16_all_v1_codes_valid() {
        let valid_codes: [(u16, Op); 33] = [
            (0x10_01, Op::SignKeygenEd25519),
            (0x10_02, Op::SignKeygenEd448),
            (0x10_03, Op::SignKeygenMLDSA44),
            (0x10_04, Op::SignKeygenMLDSA65),
            (0x10_05, Op::SignKeygenMLDSA87),
            (0x11_01, Op::SignEd25519),
            (0x11_02, Op::SignEd448),
            (0x11_03, Op::SignMLDSA44),
            (0x11_04, Op::SignMLDSA65),
            (0x11_05, Op::SignMLDSA87),
            (0x12_01, Op::VerifyEd25519),
            (0x12_02, Op::VerifyEd448),
            (0x12_03, Op::VerifyMLDSA44),
            (0x12_04, Op::VerifyMLDSA65),
            (0x12_05, Op::VerifyMLDSA87),
            (0x20_01, Op::KexKeygenX25519),
            (0x20_02, Op::KexKeygenX448),
            (0x20_03, Op::KexKeygenMLKEM512),
            (0x20_04, Op::KexKeygenMLKEM768),
            (0x20_05, Op::KexKeygenMLKEM1024),
            (0x20_06, Op::KexKeygenX25519MLKEM768),
            (0x21_01, Op::EncapsX25519),
            (0x21_02, Op::EncapsX448),
            (0x21_03, Op::EncapsMLKEM512),
            (0x21_04, Op::EncapsMLKEM768),
            (0x21_05, Op::EncapsMLKEM1024),
            (0x21_06, Op::EncapsX25519MLKEM768),
            (0x22_01, Op::DecapsX25519),
            (0x22_02, Op::DecapsX448),
            (0x22_03, Op::DecapsMLKEM512),
            (0x22_04, Op::DecapsMLKEM768),
            (0x22_05, Op::DecapsMLKEM1024),
            (0x22_06, Op::DecapsX25519MLKEM768),
        ];
        for (raw, expected) in valid_codes.iter() {
            let result = Op::from_u16(*raw);
            assert!(
                result.is_ok(),
                "Op::from_u16(0x{:04X}) returned Err({:?})",
                raw,
                result.err()
            );
            // is_ok() 통과 후 안전한 unwrap 대체 — let-else 패턴.
            let Ok(op) = result else { unreachable!() };
            assert_eq!(op, *expected, "Op::from_u16(0x{:04X})", raw);
        }
    }

    /// unmapped u16 값에 UnknownOp 반환하는지 검증.
    #[test]
    fn op_from_u16_unknown_returns_unknown_op() {
        let unmapped: [u16; 6] = [0x0000, 0x0001, 0x10_FF, 0x11_06, 0xC1_01, 0xFFFF];
        for v in unmapped.iter() {
            let result = Op::from_u16(*v);
            assert!(
                matches!(result, Err(IpcError::UnknownOp)),
                "Op::from_u16(0x{:04X}) = {:?}, expected UnknownOp",
                v,
                result
            );
        }
    }

    /// Op 의 #[repr(u16)] 가 wire LE 인코딩과 일치하는지 검증.
    #[test]
    fn op_repr_u16_roundtrip() {
        let op = Op::SignKeygenEd25519;
        let raw = op as u16;
        assert_eq!(raw, 0x10_01);
        let result = Op::from_u16(raw);
        assert!(result.is_ok(), "roundtrip failed: {:?}", result.err());
        let Ok(round) = result else { unreachable!() };
        assert_eq!(round, op);
    }
}
