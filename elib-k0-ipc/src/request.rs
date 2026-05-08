#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    SignKeygen(SignKeygenAlgo),
    Sign(SignAlgo),
    Verify(VerifyAlgo),
    KexKeygen(KexKeygenAlgo),
    Encaps(EncapsAlgo),
    Decaps(DecapsAlgo),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignKeygenAlgo {
    Ed25519,
    Ed448,
    MLDSA44,
    MLDSA65,
    MLDSA87,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAlgo {
    Ed25519,
    Ed448,
    MLDSA44,
    MLDSA65,
    MLDSA87,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyAlgo {
    Ed25519,
    Ed448,
    MLDSA44,
    MLDSA65,
    MLDSA87,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexKeygenAlgo {
    X25519,
    X448,
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    X25519MLKEM768,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncapsAlgo {
    X25519,
    X448,
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    X25519MLKEM768,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecapsAlgo {
    X25519,
    X448,
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    X25519MLKEM768,
}
