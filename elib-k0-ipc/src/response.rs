#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    SignKeygen(crate::request::SignKeygenAlgo),
    Sign(crate::request::SignAlgo),
    Verify(crate::request::VerifyAlgo),
    KexKeygen(crate::request::KexKeygenAlgo),
    Encaps(crate::request::EncapsAlgo),
    Decaps(crate::request::DecapsAlgo),
}
