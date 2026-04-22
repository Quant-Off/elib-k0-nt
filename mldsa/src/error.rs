#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidLength,
    InternalError,
    ContextTooLong,
    SigningFailed,
    InvalidSignature,
}
