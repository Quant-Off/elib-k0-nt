#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IpcError {
    TruncatedFrame = 0xC1_01,
    MagicMismatch = 0xC1_02,
    VersionMismatch = 0xC1_03,
    UnknownOp = 0xC1_04,
    AlgorithmNotImplemented = 0xC1_05,
    PayloadTooLong = 0xC1_06,
    MalformedRequest = 0xC1_07,
    TransportError = 0xC1_08,
}
