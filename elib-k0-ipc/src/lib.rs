#![cfg_attr(not(test), no_std)]
#![deny(unused_must_use)]

#[cfg(not(any(
    all(
        target_arch = "x86_64",
        any(target_os = "none", target_os = "macos", target_os = "linux")
    ),
    all(
        target_arch = "aarch64",
        any(target_os = "none", target_os = "macos", target_os = "linux")
    ),
)))]
compile_error!(
    "elib-k0-ipc: unsupported target. Supported: \
     x86_64-unknown-none, aarch64-unknown-none, \
     x86_64-apple-darwin, aarch64-apple-darwin, \
     x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu. \
     wasm32-*/wasm64-*/riscv64-*/mips-*/sparc-*/Windows/iOS/Android \
     are out of scope for this milestone. \
     Adding a new target requires (1) zeroize/src/barrier/<arch>.rs \
     implementation, (2) extending this whitelist."
);

mod error;
mod op;
mod request;
mod response;
mod secret;
mod transport;
mod wire;

pub use error::IpcError;
pub use op::Op;
pub use request::Request;
pub use response::Response;
pub use secret::{IsSecret, MustZeroize};
pub use transport::Transport;
pub use wire::{
    HEADER_LEN, Header, MAGIC, MAX_FRAME, MAX_PAYLOAD, SecureFrameBuffer, VER, decode_header,
    encode_error, encode_header,
};
