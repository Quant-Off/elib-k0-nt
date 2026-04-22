#![no_std]

pub mod barrier;
mod secret;
pub mod volatile;
mod zeroize;

pub use secret::Secret;
pub use zeroize::{Zeroize, zeroize_flat};
