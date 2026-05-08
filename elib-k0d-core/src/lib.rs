#![cfg_attr(not(test), no_std)]

mod arena;
mod dispatcher;

pub use arena::RequestArena;

use elib_k0_ipc::{SecureFrameBuffer, Transport};

pub fn serve_one<T: Transport>(transport: &mut T) {
    let mut wire_in = SecureFrameBuffer::new();
    let mut wire_out = SecureFrameBuffer::new();
    let mut arena = RequestArena::new();
    dispatcher::serve_one_body(transport, &mut wire_in, &mut wire_out, &mut arena);
}

pub fn run<T: Transport>(transport: &mut T) -> ! {
    loop {
        serve_one(transport);
    }
}

#[doc(hidden)]
pub fn serve_one_inner<T: Transport>(
    transport: &mut T,
    wire_in: &mut SecureFrameBuffer,
    wire_out: &mut SecureFrameBuffer,
    arena: &mut RequestArena,
) {
    dispatcher::serve_one_body(transport, wire_in, wire_out, arena);
}
