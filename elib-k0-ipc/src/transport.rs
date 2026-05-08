pub trait Transport {
    type Error: Copy;

    fn round_trip(&mut self, send: &[u8], recv: &mut [u8]) -> Result<usize, Self::Error>;
}
