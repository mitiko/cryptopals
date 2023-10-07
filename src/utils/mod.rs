pub mod conversions;
pub mod io;

pub trait AsU128 {
    fn as_u128(self) -> Option<u128>;
}

impl AsU128 for &[u8] {
    /// Convert 16-byte blocks into u128, otherwise if size doesn't match None
    fn as_u128(self) -> Option<u128> {
        self.try_into().ok().map(|bytes| u128::from_be_bytes(bytes))
    }
}
