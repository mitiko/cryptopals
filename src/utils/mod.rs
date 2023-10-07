pub mod conversions;
pub mod io;

pub trait AsU128 {
    fn as_u128(self) -> u128;
}

impl AsU128 for &[u8] {
    /// Convert 16-byte blocks into u128, or panic
    fn as_u128(self) -> u128 {
        u128::from_be_bytes(self.try_into().unwrap())
    }
}
