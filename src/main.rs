#![allow(dead_code)]

pub mod cbc;
pub mod ecb;
pub mod utils;
pub mod xor;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod set1;

#[cfg(test)]
mod set2;

fn main() {
    println!("Run tests with `cargo test -- --nocapture`");
}
