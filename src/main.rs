#![allow(dead_code)]

pub mod cbc;
pub mod ecb;
pub mod ctr;
pub mod utils;
pub mod xor;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod set1;

#[cfg(test)]
mod set2;

#[cfg(test)]
mod set3;

fn main() {
    println!("Run tests with `cargo test -- --nocapture`");
}
