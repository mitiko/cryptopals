#![allow(dead_code)]

pub mod utils;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod set1;

#[cfg(test)]
mod set2;

fn main() {
    println!("Run tests with `cargo test -- --nocapture`");
}
