use super::conversions::{hex_to_raw, base64_to_raw};
use std::{fs::File, io::{self, BufRead}};

pub fn read_hex_lines(filename: &str) -> Vec<Vec<u8>> {
    let file = File::open(filename).unwrap();
    io::BufReader::new(file)
        .lines()
        .map(|line| line.unwrap())
        .map(|encoded| hex_to_raw(&encoded))
        .collect()
}

pub fn read_base64(filename: &str) -> Vec<u8> {
    let input = std::fs::read_to_string(filename).unwrap();
    base64_to_raw(&input)
}
