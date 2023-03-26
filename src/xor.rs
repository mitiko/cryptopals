pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(m, n)| m ^ n).collect()
}

pub fn xor_rep(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().zip(key.iter().cycle()).map(|(x, y)| x ^ y).collect()
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    xor(a, b).iter().map(|x| x.count_ones()).sum()
}
