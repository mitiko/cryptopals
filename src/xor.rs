pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(m, n)| m ^ n).collect()
}

pub fn xor_rep(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter().cycle()).map(|(x, y)| x ^ y).collect()
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(m, n)| m ^ n)
        .map(|x| x.count_ones())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_test() {
        let start = b"this is a test";
        let end = b"wokka wokka!!!";
        assert_eq!(hamming_distance(start, end), 37);
    }

    #[test]
    fn xor_test() {
        let a = [0x0f, 0xf0, 0x55, 0x13];
        let b = [0x0f, 0x0f, 0xaa, 0xa7];
        assert_eq!(xor(&a, &b), [0x00, 0xff, 0xff, 0xb4]);
    }

    #[test]
    fn xor_uneven_test() {
        let a = [0x0f, 0xf0, 0x55, 0x13, 0xde, 0xad, 0xbe, 0xef];
        let b = [0x0f, 0x0f, 0xaa, 0xa7];
        assert_eq!(xor(&a, &b), [0x00, 0xff, 0xff, 0xb4]);
        // TODO: Do the other direction
    }

    // TODO: xor_round_trip xor(xor(a, b), b) = a
    // TODO: xor_round_trip xor(xor(a, b), a) = b

    #[test]
    fn xor_rep_test() {
        let data = [0x0f, 0xf0, 0x55, 0x13, 0xde, 0xad, 0xbe, 0xef];
        let key = [0xbb, 0x71, 0xa2]; // chosen randomly
        assert_eq!(
            xor_rep(&data, &key),
            [0xb4, 0x81, 0xf7, 0xa8, 0xaf, 0xf, 0x5, 0x9e]
        );
    }

    #[test]
    fn xor_rep_long_key() {
        let data = [0x0f, 0xf0, 0x55];
        let key = [0xbb, 0x71, 0xa2, 0x25];
        assert_eq!(xor_rep(&data, &key), [0xb4, 0x81, 0xf7]);
    }
}
