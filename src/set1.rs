use super::utils::*;

#[test]
fn challange1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(hex_to_base64(input), output.as_bytes());
}

#[test]
fn challange2() {
    let a = "1c0111001f010100061a024b53535009181c";
    let b = "686974207468652062756c6c277320657965";
    let output = "746865206b696420646f6e277420706c6179";
    assert_eq!(xor(&hex_to_raw(a), &hex_to_raw(b)), hex_to_raw(output));
}

#[test]
fn challange3() {
    let encoded = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let bytes = hex_to_raw(encoded);

    // create frequency table per bit position
    // good thing I know data compression 🙄
    let text = std::fs::read_to_string("data/book1").unwrap();
    let mut bit_counts = vec![[0; 2]; 8];
    let mut enc_bit_counts = vec![[0; 2]; 8];

    // for byte in text.bytes().filter(|&b| b.is_ascii_lowercase() || b == b' ') {
    for byte in text.bytes() {
        let mut bit_mask = 1;
        for bit_id in 0..8 {
            let bit = usize::from(byte & bit_mask > 0);
            bit_counts[bit_id][bit] += 1;
            bit_mask <<= 1;
        }
    }

    for byte in bytes.iter() {
        let mut bit_mask = 1;
        for bit_id in 0..8 {
            let bit = usize::from(byte & bit_mask > 0);
            enc_bit_counts[bit_id][bit] += 1;
            bit_mask <<= 1;
        }
    }

    let freq: Vec<f64> = bit_counts.iter()
        .map(|&[c0, c1]| f64::from(c0) / f64::from(c0 + c1))
        .collect();

    let enc_freq: Vec<f64> = enc_bit_counts.iter()
        .map(|&[c0, c1]| f64::from(c0) / f64::from(c0 + c1))
        .collect();

    println!("freq1: {freq:?}");
    println!("freq2: {enc_freq:?}");
    let avg = freq.iter().sum::<f64>() / 8.0;
    println!("avg: {avg}");

    let mut key: u8 = 0;
    for (&expected, &real) in freq.iter().zip(enc_freq.iter()) {
        let bit = u8::from((expected >= 0.5 && real < 0.5) || (expected < 0.5 && real >= 0.5));
        key >>= 1;
        key |= bit << 7;
    }

    println!("key: {key}");

    let decoded: Vec<u8> = bytes.iter().map(|byte| byte ^ key).collect();
    let s = String::from_utf8_lossy(&decoded);

    // for i in 0..=255 {
    //     let decoded: Vec<u8> = bytes.iter().map(|byte| byte ^ i).collect();
    //     let s = String::from_utf8_lossy(&decoded);
    //     println!("[{i}] {s}");
    // }

    // by bruteforce it's 88, but statistically 91 is more correct.
    // they're almost identical except the last 2 bits are flipped.

    dbg!(s);
}
