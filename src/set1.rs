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
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let encoded = hex_to_raw(input);

    let freq: Vec<f64> = {
        let text = std::fs::read_to_string("data/book1").unwrap();
        let mut counts = vec![1.0; 256];
        text.bytes().for_each(|byte| counts[usize::from(byte)] += 1.0);
        let sum: f64 = counts.iter().sum();
        counts.iter().map(|c| c / sum).collect()
    };

    let mut min_cross_entropy = f64::MAX;
    let mut best_key = 0;
    for key in 0..=255 {
        let decoded: Vec<u8> = encoded.iter().map(|byte| byte ^ key).collect();
        let dec_freq: Vec<f64> = {
            let mut counts = vec![1.0; 256];
            decoded.iter().for_each(|&byte| counts[usize::from(byte)] += 1.0);
            let sum: f64 = counts.iter().sum();
            counts.iter().map(|c| c / sum).collect()
        };

        let cross_entropy: f64 = freq.iter().zip(dec_freq.iter())
            .map(|(p, q)| -p * q.log2()).sum();

        if cross_entropy <= min_cross_entropy {
            min_cross_entropy = cross_entropy;
            best_key = key;
        }
    }

    let decoded: Vec<u8> = encoded.iter().map(|byte| byte ^ best_key).collect();
    let output = String::from_utf8_lossy(&decoded);

    assert_eq!(best_key, 88);
    assert_eq!(output, "Cooking MC's like a pound of bacon");
}
