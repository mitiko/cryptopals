use std::collections::HashSet;

use crate::utils::{conversions::*, io::*, AsU128};
use crate::{ecb::*, xor::*};
use lazy_static::lazy_static;

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

    let (key, _) = xor_cross_entropy_analysis(&encoded);

    let decoded: Vec<u8> = encoded.iter().map(|byte| byte ^ key).collect();
    let output = String::from_utf8_lossy(&decoded);

    assert_eq!(key, 88);
    assert_eq!(output, "Cooking MC's like a pound of bacon");
}

lazy_static! {
    static ref FREQ_ENG: Vec<f64> = {
        let text = std::fs::read_to_string("data/book1").unwrap();
        let mut counts = [1.0; 256];
        text.as_bytes()
            .iter()
            .for_each(|&byte| counts[usize::from(byte)] += 1.0);
        let sum: f64 = counts.iter().sum();
        counts.iter().map(|c| c / sum).collect()
    };
}

fn xor_cross_entropy_analysis(encoded: &[u8]) -> (u8, f64) {
    let mut min_cross_entropy = f64::MAX;
    let mut best_key = 0;
    for key in 0..=255 {
        let decoded: Vec<u8> = encoded.iter().map(|byte| byte ^ key).collect();
        let freq: Vec<f64> = {
            let mut counts = [1.0; 256];
            decoded
                .iter()
                .for_each(|&byte| counts[usize::from(byte)] += 1.0);
            let sum: f64 = counts.iter().sum();
            counts.iter().map(|c| c / sum).collect()
        };

        let cross_entropy: f64 = FREQ_ENG
            .iter()
            .zip(freq.iter())
            .map(|(p, q)| -p * q.log2())
            .sum();

        if cross_entropy <= min_cross_entropy {
            min_cross_entropy = cross_entropy;
            best_key = key;
        }
    }

    (best_key, min_cross_entropy)
}

#[test]
#[ignore]
fn challange4() {
    let input = read_hex_lines("data/set1/challange4.txt");

    // min_by_key doesn't work on f64 :'(
    let mut line_id = 0;
    let mut min_entropy = f64::MAX;
    for (i, bytes) in input.iter().enumerate() {
        let (_, entropy) = xor_cross_entropy_analysis(&bytes);
        if entropy < min_entropy {
            line_id = i;
            min_entropy = entropy;
        }
    }

    let bytes = input.iter().skip(line_id).next().unwrap();
    let (key, _) = xor_cross_entropy_analysis(&bytes);
    let decoded: Vec<u8> = xor_rep(bytes, &[key]);

    assert_eq!(key, 53);
    assert_eq!(decoded, b"Now that the party is jumping\n");
}

#[test]
fn challange5() {
    let key = b"ICE";
    let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    assert_eq!(xor_rep(input, key), hex_to_raw(output));
}

#[test]
fn challange6() {
    let bytes = read_base64("data/set1/challange6.txt");

    let mut key_size = 0;
    let mut min_hamming_distance = f64::MAX;
    // find the block length (key size) that produces the minimal
    // hamming distance for two consecutive blocks
    // * for resilience, I'm using 4x the block length
    for l in 2..=40 {
        // test 4 blocks of key_size
        let hd = hamming_distance(&bytes[..4 * l], &bytes[4 * l..8 * l]);
        let normalized_hd = f64::from(hd) / f64::from(l as u8);
        if normalized_hd < min_hamming_distance {
            min_hamming_distance = normalized_hd;
            key_size = l;
        }
    }

    let key: Vec<u8> = (0..key_size)
        .map(|offset| {
            bytes
                .iter()
                .skip(offset)
                .step_by(key_size)
                .map(|&x| x)
                .collect::<Vec<u8>>()
        }) // group by xor-ed with same byte of key
        .map(|group| xor_cross_entropy_analysis(&group).0)
        .collect();

    // encryption is symmetric
    let raw = xor_rep(&bytes, &key);
    std::fs::write("data/decoded/set1-challange6.txt", raw).unwrap();
    assert_eq!(
        key,
        hex_to_raw("5465726d696e61746f7220583a204272696e6720746865206e6f697365")
    );
}

#[test]
fn challange7() {
    let data = read_base64("data/set1/challange7.txt");
    let key = b"YELLOW SUBMARINE";
    let raw = aes128_ecb_decrypt(key, &data);
    std::fs::write("data/decoded/set1-challange7.txt", raw).unwrap();
}

#[test]
fn challange8() {
    let input = read_hex_lines("data/set1/challange8.txt");

    // find which one has the most repetitions
    // luckily 16 bytes fit into u128 :))
    let (line, _) = input
        .iter()
        .enumerate()
        .min_by_key(|(_, encoded)| {
            assert_eq!(encoded.len(), 160);
            (0..encoded.len())
                .step_by(16)
                .map(|i| encoded[i..i + 16].as_u128())
                .collect::<HashSet<_>>()
                .len()
        })
        .unwrap();

    assert_eq!(line, 132);
}
