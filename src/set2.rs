use std::collections::HashSet;

use rand::rngs::StdRng;
use rand::{RngCore, Rng, SeedableRng};

use crate::utils::{io::*, conversions::*};
use crate::{ecb::*, cbc::*};

#[test]
fn challange9() {
    let input = b"YELLOW SUBMARINE";
    let output = b"YELLOW SUBMARINE\x04\x04\x04\x04";
    assert_eq!(pkcs7_pad_to(20, input), output);
}

#[test]
fn challange10() {
    let data = read_base64("data/set2/challange10.txt");
    let key = b"YELLOW SUBMARINE";
    let iv = b"\x00\x00\x00";
    let decrypted = aes128_cbc_decrypt(key, iv, &data);
    assert_eq!(&decrypted[decrypted.len() - 5..], b"\x0a\x04\x04\x04\x04");
    std::fs::write("data/decoded/set2-challange10.txt", decrypted).unwrap();
}

#[derive(PartialEq, Eq, Debug)]
enum Mode { ECB, CBC }
fn encryption_oracle(plaintext: &[u8], seed: [u8; 32]) -> (Mode, Vec<u8>) {
    let mut rng = rand::rngs::StdRng::from_seed(seed);

    fn gen_twig(rng: &mut StdRng) -> Vec<u8> {
        let len = rng.gen_range(5..=10);
        let mut data = vec![0; len];
        rng.fill_bytes(&mut data);
        data
    }

    let key = rng.gen();
    let iv: [_; 16] = rng.gen();
    let mut prefix = gen_twig(&mut rng);
    let suffix = gen_twig(&mut rng);
    let mode = if rng.gen() { Mode::ECB } else { Mode::CBC };
    let data = {
        prefix.extend_from_slice(plaintext);
        prefix.extend(suffix);
        pkcs7_pad(&prefix)
    };

    let ciphertext = match mode {
        Mode::ECB => aes128_ecb_encrypt(&key, &data),
        Mode::CBC => aes128_cbc_encrypt(&key, &iv, &data)
    };
    (mode, ciphertext)
}

fn detection_oracle(ciphertext: &[u8]) -> Mode {
    // same code as in challange 8
    let mut set = HashSet::new();
    for i in (0..ciphertext.len()).step_by(16) {
        let block = &ciphertext[i..i+16];
        let block_data = u128::from_be_bytes(block.try_into().unwrap());
        set.insert(block_data);
    }
    if set.len() < ciphertext.len() / 16 { Mode::ECB } else { Mode::CBC }
}

#[test]
fn challange11() {
    // detect repeating data, regardless of random prefix, suffix
    let plaintext = [0; 64];

    // generate random seeds from a seeded rng
    let mut rng = rand::rngs::StdRng::from_seed([133; 32]);
    for _ in 0..1000 {
        let (mode, ciphertext) = encryption_oracle(&plaintext, rng.gen());
        assert_eq!(mode, detection_oracle(&ciphertext));
    }
}

// vulnerable function
fn ecb_random(plaintext: &[u8]) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::from_seed([57; 32]);

    let key = rng.gen();
    let suffix_str = base64_to_raw("
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK");

    let data = {
        let mut data = Vec::with_capacity(plaintext.len() + suffix_str.len());
        data.extend_from_slice(plaintext);
        data.extend_from_slice(&suffix_str);
        pkcs7_pad(&data)
    };

    aes128_ecb_encrypt(&key, &data)
}

fn get_block_size() -> usize {
    let initial_cipher_size = ecb_random(b"").len();
    (1..(1 << 16))
        .map(|i| ecb_random(&b"A".repeat(i)).len())
        .find(|&cipher_size| cipher_size > initial_cipher_size)
        .map(|cipher_size| cipher_size - initial_cipher_size)
        .unwrap()
}

fn get_suffix_len() -> usize {
    let initial_cipher_size = ecb_random(b"").len();
    (1..16)
        .map(|i| (i, ecb_random(&b"A".repeat(i)).len()))
        .find(|&(_, cipher_size)| cipher_size > initial_cipher_size)
        .map(|(prefix_len, _)| initial_cipher_size - prefix_len + 1)
        .unwrap()
}

#[test]
fn challange12() {
    assert_eq!(get_block_size(), 16);
    assert_eq!(detection_oracle(&b"0".repeat(16*4)), Mode::ECB);
    let suffix_len = get_suffix_len();
    assert_eq!(suffix_len, 138);

    // let known_plaintext = Vec::new();

    // use the current prefix + each byte from 0 to 255
    // the one that matches the block_id with only the prefix is ours
    // assert only one matches?

    // append the new byte & move the block_id if needed (pos % 16 == 1)
}
