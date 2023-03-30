use std::collections::HashSet;

use rand::rngs::StdRng;
use rand::{RngCore, Rng, SeedableRng};

use crate::utils::io::*;
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

enum Mode { ECB, CBC }
fn encryption_oracle(plaintext: &[u8]) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::from_seed([133; 32]);

    fn gen_twig(rng: &mut StdRng) -> Vec<u8> {
        let len = rng.gen_range(5..=10);
        let mut data = vec![0; len];
        rng.fill_bytes(&mut data);
        data
    }

    let key = rng.gen();
    let iv: [_; 16] = rng.gen();
    let mut prefix = gen_twig(&mut rng);
    let postfix = gen_twig(&mut rng);
    let mode = if rng.gen() { Mode::ECB } else { Mode::CBC };
    let data = {
        prefix.extend_from_slice(plaintext);
        prefix.extend(postfix);
        pkcs7_pad(&prefix)
    };

    match mode {
        Mode::ECB => aes128_ecb_encrypt(&key, &data),
        Mode::CBC => aes128_cbc_encrypt(&key, &iv, &data)
    }
}

fn detection_oracle(ciphertext: &[u8]) -> Mode {
    // same code as in challange 8
    let mut set = HashSet::new();
    for i in (0..ciphertext.len()).step_by(16) {
        let block = &ciphertext[i..i+16];
        let block_data = u128::from_be_bytes(block.try_into().unwrap());
        set.insert(block_data);
    }
    if set.len() < ciphertext.len() / 16 { Mode::CBC } else { Mode::ECB }
}

#[test]
fn challange11() {
}
