use rand::{SeedableRng, Rng};

use crate::{utils::io::*, cbc::*, ecb::*};

fn encrypt() -> Vec<u8> {
    let strings = read_base64_lines("data/set3/challange17.txt");
    assert!(strings.len() == 10);

    let mut rng = rand::rngs::StdRng::from_seed([57; 32]);
    let key = rng.gen();
    let iv: [u8; 16] = rng.gen();
    let plaintext = &strings[rng.gen_range(0..10)];
    let padded = pkcs7_pad(&plaintext);
    let ciphertext_data = aes128_cbc_encrypt(&key, &iv, &padded);
    [iv.to_vec(), ciphertext_data].concat()
}

// vulnerable function / web server
fn leak_padding_error(ciphertext: &[u8]) -> bool {
    let mut rng = rand::rngs::StdRng::from_seed([57; 32]);
    let key = rng.gen();
    let iv = &ciphertext[..16];
    let plaintext = aes128_cbc_decrypt(&key, &iv, &ciphertext[16..]);
    pkcs7_unpad(&plaintext).is_some()
}

// fn crack_last_block(ciphertext: &[u8]) -> Vec<u8> {
//     assert!(ciphertext.len() >= 32, "At least 2 blocks are required to crack the last one");
// }

#[test]
fn challange17() {
    let ciphertext = encrypt();
    assert_eq!(leak_padding_error(&ciphertext), true);

    // let n = ciphertext.len();
    // let mut v = Vec::new();
    // for byte in 0..=0xff {
    //     let mut mutatated_ciphertext = ciphertext.clone();
    //     mutatated_ciphertext[n - 1] ^= byte;
    //     if leak_padding_error(&mutatated_ciphertext) {
    //         v.push(byte);
    //     }
    // }
}