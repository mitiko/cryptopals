use crate::{cbc::*, ecb::*, utils::io::*};
use rand::{Rng, SeedableRng};

fn server_encrypt() -> Vec<u8> {
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

fn decrypt(ciphertext: &[u8]) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::from_seed([57; 32]);
    let key = rng.gen();
    let iv = &ciphertext[..16];
    let plaintext = aes128_cbc_decrypt(&key, &iv, &ciphertext[16..]);
    plaintext
}

fn crack_last_block(ciphertext: &[u8]) -> Vec<u8> {
    assert!(
        ciphertext.len() >= 32,
        "At least 2 blocks are required to crack the last one"
    );
    let mut plaintext = Vec::new(); // this is actually the block in reverse
    let mut mutated_ciphertext = ciphertext.to_owned();
    let n = ciphertext.len();
    // We'll crack/decipher plaintext from the last block one byte at a time
    // at most we're doing 256 checks per byte => 2^8 * 2^4 = 2^12 <<< 2^128
    // Additionally, exploiting English's letter frequency table, average checks
    // per byte can be lowered to probably well below 128, effectively halved
    // First we'll start by eating as much of the already setup

    if leak_padding_error(&mutated_ciphertext) {
        let pad = (1..=16)
            .rev()
            .find(|&guess_pad| {
                let idx = n - usize::from(guess_pad) - 16;
                mutated_ciphertext[idx] ^= 0x01;
                let is_padded = leak_padding_error(&mutated_ciphertext);
                mutated_ciphertext[idx] ^= 0x01;
                !is_padded
            })
            .unwrap();
        plaintext = [pad].repeat(usize::from(pad));
    }

    while plaintext.len() != 16 {
        // The invariant for each iteration of the loops is that the mutated
        // ciphertexts has been altered to make the last x known bytes of the
        // plaintext the padding byte x (1 <= x < 16)
        // For the next iteration we'll modify the last x bytes to be the
        // padding byte x + 1 and bruteforce guess the previous byte in the last
        // block of plaintext.
        let known_bytes = plaintext.len();
        let padding_byte = u8::try_from(known_bytes).unwrap() + 1;
        // We're attacking the (x + 1)-st byte back from the end
        let idx = ciphertext.len() - (known_bytes + 1) - 16;

        let modifier_byte = padding_byte ^ (padding_byte - 1);
        mutated_ciphertext
            .iter_mut()
            .skip(idx + 1)
            .take(plaintext.len())
            .for_each(|x| *x ^= modifier_byte);

        // let last_bytes: Vec<_> = decrypt(&mutated_ciphertext)
        //     .into_iter()
        //     .rev()
        //     .take(16)
        //     .rev()
        //     .collect();
        // dbg!(&last_bytes);
        // // assert!(false);

        dbg!(padding_byte);
        dbg!(plaintext.len());

        let byte = (0x00..=0xff)
            .find(|byte| {
                mutated_ciphertext[idx] ^= byte;
                let mut is_padded = leak_padding_error(&mutated_ciphertext);
                mutated_ciphertext[idx] ^= byte;
                // Double check that if we're cracking the last byte, the
                // matched plaintext is 0x01, not 0x02 or 0x03
                // (with previous plaintext interfering)
                if is_padded && known_bytes == 0 {
                    mutated_ciphertext[idx] ^= byte;
                    mutated_ciphertext[idx - 1] ^= 0x01;
                    is_padded = leak_padding_error(&mutated_ciphertext);
                    mutated_ciphertext[idx - 1] ^= 0x01;
                    mutated_ciphertext[idx] ^= byte;
                }
                is_padded
            })
            .unwrap();

        dbg!(byte);
        mutated_ciphertext[idx] ^= byte;
        let last_bytes: Vec<_> = decrypt(&mutated_ciphertext)
            .into_iter()
            .rev()
            .take(16)
            .rev()
            .collect();
        dbg!(&last_bytes);
        plaintext.push(byte ^ padding_byte);
    }

    plaintext.reverse();
    plaintext
}

#[test]
fn challange17() {
    let ciphertext = server_encrypt();
    assert_eq!(leak_padding_error(&ciphertext), true);
    dbg!("before");
    let pl = crack_last_block(&ciphertext);
    // dbg!("after");
    let st = String::from_utf8_lossy(&pl);
    dbg!(st);
    dbg!(pl.len());
    dbg!(pl);
    dbg!(&ciphertext);
    let pl = crack_last_block(&ciphertext[..ciphertext.len() - 16]);
    let st = String::from_utf8_lossy(&pl);
    dbg!(st);
    // dbg!(pl.len());
    dbg!(pl);
    // assert!(false);

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
