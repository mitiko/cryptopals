use crate::{
    cbc::*,
    ctr::{aes128_ctr_decrypt, aes128_ctr_encrypt},
    ecb::*,
    set1::{break_rep_xor, xor_cross_entropy_analysis},
    utils::{conversions::base64_to_raw, io::*},
    xor::xor_rep,
};
use lazy_static::lazy_static;
use rand::{Rng, SeedableRng};

lazy_static! {
    static ref COOKIES: Vec<Vec<u8>> = {
        let lines = read_base64_lines("data/set3/challange17.txt");
        assert!(lines.len() == 10);
        lines
    };
}

fn server_encrypt(data: &[u8]) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::from_seed([57; 32]);
    let key = rng.gen();
    let iv: [u8; 16] = rng.gen();
    let padded = pkcs7_pad(data);
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
    // Note: plaintext block is stored in reverse
    let mut plaintext = Vec::with_capacity(16);
    let mut mutated_ciphertext = ciphertext.to_owned();
    let n = ciphertext.len();
    // We'll crack/decipher plaintext from the last block one byte at a time
    // at most we're doing 256 checks per byte => 2^8 * 2^4 = 2^12 <<< 2^128
    // Additionally, exploiting English's letter frequency table, average checks
    // per byte can be lowered to probably well below 128, effectively halved

    // First we'll start by eating as much of the already setup padding:
    if leak_padding_error(&mutated_ciphertext) {
        let pad = (1..=16)
            .rev()
            .find(|&guess_pad| {
                let idx = n - usize::from(guess_pad) - 16;
                mutated_ciphertext[idx] ^= 0x01;
                let is_padded = leak_padding_error(&mutated_ciphertext);
                mutated_ciphertext[idx] ^= 0x01; // undo xor to restore state
                !is_padded
            })
            .unwrap();
        plaintext = [pad].repeat(usize::from(pad));
    }

    while plaintext.len() != 16 {
        // The invariant for each iteration of the loops is that the mutated
        // ciphertexts has been altered to make the last x known bytes of the
        // plaintext the padding byte x (1 <= x < 16)
        let known_bytes = plaintext.len();
        let padding_byte = u8::try_from(known_bytes).unwrap() + 1;
        // We're attacking the (x + 1)-st byte back from the end
        let idx = ciphertext.len() - (known_bytes + 1) - 16;

        // For the next iteration we'll modify the last x bytes to be the
        // padding byte x + 1 and bruteforce guess the previous byte in the last
        // block of plaintext
        let modifier_byte = padding_byte ^ (padding_byte - 1);
        mutated_ciphertext
            .iter_mut()
            .skip(idx + 1)
            .take(plaintext.len())
            .for_each(|x| *x ^= modifier_byte);

        // Bruteforce the modifier byte which sets our desired padding
        let byte = (0x00..=0xff)
            .find(|byte| {
                mutated_ciphertext[idx] ^= byte;
                let mut is_padded = leak_padding_error(&mutated_ciphertext);
                mutated_ciphertext[idx] ^= byte; // undo xor to restore state

                // Double check that if we're cracking the last byte, the
                // matched plaintext is 0x01, not 0x02 or 0x03
                // (with previous plaintext interfering)
                if is_padded && known_bytes == 0 {
                    mutated_ciphertext[idx] ^= byte;
                    mutated_ciphertext[idx - 1] ^= 0x01;
                    is_padded = leak_padding_error(&mutated_ciphertext);
                    mutated_ciphertext[idx - 1] ^= 0x01; // undo xor to restore state
                    mutated_ciphertext[idx] ^= byte;
                }
                is_padded
            })
            .unwrap();

        // plaintext_unknown ^ byte = padding
        // plaintext_unknown = plaintext_unknown ^ byte ^ byte = padding ^ byte
        plaintext.push(byte ^ padding_byte);
        // Do the modification to keep invariant for next iteration of loop
        mutated_ciphertext[idx] ^= byte;
    }

    plaintext.reverse();
    plaintext
}

fn crack_cbc(mut ciphertext: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(ciphertext.len() - 16);
    while ciphertext.len() >= 32 {
        let cracked_block = crack_last_block(&ciphertext);
        plaintext.extend(cracked_block.iter().rev());
        ciphertext = &ciphertext[..ciphertext.len() - 16];
    }
    plaintext.reverse();
    pkcs7_unpad(&plaintext).unwrap()
}

#[test]
fn challange17() {
    for cookie_id in 0..10 {
        let data = &COOKIES[cookie_id];
        let ciphertext = server_encrypt(data);
        let plaintext = crack_cbc(&ciphertext);
        assert_eq!(data, &plaintext);
    }
}

#[test]
fn challange18() {
    let ciphertext =
        base64_to_raw("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
    let key = b"YELLOW SUBMARINE";
    let plaintext = aes128_ctr_decrypt(&ciphertext, key, 0, 0);
    assert!(String::from_utf8_lossy(&plaintext).contains("Ice, Ice, baby"));
}

#[test]
fn challange19() {
    let plaintexts = read_base64_lines("data/set3/challenge19.txt");
    let key = rand::rngs::StdRng::from_seed([57; 32]).gen();
    let ciphertexts: Vec<_> = plaintexts
        .iter()
        .map(|p| aes128_ctr_encrypt(&p, &key, 0, 0))
        .collect();

    let mut decoded = vec![Vec::new(); ciphertexts.len()];
    let len = ciphertexts.iter().map(|c| c.len()).max().unwrap();
    for idx in 0..len {
        let cipher_bytes: Vec<u8> = ciphertexts
            .iter()
            .filter_map(|c| c.get(idx))
            .map(|&x| x)
            .collect();
        let (key, _) = xor_cross_entropy_analysis(&cipher_bytes);
        for (i, data) in decoded.iter_mut().enumerate() {
            if let Some(byte) = ciphertexts[i].get(idx) {
                data.push(byte ^ key);
            }
        }
    }
    assert!(String::from_utf8_lossy(&decoded[5]).contains("polite meaningless words"));
    assert!(String::from_utf8_lossy(&decoded[34]).contains("yet I number him in the song"));
    // doesn't decode all the way correctly but gets the bulk of the job done
}

#[test]
fn challange20() {
    let plaintexts = read_base64_lines("data/set3/challenge20.txt");
    let key = rand::rngs::StdRng::from_seed([57; 32]).gen();
    let ciphertexts: Vec<_> = plaintexts
        .iter()
        .map(|p| aes128_ctr_encrypt(&p, &key, 0, 0))
        .collect();

    let len = ciphertexts.iter().map(|c| c.len()).min().unwrap();
    let mut long_cipher: Vec<u8> = Vec::with_capacity(len * ciphertexts.len());
    for ciphertext in ciphertexts {
        long_cipher.extend(&ciphertext[..len]);
    }

    let key = break_rep_xor(&long_cipher);
    let long_plain = xor_rep(&long_cipher, &key);
    let decoded: Vec<_> = long_plain.chunks_exact(len).map(|x| x.to_vec()).collect();

    assert_eq!(plaintexts.len(), decoded.len());
    assert!(String::from_utf8_lossy(&decoded[5]).contains("when I come your warned"));
    assert!(String::from_utf8_lossy(&decoded[34])
        .contains("wake ya with hundreds of thousands of volts"));
    // doesn't decode all the way correctly but gets the bulk of the job done
}
