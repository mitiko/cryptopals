use std::collections::{HashMap, HashSet};

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use crate::utils::{conversions::*, io::*};
use crate::{cbc::*, ecb::*};

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
enum Mode {
    ECB,
    CBC,
}
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
        Mode::CBC => aes128_cbc_encrypt(&key, &iv, &data),
    };
    (mode, ciphertext)
}

fn detection_oracle(ciphertext: &[u8]) -> Mode {
    // same code as in challange 8
    let mut set = HashSet::new();
    for i in (0..ciphertext.len()).step_by(16) {
        let block = &ciphertext[i..i + 16];
        let block_data = u128::from_be_bytes(block.try_into().unwrap());
        set.insert(block_data);
    }
    if set.len() < ciphertext.len() / 16 {
        Mode::ECB
    } else {
        Mode::CBC
    }
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

#[test]
fn challange14() {
    assert_eq!(
        pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04"),
        Some(b"ICE ICE BABY".to_vec())
    );
    assert_eq!(pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05"), None);
    assert_eq!(pkcs7_unpad(b"ICE ICE BABY\x05\x04\x04\x04"), None);
}

const SECRET: &str = "
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";

// vulnerable function
fn ecb_random(plaintext: &[u8]) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::from_seed([57; 32]);

    let key = rng.gen();
    let suffix_str = base64_to_raw(SECRET);

    let data = {
        let mut data = Vec::with_capacity(plaintext.len() + suffix_str.len() + 16);
        data.extend_from_slice(plaintext);
        data.extend_from_slice(&suffix_str);
        pkcs7_pad(&data)
    };

    aes128_ecb_encrypt(&key, &data)
}

fn get_block_size<F>(insecure_fn: F) -> usize
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let initial_cipher_size = insecure_fn(b"").len();
    (1..(1 << 16))
        .map(|i| insecure_fn(&b"A".repeat(i)).len())
        .find(|&cipher_size| cipher_size > initial_cipher_size)
        .map(|cipher_size| cipher_size - initial_cipher_size)
        .unwrap()
}

fn get_suffix_len<F>(insecure_fn: F) -> usize
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let initial_cipher_size = insecure_fn(b"").len();
    (1..16)
        .map(|i| (i, insecure_fn(&b"A".repeat(i)).len()))
        .find(|&(_, cipher_size)| cipher_size > initial_cipher_size)
        .map(|(prefix_len, _)| initial_cipher_size - prefix_len)
        .unwrap()
}

#[ignore]
#[test]
fn challange12() {
    assert_eq!(get_block_size(ecb_random), 16);
    assert_eq!(detection_oracle(&b"0".repeat(16 * 4)), Mode::ECB);
    let suffix_len = get_suffix_len(ecb_random);
    assert_eq!(suffix_len, 138);

    fn get_nth_block(data: &[u8], n: usize) -> u128 {
        let block = data
            .iter()
            .skip(n * 16)
            .take(16)
            .map(|&x| x)
            .collect::<Vec<_>>();
        u128::from_be_bytes(block.try_into().unwrap())
    }

    let mut known_plaintext: Vec<u8> = Vec::new();
    while known_plaintext.len() != suffix_len {
        let block_id = known_plaintext.len() / 16;
        let prefix_len = 15 - (known_plaintext.len() % 16);
        let mut msg = b"A".repeat(prefix_len);
        msg.extend_from_slice(&known_plaintext);

        let truth_cipher = ecb_random(&msg[..prefix_len]);
        let true_hash = get_nth_block(&truth_cipher, block_id);

        let mut possible_bytes = Vec::new();
        for byte in 0x00..=0xff {
            msg.push(byte);
            let search_cipher = ecb_random(&msg);
            let search_hash = get_nth_block(&search_cipher, block_id);
            if search_hash == true_hash {
                possible_bytes.push(byte);
            }
            msg.pop();
        }
        assert_eq!(possible_bytes.len(), 1);
        known_plaintext.push(possible_bytes[0]);
    }

    assert_eq!(known_plaintext, base64_to_raw(SECRET));
}

#[derive(Debug, PartialEq, Eq)]
struct Profile {
    email: String,
    role: String,
    uid: u32,
}

impl Profile {
    fn for_email(email: &str) -> Self {
        let email_safe = email.replace('&', "%amp").replace('=', "%eq");
        Self {
            email: email_safe,
            uid: 10,
            role: String::from("role"),
        }
    }

    fn encode(&self) -> String {
        format!("email={}&uid={}&role={}", self.email, self.uid, self.role)
    }

    fn decode(data: &str) -> Option<Self> {
        let mut hashmap = HashMap::new();
        for kv_pair in data.split('&').take(3) {
            let fields: Vec<&str> = kv_pair.split('=').take(2).collect();
            if fields.len() < 2 {
                return None;
            }
            hashmap.insert(fields[0], fields[1]);
        }
        let email = hashmap.get("email")?.to_owned().to_owned();
        let role = hashmap.get("role")?.to_owned().to_owned();
        let uid = hashmap.get("uid")?.parse().ok()?;
        Some(Self { email, role, uid })
    }

    fn encrypt_with_key(&self, key: &[u8; 16]) -> Vec<u8> {
        let stringified = self.encode();
        let bytes = pkcs7_pad(stringified.as_bytes());
        aes128_ecb_encrypt(key, &bytes)
    }

    fn decrypt_with_key(key: &[u8; 16], ciphertext: &[u8]) -> Option<Self> {
        let raw_bytes = aes128_ecb_decrypt(key, ciphertext);
        let bytes = pkcs7_unpad(&raw_bytes)?;
        Self::decode(&String::from_utf8(bytes).ok()?)
    }
}

#[test]
fn encode_and_decode_profiles() {
    let profile = Profile::for_email("foo@bar.com");
    let encoded = profile.encode();
    let decoded = Profile::decode(&encoded).unwrap();
    assert_eq!(profile, decoded);
    assert_eq!(encoded.split('&').count(), 3);
    assert_eq!(encoded.split('=').count(), 4);
}

#[test]
fn encrypt_and_decrypt_profile() {
    let key = rand::rngs::StdRng::from_seed([57; 32]).gen();
    let profile = Profile::for_email("foo@bar.com");
    let encrypted = profile.encrypt_with_key(&key);
    let decrypted = Profile::decrypt_with_key(&key, &encrypted).unwrap();
    assert_eq!(profile, decrypted);
}

#[test]
fn challange13() {
    let key = rand::rngs::StdRng::from_seed([57; 32]).gen();
    let get_encrypted_profile = |data: &[u8]| -> Vec<u8> {
        let profile = Profile::for_email(&String::from_utf8_lossy(data));
        profile.encrypt_with_key(&key)
    };
    assert_eq!(get_block_size(get_encrypted_profile), 16);
    let static_len = get_suffix_len(get_encrypted_profile); // prefix + suffix
    assert_eq!(static_len, 23);
    // do we find the ending ""=user" or do we *know* the message format?
    // challange 15 seems to do this, so let's keep it easy here.

    // get len when "user" will overflow into next block (n is padding)
    // static_len + email_len = n*16 + b"user".len()
    // n = ceil((static_len - b"user".len()) / 16) * 16
    // email_len = n*16 - static_len + b"user".len()
    // example: [email=123456789a] [bcd&uid=10&role=] [user............]
    let multiple_of_16 = 16 + (static_len - "user".len()) >> 4 << 4;
    let email_len = multiple_of_16 - static_len + b"user".len();
    assert_eq!(email_len, 13);
    let ciphertext = get_encrypted_profile(&b"A".repeat(email_len));

    // encrypt block with the unknown key
    let admin_encrypted = {
        let mut data = b"A".repeat(16 - b"email=".len());
        let malicious_text = pkcs7_pad(b"admin");
        data.extend_from_slice(&malicious_text);
        &get_encrypted_profile(&data)[16..32] // second block
    };

    let block_count = ciphertext.len() / 16;
    let mut cipher_malicious = ciphertext[..(block_count - 1) * 16].to_vec();
    cipher_malicious.extend_from_slice(admin_encrypted);

    let malicious_profile = Profile::decrypt_with_key(&key, &cipher_malicious);
    assert_eq!(malicious_profile.unwrap().role, "admin");
}
