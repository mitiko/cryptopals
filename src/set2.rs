use std::collections::{HashMap, HashSet};
use std::ops::{Add, Sub};

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use crate::utils::{conversions::*, io::*, AsU128};
use crate::{cbc::*, ecb::*, xor::*};

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

/// Generates a buffer with random length and random bytes
fn gen_twig(
    range: impl rand::distributions::uniform::SampleRange<usize>,
    rng: &mut StdRng,
) -> Vec<u8> {
    let len = rng.gen_range(range);
    let mut data = vec![0; len];
    rng.fill_bytes(&mut data);
    data
}

/// Encrypts with either ECB or CBC
fn encryption_oracle(plaintext: &[u8], seed: [u8; 32]) -> (Mode, Vec<u8>) {
    // we take in the seed to test with multiple keys and suffixes
    let mut rng = rand::rngs::StdRng::from_seed(seed);

    let key = rng.gen();
    let iv: [_; 16] = rng.gen();
    let mut prefix = gen_twig(5..=10, &mut rng);
    let suffix = gen_twig(5..=10, &mut rng);
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

/// Detects ECB or CBC by finding repeating blocks
/// For this to work plaintext must've been repeating data
fn detection_oracle(ciphertext: &[u8]) -> Mode {
    // same code as in challange 8
    let mut set = HashSet::new();
    (0..ciphertext.len())
        .step_by(16)
        .map(|i| ciphertext[i..i + 16].as_u128().unwrap())
        .for_each(|block| {
            set.insert(block);
        });

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

const SECRET: &str = "
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";

// vulnerable function
fn ecb_random(plaintext: &[u8]) -> Vec<u8> {
    let key = rand::rngs::StdRng::from_seed([57; 32]).gen();
    let suffix = base64_to_raw(SECRET);

    let data = {
        let mut data = Vec::with_capacity(plaintext.len() + suffix.len() + 16);
        data.extend_from_slice(plaintext);
        data.extend_from_slice(&suffix);
        pkcs7_pad(&data)
    };

    aes128_ecb_encrypt(&key, &data)
}

/// Detects the block size of a vulnerable ECB fn
fn detect_block_size<F>(insecure_fn: F) -> usize
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

/// Detects the suffix length of a vulnerable non prefixed ECB function
fn detect_suffix_len<F>(insecure_fn: F) -> usize
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    // An empty plaintext will give us the padded length of the encrypted suffix
    // we want to extract the real length
    // A simple bruteforce attack is sufficient
    // the prefix that changes the ciphertext's block count must've aligned the
    // suffix perfectly on the start of the next block
    // Thus, if we substract from the initial cipher size this prefix length
    // we'll get the suffix length
    let initial_cipher_size = insecure_fn(b"").len();
    (1..=16)
        .map(|i| (i, insecure_fn(&b"A".repeat(i)).len()))
        .find(|&(_, cipher_size)| cipher_size > initial_cipher_size)
        .map(|(prefix_len, _)| initial_cipher_size - prefix_len)
        .unwrap()
}

#[test]
fn test_suffix_len_detection() {
    let vuln_fn_generator = |suffix_len: usize| {
        move |plaintext: &[u8]| {
            let key = rand::rngs::StdRng::from_seed([57; 32]).gen();
            let suffix = b"A".repeat(suffix_len);

            let data = {
                let mut data = Vec::with_capacity(plaintext.len() + suffix.len() + 16);
                data.extend_from_slice(plaintext);
                data.extend_from_slice(&suffix);
                pkcs7_pad(&data)
            };

            aes128_ecb_encrypt(&key, &data)
        }
    };

    for suffix_len in 16..32 {
        let vuln_function = vuln_fn_generator(suffix_len);
        assert_eq!(detect_suffix_len(vuln_function), suffix_len);
    }
}

fn get_nth_block(data: &[u8], n: usize) -> u128 {
    data.iter()
        .skip(n * 16)
        .take(16)
        .map(|&x| x)
        .collect::<Vec<_>>()
        .as_u128()
        .unwrap()
}

#[test]
fn challange12() {
    assert_eq!(detect_block_size(ecb_random), 16);
    assert_eq!(detection_oracle(&ecb_random(&b"0".repeat(64))), Mode::ECB);
    let suffix_len = detect_suffix_len(ecb_random);
    assert_eq!(suffix_len, 138);

    let mut known_plaintext: Vec<u8> = Vec::new();
    while known_plaintext.len() != suffix_len {
        let block_id = known_plaintext.len() / 16;
        let prefix_len = 15 - (known_plaintext.len() % 16);
        let mut msg = b"A".repeat(prefix_len);
        msg.extend_from_slice(&known_plaintext);

        let truth_cipher = ecb_random(&msg[..prefix_len]);
        let true_hash = get_nth_block(&truth_cipher, block_id);

        let possible_bytes: Vec<_> = (0x00..=0xff)
            .map(|byte| {
                msg.push(byte);
                let search_cipher = ecb_random(&msg);
                let search_hash = get_nth_block(&search_cipher, block_id);
                msg.pop();
                (byte, search_hash)
            })
            .filter(|&(_, search_hash)| search_hash == true_hash)
            .map(|(byte, _)| byte)
            .collect();

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
    assert_eq!(detect_block_size(get_encrypted_profile), 16);
    let static_len = detect_suffix_len(get_encrypted_profile); // prefix + suffix
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

// (less?) vulnerable function
fn ecb_random_prefixed(plaintext: &[u8]) -> Vec<u8> {
    // only for consistency (not actually required to use a seed)
    let mut rng = rand::rngs::StdRng::from_seed([37; 32]);

    let key = rng.gen();
    let prefix = gen_twig(10..=120, &mut rng);
    let suffix = base64_to_raw(SECRET);

    let data = {
        let mut data = Vec::with_capacity(prefix.len() + plaintext.len() + suffix.len() + 16);
        data.extend_from_slice(&prefix);
        data.extend_from_slice(plaintext);
        data.extend_from_slice(&suffix);
        pkcs7_pad(&data)
    };

    aes128_ecb_encrypt(&key, &data)
}

/// Detects the suffix length of a vulnerable ECB function
fn detect_affix_lens<F>(insecure_fn: F) -> (usize, usize)
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    // BRIEF:
    // Unlike the suffix detector, we can't judge purely on ciphertext size,
    // if we attempt to we'll derive prefix_rem + suffix_rem and won't have
    // enough information to get the individual lengths.
    // With 2 additional bruteforce attacks we can first detect the block count
    // of the padded prefix, and then extract the exact padding size, which
    // gives us the unpadded prefix length.

    // PART 1:
    // To ensure we get a fill-in to both the prefix blocks and suffix blocks
    // we must consider a wider range for the bruteforce. Consider:
    // [abcdefAxyzwvutsr] vs [abcdefAAAAAAAAAA] [AAAAAAAxyzwvutsr]
    // In the extremes, the range is from 1 to 32, and to avoid this undesired
    // clustering we shall start at the top of the range and search in reverse.
    // This introduces a few new problems - first, we have to use a non-empty
    // plaintext for the initial size, second (and this is the bigger issue)
    // we may overfill: [abcdefghijklmnoA] [AAAAAAAAAAAAAAAA] [Axyzwvutsrqponml]
    // There is no way to detect if we've overfilled during this bruteforce but
    // we can account for it later, no drama.
    // Additionally, this allows to shorten the search from 1..32 to 16..32 yay
    // We must be careful when searching backwards too because when we've padded
    // perfectly with As pkcs7 adds 1 additional block. Example:
    // [xAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAy] [PPPPPPPPPPPPPPPP]
    // Here the count is 30 but we'll detect a change in cipher size at 29.
    // To account for it we can just add 1, but be careful, we must also adjust
    // the search range - results vary 16..=32, so we search 15..=31
    // * also why we substract 16 at the very end computing `suffix_len`

    let initial_cipher_size = insecure_fn(&b"A".repeat(32)).len();
    let combined_rem = (15..=31)
        .rev()
        .map(|i| (i, insecure_fn(&b"A".repeat(i)).len()))
        .find(|&(_, cipher_size)| cipher_size < initial_cipher_size)
        .map(|(combined_rem, _)| combined_rem)
        .unwrap()
        .add(1);

    // PART 2:
    // Now, we'll detect the exact block count of the prefix. Keep in mind if
    // we've overfilled, we'll be counting that block of As as well.
    // The idea is simple - have two unaligned ciphers, for the blocks that
    // match, they're part of the prefix, where they don't is the location we've
    // tampered with. For the first block, we'll just use our padding:
    // [prefix_abcdefAAA] [AAAAAsuffix_mnop]
    // And for the second one, we'll expand the controlled text with 1 block:
    // [prefix_abcdefAAA] [AAAAAAAAAAAAAAAA] [AAAAAsuffix_mnop]
    // Here's how it would look for overfilled blocks if you're curious:
    // [abcdefghijklmnoA] [AAAAAAAAAAAAAAAA] [Axyzwvutsrqponml]
    // [abcdefghijklmnoA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA] [Axyzwvutsrqponml]
    // ^^ Notice how we have 2 common prefix blocks instead of 1.
    // Another assumption is that our fill-in string isn't the prefix or suffix.
    // If we wanted to be completely accurate, we would have to repeat the
    // experiment with at least 3 different filler bytes but for simplicity
    // let's just assume the secret isn't just a blob of As.
    // Why 3 you ask? Well, with 2 if the prefix is 17 As we'd get 2 different
    // results for As, Bs as fillers. We'd need a third tie-breaker. Then we
    // choose the duplicate result.

    let cipher = insecure_fn(&b"A".repeat(combined_rem));
    let cipher_extra_block = insecure_fn(&b"A".repeat(combined_rem + 16));
    assert_eq!(cipher_extra_block.len(), cipher.len() + 16);

    let common_prefix_blocks = cipher
        .iter()
        .zip(cipher_extra_block.iter())
        .enumerate()
        .step_by(16)
        .map(|(i, _)| {
            (
                cipher[i..i + 16].as_u128().unwrap(),
                cipher_extra_block[i..i + 16].as_u128().unwrap(),
            )
        })
        .take_while(|(true_block, user_block)| true_block == user_block)
        .count();

    // PART 3:
    // Now that we know the exact prefix blocks count (and know where to look),
    // we can bruteforce the exact padding by changing the filler text & looking
    // duplicate blocks:
    // 0 yes [prefix_abcdefAAA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA]
    // 1 yes [prefix_abcdefBAA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA]
    // 2 yes [prefix_abcdefBBA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA]
    // 3 yes [prefix_abcdefBBB] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA]
    // 4 no  [prefix_abcdefBBB] [BAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA]
    // The first `no` match between the two blocks we get, is when we overflowed
    // the prefix. The last `yes` is when we exactly padded the prefix.
    // To be sure we'd get at least 2 duplicate blocks,
    // we need to use >= 32 + max_prefix_padding = 32 + 32 = 64
    // For overfilled blocks we'll match the overfill
    // 00 yes [xAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA]
    // 01 yes [xBAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA]
    // 02 yes [xBBAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA]
    // 03 yes [xBBBAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA]
    // 31 yes [xBBBBBBBBBBBBBBB] [BBBBBBBBBBBBBBBB] [AAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA]
    // 32 no  [xBBBBBBBBBBBBBBB] [BBBBBBBBBBBBBBBB] [BAAAAAAAAAAAAAAA] [AAAAAAAAAAAAAAAA]
    //                the blocks we're comparing     ^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^

    let prefix_padding_len = (0..=33)
        .map(|i| [b"B".repeat(i), b"A".repeat(64)].concat())
        .map(|plaintext| insecure_fn(&plaintext))
        .map(|cipher| {
            cipher
                .into_iter()
                .skip(common_prefix_blocks * 16)
                .take(32)
                .collect()
        })
        .map(|data: Vec<_>| (data[..16].as_u128().unwrap(), data[16..].as_u128().unwrap()))
        .enumerate()
        .find(|(_, (block1, block2))| block1 != block2)
        .map(|(i, _)| i)
        .unwrap()
        .sub(1);
    // // for debugging only
    // .checked_sub(1).expect("Failed to detect exact prefix padding");

    let prefix_len = common_prefix_blocks * 16 - prefix_padding_len;
    let suffix_len = (cipher.len() - 16) - prefix_len - combined_rem;
    (prefix_len, suffix_len)
}

#[test]
fn test_affix_lens_detection() {
    let vuln_fn_generator = |prefix_len: usize, suffix_len: usize| {
        let mut rng = rand::rngs::StdRng::from_seed([23; 32]);
        let key = rng.gen(); // random key
        move |plaintext: &[u8]| {
            let prefix = b"X".repeat(prefix_len);
            let suffix = b"Y".repeat(suffix_len);

            let data = {
                let size_hint = prefix.len() + plaintext.len() + suffix.len();
                let mut data = Vec::with_capacity(size_hint + 16);
                data.extend_from_slice(&prefix);
                data.extend_from_slice(plaintext);
                data.extend_from_slice(&suffix);
                pkcs7_pad(&data)
            };

            aes128_ecb_encrypt(&key, &data)
        }
    };

    for prefix_len in 0..32 {
        for suffix_len in 0..32 {
            let vuln_function = vuln_fn_generator(prefix_len, suffix_len);
            assert_eq!(detect_affix_lens(vuln_function), (prefix_len, suffix_len));
        }
    }
}

#[test]
fn challange14() {
    assert_eq!(detect_block_size(ecb_random_prefixed), 16);
    assert_eq!(
        detection_oracle(&ecb_random_prefixed(&b"0".repeat(64))),
        Mode::ECB
    );
    let (prefix_len, suffix_len) = detect_affix_lens(ecb_random_prefixed);
    assert_eq!(prefix_len, 85); // consistent due to seed
    assert_eq!(suffix_len, 138); // secret length is 138
    let prefix_padding = 16 - (prefix_len % 16);
    let prefix_block_count = (prefix_len + prefix_padding) / 16;

    let mut known_plaintext: Vec<u8> = Vec::new();
    while known_plaintext.len() != suffix_len {
        let block_id = prefix_block_count + known_plaintext.len() / 16;
        let fill_len = 15 - (known_plaintext.len() % 16);
        let mut msg = b"A".repeat(prefix_padding);
        msg.extend_from_slice(&b"A".repeat(fill_len));
        msg.extend_from_slice(&known_plaintext);

        // leaks the 1 byte that is the prefix of the suffix
        let truth_cipher = ecb_random_prefixed(&msg[..(prefix_padding + fill_len)]);
        let true_hash = get_nth_block(&truth_cipher, block_id);

        let possible_bytes: Vec<_> = (0x00..=0xff)
            .map(|byte| {
                msg.push(byte);
                let search_cipher = ecb_random_prefixed(&msg);
                let search_hash = get_nth_block(&search_cipher, block_id);
                msg.pop();
                (byte, search_hash)
            })
            .filter(|&(_, search_hash)| search_hash == true_hash)
            .map(|(byte, _)| byte)
            .collect();

        assert_eq!(possible_bytes.len(), 1);
        known_plaintext.push(possible_bytes[0]);
    }

    assert_eq!(known_plaintext, base64_to_raw(SECRET));
}

#[test]
fn challange15() {
    assert_eq!(
        pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04"),
        Some(b"ICE ICE BABY".to_vec())
    );
    assert_eq!(pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05"), None);
    assert_eq!(pkcs7_unpad(b"ICE ICE BABY\x05\x04\x04\x04"), None);
    assert_eq!(
        pkcs7_unpad(&pkcs7_pad(&b"A".repeat(16))),
        Some(b"A".repeat(16))
    );
}

// vulnerable function
fn encrypt_user_data(user_data: &[u8]) -> Vec<u8> {
    // only for consistency (not actually required to use a seed)
    let mut rng = rand::rngs::StdRng::from_seed([29; 32]);
    let key = rng.gen();
    let iv: [u8; 16] = rng.gen();

    let prefix = b"comment1=cooking%20MCs;userdata=";
    let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";

    let escaped_user_data: Vec<_> = user_data
        .iter()
        .map(|&byte| {
            if b";&=%".contains(&byte) {
                [vec![b'%'], raw_to_hex(&[byte])]
                    .into_iter()
                    .flatten()
                    .collect()
            } else {
                vec![byte]
            }
        })
        .flatten()
        .collect();

    let data = {
        let size_hint = prefix.len() + escaped_user_data.len() + suffix.len();
        let mut data = Vec::with_capacity(size_hint + 16);
        data.extend_from_slice(prefix);
        data.extend_from_slice(&escaped_user_data);
        data.extend_from_slice(suffix);
        pkcs7_pad(&data)
    };

    aes128_cbc_encrypt(&key, &iv, &data)
}

// helper function
fn decrypt_user_data(ciphertext: &[u8]) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::from_seed([29; 32]);
    let key = rng.gen();
    let iv: [u8; 16] = rng.gen();
    let raw = aes128_cbc_decrypt(&key, &iv, ciphertext);
    pkcs7_unpad(&raw).unwrap()
}

#[test]
fn test_user_data_is_escaped() {
    let encrypted = encrypt_user_data(b";admin=true;");
    let decrypted = decrypt_user_data(&encrypted);
    assert_eq!(decrypted, b"comment1=cooking%20MCs;userdata=%3badmin%3dtrue%3b;comment2=%20like%20a%20pound%20of%20bacon");
}

fn check_is_admin(ciphertext: &[u8]) -> bool {
    let decrypted = decrypt_user_data(ciphertext);
    let s = String::from_utf8_lossy(&decrypted);
    s.find(";admin=true;").is_some()
}

#[test]
fn test_user_is_not_admin() {
    let encrypted = encrypt_user_data(b";admin=true;");
    assert_eq!(check_is_admin(&encrypted), false);
}

#[test]
fn challange16() {
    // BRIEF:
    // The description is clear, if we flip two carefully positioned bits in the
    // ciphertext, when decoding, the xor will flip two bits in the same
    // relative positions the next block's decoded plaintext. All we need to do
    // is find a close hamming distance replacement & bruteforce the padding.

    // PART 1:
    // To create the perfect replacement string, we shall acquire hamming
    // distance neighbors of the restricted characters + their indices in our
    // desired string.

    let desired_plaintext = b";admin=true;";
    let restricted_bytes = b";&=%";
    let modifiers = restricted_bytes
        .iter()
        .map(|&byte| {
            byte ^ (0x00..=0xff)
                .filter(|x: &u8| x.is_ascii_alphanumeric()) // just to be sleek
                .map(|replacement_byte| {
                    (
                        replacement_byte,
                        hamming_distance(&[replacement_byte], &[byte]),
                    )
                })
                .min_by_key(|&(_, distance)| distance)
                .map(|(b, _)| b)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let malicious_plaintext = desired_plaintext
        .iter()
        .map(|&byte| {
            restricted_bytes
                .iter()
                .position(|&disallowed_byte| disallowed_byte == byte)
                .map(|i| byte ^ modifiers[i])
                .unwrap_or(byte)
        })
        .collect::<Vec<_>>();
    let modifier = {
        let mut xor_string = xor(&malicious_plaintext, desired_plaintext);
        let pad_len = 16 - (xor_string.len() % 16);
        xor_string.extend_from_slice(&b"A".repeat(pad_len));
        xor_string
    };

    // PART 2:
    // Unlike ECB we can't get the exact prefix len. We only need to know the
    // last block's location though, and then we can bruteforce the exact
    // padding.

    let vulnerable_block_id = {
        let cipher = encrypt_user_data(b"");
        let cipher_extra_block = encrypt_user_data(&b"A".repeat(16));
        assert_eq!(cipher_extra_block.len(), cipher.len() + 16);
        cipher
            .iter()
            .zip(cipher_extra_block.iter())
            .enumerate()
            .step_by(16)
            .map(|(i, _)| {
                (
                    cipher[i..i + 16].as_u128().unwrap(),
                    cipher_extra_block[i..i + 16].as_u128().unwrap(),
                )
            })
            .position(|(true_block, user_block)| true_block != user_block)
            .unwrap()
            .sub(1) // we want the block before the block we control
    };

    // PART 3:
    // Now we need to bruteforce all possible paddings, attempting the attack
    // for each one (applying the modifier at the specified location) until
    // we're granted access

    let modify_cipher = |ciphertext: Vec<u8>| {
        let vulnerable_block = get_nth_block(&ciphertext, vulnerable_block_id).to_be_bytes();
        let modified_block = xor(&vulnerable_block, &modifier);
        ciphertext
            .iter()
            .enumerate()
            .map(|(i, &byte)| {
                if i < vulnerable_block_id * 16 || i >= (vulnerable_block_id + 1) * 16 {
                    byte
                } else {
                    modified_block[i - vulnerable_block_id * 16]
                }
            })
            .collect::<Vec<_>>()
    };
    let padding_len = (0..16)
        .map(|i| b"A".repeat(i))
        .map(|padding| [padding.as_slice(), &malicious_plaintext].concat())
        .map(|plaintext| encrypt_user_data(&plaintext))
        .map(modify_cipher)
        .position(|ciphertext| check_is_admin(&ciphertext))
        .unwrap();
    let malicious_plaintext = [b"A".repeat(padding_len), malicious_plaintext].concat();
    let ciphertext = encrypt_user_data(&malicious_plaintext);
    let malicious_ciphertext = modify_cipher(ciphertext);

    assert_eq!(check_is_admin(&malicious_ciphertext), true);
}
