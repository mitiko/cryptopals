use crate::{cbc::*, ctr::{aes128_ctr_decrypt, aes128_ctr_encrypt, aes128_ctr_iteration}, ecb::*, utils::conversions::raw_to_hex};

#[test]
fn aes128_ecb_encrypt_decrypt() {
    let data = pkcs7_pad(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.");
    let key = b"YELLOW SUBMARINE";
    let ciphertext = aes128_ecb_encrypt(key, &data);
    assert_eq!(aes128_ecb_decrypt(key, &ciphertext), data);
}

#[test]
fn pkcs7_exact() {
    let input = b"YELLOW SUBMARINE";
    let output = b"YELLOW SUBMARINE\x05\x05\x05\x05\x05";
    assert_eq!(pkcs7_pad_to(16, input), input);
    assert_eq!(pkcs7_pad_to(21, input), output);
}

#[test]
fn pkcs7_auto() {
    let input_aligned = b"YELLOW SUBMARINE";
    let input_not_aligned = b"YELLOW SUBMARINE111";
    assert_eq!(pkcs7_pad(input_aligned), b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10");
    assert_eq!(pkcs7_pad(input_not_aligned), b"YELLOW SUBMARINE111\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d");
}

#[test]
fn pcks7_unpad_test() {
    assert_eq!(pkcs7_unpad(b"YELLOW SUBMARIN\x01"), Some(b"YELLOW SUBMARIN".to_vec()));
    assert_eq!(pkcs7_unpad(b"YELLOW SUBMARI\x02\x02"), Some(b"YELLOW SUBMARI".to_vec()));
    assert_eq!(pkcs7_unpad(b"YELLOW SUBMAR\x03\x03\x03"), Some(b"YELLOW SUBMAR".to_vec()));
    assert_eq!(pkcs7_unpad(b"YELLOW SUBMAR\x01\x01\x01"), Some(b"YELLOW SUBMAR\x01\x01".to_vec()));
    assert_eq!(pkcs7_unpad(b"YELLOW SUBMARIN\x03\x03"), None);
    assert_eq!(pkcs7_unpad(b"YELLOW SUBMARIN\x00"), None);
}

#[test]
fn aes128_cbc_encrypt_matches_openssl() {
    let data = pkcs7_pad(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.");
    let key = b"YELLOW SUBMARINE";
    let iv = b"\x00\x00\x00";
    let openssl_iv = &iv.repeat(16)[..16];
    let cipher = openssl::symm::Cipher::aes_128_cbc();
    let output = openssl::symm::encrypt(cipher, key, Some(openssl_iv), &data).unwrap();
    assert_eq!(aes128_cbc_encrypt(key, iv, &data), &output[..64]); // openssl autopads
}

#[test]
fn aes128_cbc_encrypt_decrypt() {
    let data = pkcs7_pad(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.");
    let key = b"YELLOW SUBMARINE";
    let iv = b"\x00\x00\x00";
    let ciphertext = aes128_cbc_encrypt(key, iv, &data);
    assert_eq!(aes128_cbc_decrypt(key, iv, &ciphertext), data);
}

#[test]
fn aes128_ctr_single_iteration() {
    let key = b"YELLOW SUBMARINE";
    let (nonce, counter) = (3 << 32, 1);
    let data = b"Lorem ipsum dolo";
    let ciphertext = aes128_ctr_iteration(data, key, nonce, counter);
    assert_eq!(raw_to_hex(&ciphertext), b"1070a4d8142593df4fa3ada7901c98a7");

    let data = b"Lorem ipsum";
    let ciphertext = aes128_ctr_iteration(data, key, nonce, counter);
    assert_eq!(raw_to_hex(&ciphertext), b"1070a4d8142593df4fa3ad");
}

#[test]
#[should_panic]
fn aes128_ctr_single_iteration_large() {
    // over 16 bytes in one iteration panics
    aes128_ctr_iteration(b"0123456789abcdefX", b"YELLOW SUBMARINE", 0, 0);
}

#[test]
fn aes128_ctr_multi_iteration() {
    let key = b"YELLOW SUBMARINE";
    let data = b"Lorem ipsum dolor sit amet";
    let (nonce, counter) = (3 << 32, 33);
    let ciphertext = aes128_ctr_encrypt(data, key, nonce, counter);
    assert_eq!(raw_to_hex(&ciphertext), b"cd5e958ee26928926bd28c8e105b9917c16b495a880e372726d");
}

#[test]
fn aes128_ctr_multi_decrypt() {
    let key = b"YELLOW SUBMARINE";
    let data = b"Lorem ipsum dolor sit amet";
    let (nonce, counter) = (3 << 32, 33);
    let ciphertext = aes128_ctr_encrypt(data, key, nonce, counter);
    assert_eq!(aes128_ctr_decrypt(&ciphertext, key, nonce, counter), data);
}
