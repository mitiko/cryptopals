use openssl::cipher;

use crate::{cbc::*, ctr::{aes128_ctr_encrypt, aes128_ctr_iteration}, ecb::*, utils::conversions::raw_to_hex};

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
    let data = b"YELLOW SUBMARINE";
    let (nonce, counter) = (3 << 32, 1);
    let ciphertext = aes128_ctr_iteration(data, nonce, counter);
    assert_eq!(raw_to_hex(&ciphertext), b"e31586e966489ee7798d973b8abc013");

    let data = b"YELLOW SUBMA";
    let ciphertext = aes128_ctr_iteration(data, nonce, counter);
    assert_eq!(raw_to_hex(&ciphertext), b"4fc4b37bc4adddd870a144a8");
}

#[test]
#[should_panic]
fn aes128_ctr_single_iteration_large() {
    aes128_ctr_iteration(b"0123456789abcdefX", 0, 0);
}

#[test]
fn aes128_ctr_multi_iteration() {
    let data = b"YELLOW SUBMARINE AND MORE";
    let (nonce, counter) = (3 << 32, 33);
    let ciphertext = aes128_ctr_encrypt(data, nonce, counter);
    assert_eq!(raw_to_hex(&ciphertext), b"8c246596274686eda0d039e6ad2f1f3763d32ebac2d3318");
}
