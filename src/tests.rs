use crate::utils::conversions::*;
use crate::{xor::*, ecb::*, cbc::*};

#[test]
fn convert_hex_to_raw() {
    let input = "74657374";
    let output = vec![0x74, 0x65, 0x73, 0x74];
    assert_eq!(hex_to_raw(input), output);
}

#[test]
fn convert_raw_to_base64() {
    let input = &[0x74, 0x65, 0x73, 0x74];
    let output = "dGVzdA==";
    assert_eq!(raw_to_base64(input), output.as_bytes());
}

#[test]
fn convert_base64_to_raw() {
    let inputs = ["MQ==", "MTI=", "MTIz", "MTIzNDU2Nw=="];
    assert_eq!(base64_to_raw(inputs[0]), [0x31]);
    assert_eq!(base64_to_raw(inputs[1]), [0x31, 0x32]);
    assert_eq!(base64_to_raw(inputs[2]), [0x31, 0x32, 0x33]);
    assert_eq!(base64_to_raw(inputs[3]), [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37]);
}

#[test]
fn convert_raw_to_base64_to_raw() {
    let input = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
    let base64 = raw_to_base64(input);
    assert_eq!(base64_to_raw(std::str::from_utf8(&base64).unwrap()), input);
}

#[test]
fn convert_base64_to_raw_to_base64() {
    let input = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4=";
    let raw = base64_to_raw(input);
    assert_eq!(std::str::from_utf8(&raw_to_base64(&raw)).unwrap(), input);
}

#[test]
fn hamming_distance_test() {
    let start = b"this is a test";
    let end = b"wokka wokka!!!";
    assert_eq!(hamming_distance(start, end), 37);
}

#[test]
fn xor_test() {
    let a = [0x0f, 0xf0, 0x55, 0x13];
    let b = [0x0f, 0x0f, 0xaa, 0xa7];
    assert_eq!(xor(&a, &b), [0x00, 0xff, 0xff, 0xb4]);
}

#[test]
fn xor_uneven_test() {
    let a = [0x0f, 0xf0, 0x55, 0x13, 0xde, 0xad, 0xbe, 0xef];
    let b = [0x0f, 0x0f, 0xaa, 0xa7];
    assert_eq!(xor(&a, &b), [0x00, 0xff, 0xff, 0xb4]);
}

#[test]
fn xor_rep_test() {
    let data = [0x0f, 0xf0, 0x55, 0x13, 0xde, 0xad, 0xbe, 0xef];
    let key  = [0xbb, 0x71, 0xa2]; // chosen randomly
    assert_eq!(xor_rep(&data, &key), [0xb4, 0x81, 0xf7, 0xa8, 0xaf, 0xf, 0x5, 0x9e]);
}

#[test]
fn xor_rep_long_key() {
    let data = [0x0f, 0xf0, 0x55];
    let key = [0xbb, 0x71, 0xa2, 0x25];
    assert_eq!(xor_rep(&data, &key), [0xb4, 0x81, 0xf7]);
}

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
