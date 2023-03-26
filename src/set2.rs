use crate::utils::io::*;
use crate::{ecb::*, cbc::*};

#[test]
fn challange9() {
    let input = b"YELLOW SUBMARINE";
    let output = b"YELLOW SUBMARINE\x04\x04\x04\x04";
    assert_eq!(pkcs7_pad(input, 20), output);
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
