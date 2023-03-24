use super::utils::*;

#[test]
fn challange9() {
    let input = b"YELLOW SUBMARINE";
    let output = b"YELLOW SUBMARINE\x04\x04\x04\x04";
    assert_eq!(pkcs7_pad(input, 20), output);
}

