use super::*;

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
