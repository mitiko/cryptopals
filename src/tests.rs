use super::utils::*;

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
    let input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.".as_bytes();
    let base64 = raw_to_base64(input);
    assert_eq!(base64_to_raw(std::str::from_utf8(&base64).unwrap()), input);
}

#[test]
fn convert_base64_to_raw_to_base64() {
    let input = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4=";
    let raw = base64_to_raw(input);
    assert_eq!(std::str::from_utf8(&raw_to_base64(&raw)).unwrap(), input);
}
