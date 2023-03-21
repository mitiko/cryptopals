use super::*;

#[test]
fn challange1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(hex_to_base64(input), output.as_bytes());
}

#[test]
fn challange2() {
    let a = "1c0111001f010100061a024b53535009181c";
    let b = "686974207468652062756c6c277320657965";
    let output = "746865206b696420646f6e277420706c6179";
    assert_eq!(xor(&hex_to_raw(a), &hex_to_raw(b)), hex_to_raw(output));
}
