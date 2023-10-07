pub fn hex_to_raw(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex string is not byte aligned");
    input
        .bytes()
        .enumerate()
        .step_by(2)
        .map(|(i, _)| u8::from_str_radix(&input[i..i + 2], 16).expect("string is not valid hex"))
        .collect()
}

pub fn raw_to_hex(buf: &[u8]) -> Vec<u8> {
    buf
        .iter()
        .map(|byte| format!("{byte:x}").as_bytes().to_owned())
        .flatten()
        .collect()
}

pub fn raw_to_base64(buf: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(4 * buf.len() / 3);
    let mut it = buf.iter();
    loop {
        match (it.next(), it.next(), it.next()) {
            (Some(a), Some(b), Some(c)) => {
                output.push(a >> 2);
                output.push(((a & 0x03) << 4) | (b >> 4));
                output.push(((b & 0x0f) << 2) | (c >> 6));
                output.push(c & 0x3f);
            }
            (Some(a), Some(b), None) => {
                output.push(a >> 2);
                output.push(((a & 0x03) << 4) | (b >> 4));
                output.push((b & 0x0f) << 2);
            }
            (Some(a), None, None) => {
                output.push(a >> 2);
                output.push((a & 0x03) << 4);
            }
            _ => break,
        }
    }

    for byte in output.iter_mut() {
        *byte = match *byte {
            62 => b'+',
            63 => b'/',
            0..=25 => *byte + b'A',
            26..=51 => *byte - 26 + b'a',
            _ => *byte - 52 + b'0',
        };
    }
    let rem = (3 - buf.len() % 3) % 3;
    for _ in 0..rem {
        output.push(b'=');
    }
    output
}

pub fn base64_to_raw(input: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(3 * input.len() / 4);
    let mut chars = input
        .bytes()
        .filter(|&byte| {
            byte.is_ascii_alphanumeric() || byte == b'=' || byte == b'+' || byte == b'/'
        })
        .map(|byte| match byte {
            b'+' => 62,
            b'/' => 63,
            b'=' => 64,
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            _ => 64,
        });

    loop {
        let (Some(a), Some(b), Some(c), Some(d)) =
            (chars.next(), chars.next(), chars.next(), chars.next())
        else {
            break;
        };
        let mut buf = (u32::from(a) << 6) | u32::from(b);
        if c == 64 {
            output.push(u8::try_from(buf >> 4).unwrap());
            break;
        }
        buf = (buf << 6) | u32::from(c);
        if d == 64 {
            output.extend(u16::try_from(buf >> 2).unwrap().to_be_bytes());
            break;
        }
        buf = (buf << 6) | u32::from(d);
        output.extend(&buf.to_be_bytes()[1..]);
    }
    output
}

pub fn hex_to_base64(buf: &str) -> Vec<u8> {
    raw_to_base64(&hex_to_raw(buf))
}

pub fn base64_to_hex(_input: &str) -> Vec<u8> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_hex_to_raw() {
        assert_eq!(hex_to_raw("74657374"), vec![0x74, 0x65, 0x73, 0x74]);
    }

    #[test]
    fn convert_raw_to_base64() {
        assert_eq!(raw_to_base64(&[0x31]), b"MQ==");
        assert_eq!(raw_to_base64(&[0x31, 0x32]), b"MTI=");
        assert_eq!(raw_to_base64(&[0x31, 0x32, 0x33]), b"MTIz");
        assert_eq!(raw_to_base64(&[0x31, 0x32, 0x33, 0x34]), b"MTIzNA==");
    }

    #[test]
    fn convert_base64_to_raw() {
        assert_eq!(base64_to_raw("MQ=="), [0x31]);
        assert_eq!(base64_to_raw("MTI="), [0x31, 0x32]);
        assert_eq!(base64_to_raw("MTIz"), [0x31, 0x32, 0x33]);
        assert_eq!(base64_to_raw("MTIzNA=="), [0x31, 0x32, 0x33, 0x34]);
        assert_eq!(base64_to_raw("MTIzND=="), [0x31, 0x32, 0x33, 0x34]);
    }

    #[test]
    fn convert_raw_to_hex() {
        assert_eq!(raw_to_hex(&[0x65]), b"65");
        assert_eq!(raw_to_hex(&[0x65, 0x66]), b"6566");
        assert_eq!(raw_to_hex(&[0x65, 0x66, 0x67]), b"656667");
    }

    // TODO: convert hex_to_base64
    // TODO: convert base64_to_base64

    // Roundtrip tests:

    // TODO: Add roundtrip tests for hex_to_raw & raw_to_hex
    // TODO: Add roundtrip tests for hex_to_base64 & base74_to_hex

    #[test]
    fn convert_raw_to_base64_to_raw() {
        let input = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        let base64 = raw_to_base64(input);
        let output = base64_to_raw(std::str::from_utf8(&base64).unwrap());
        assert_eq!(output, input);
    }

    #[test]
    fn convert_base64_to_raw_to_base64() {
        let input = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4=";
        let raw = base64_to_raw(input);
        let output = &raw_to_base64(&raw);
        assert_eq!(output, input.as_bytes());
    }
}
