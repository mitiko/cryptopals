pub fn hex_to_raw(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex string is not byte aligned");
    input.bytes()
        .enumerate().step_by(2)
        .map(|(i, _)| u8::from_str_radix(&input[i..i+2], 16).expect("string is not valid hex"))
        .collect()
}

pub fn raw_to_base64(buf: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(4 * buf.len() / 3);
    let rem = (3 - buf.len() % 3) % 3;
    let mut it = buf.iter();
    loop {
        match (it.next(), it.next(), it.next()) {
            (Some(a), Some(b), Some(c)) => {
                output.push(a >> 2);
                output.push(((a & 0x03) << 4) | (b >> 4));
                output.push(((b & 0x0f) << 2) | (c >> 6));
                output.push(c & 0x3f);
            },
            (Some(a), Some(b), None) => {
                output.push(a >> 2);
                output.push(((a & 0x03) << 4) | (b >> 4));
                output.push((b & 0x0f) << 2);
            },
            (Some(a), None, None) => {
                output.push(a >> 2);
                output.push((a & 0x03) << 4);
            },
            _ => break
        }
    }

    for byte in output.iter_mut() {
        *byte = match *byte {
            62 => b'+',
            63 => b'/',
            0..=25 => *byte + b'A',
            26..=51 => *byte - 26 + b'a',
            _ => *byte - 52 + b'0'
        };
    }
    for _ in 0..rem {
        output.push(b'=');
    }
    output
}

pub fn base64_to_raw(input: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(3 * input.len() / 4);
    let mut chars = input.bytes()
        .filter(|&byte|
            byte.is_ascii_alphanumeric() ||
            byte == b'=' || byte == b'+' || byte == b'/')
        .map(|byte| match byte {
            b'+' => 62,
            b'/' => 63,
            b'=' => 64,
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            _ => 64
        });

    loop {
        let (Some(a), Some(b), Some(c), Some(d)) = (chars.next(), chars.next(), chars.next(), chars.next()) else { break };
        let mut buf = (u32::from(a) << 6) | u32::from(b);
        if c == 64 { output.push(u8::try_from(buf >> 4).unwrap()); break; }
        buf = (buf << 6) | u32::from(c);
        if d == 64 { output.extend(u16::try_from(buf >> 2).unwrap().to_be_bytes()); break; }
        buf = (buf << 6) | u32::from(d);
        output.extend(&buf.to_be_bytes()[1..]);
    }
    output
}

pub fn hex_to_base64(buf: &str) -> Vec<u8> {
    raw_to_base64(&hex_to_raw(buf))
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(m, n)| m ^ n).collect()
}

pub fn xor_rep(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().zip(key.iter().cycle()).map(|(x, y)| x ^ y).collect()
}
