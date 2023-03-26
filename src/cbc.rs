use crate::{xor::*, ecb::*};

/// Panics if plaintext is not 16-byte aligned
pub fn aes128_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    assert!(data.len() % 16 == 0);
    let mut output: Vec<u8> = Vec::with_capacity(data.len());
    output.extend(aes128_ecb_encrypt(key, &xor_rep(&data[..16], iv)));
    for (i, block) in data.chunks(16).enumerate().skip(1) {
        let block = pkcs7_pad(block, 16);
        let prev_block = &output[(i-1)*16..i*16];
        output.extend(aes128_ecb_encrypt(key, &xor(prev_block, &block)));
    }
    output
}

pub fn aes128_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    assert!(data.len() % 16 == 0);
    let mut output: Vec<u8> = Vec::with_capacity(data.len());
    output.extend(xor_rep(&aes128_ecb_decrypt(key, &data[..16]), iv));
    for (prev_block, block) in data.chunks(16).zip(data.chunks(16).skip(1)) {
        output.extend(xor(&aes128_ecb_decrypt(key, &block), &prev_block));
    }
    output
}
