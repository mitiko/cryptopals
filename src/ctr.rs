use crate::{
    ecb::aes128_ecb_encrypt,
    xor::xor,
};

pub fn aes128_ctr_iteration(plaintext_block: &[u8], key: &[u8; 16], nonce: u64, counter: u64) -> Vec<u8> {
    assert!(plaintext_block.len() <= 16);
    let iv_cntr_pair = [nonce.to_le_bytes(), counter.to_le_bytes()].concat();
    let iteration_block = aes128_ecb_encrypt(key, &iv_cntr_pair);
    xor(&iteration_block, plaintext_block)
}

pub fn aes128_ctr_encrypt(data: &[u8], key: &[u8; 16], nonce: u64, start_counter: u64) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    for (offset, block) in data.chunks(16).enumerate() {
        let counter = start_counter.wrapping_add(u64::try_from(offset).unwrap());
        let ciphertext_block = aes128_ctr_iteration(block, key, nonce, counter);
        output.extend(ciphertext_block);
    }
    output
}

pub fn aes128_ctr_decrypt(ciphertext: &[u8], key: &[u8; 16], nonce: u64, start_counter: u64) -> Vec<u8> {
    aes128_ctr_encrypt(ciphertext, key, nonce, start_counter)
}
