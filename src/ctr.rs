use crate::{
    ecb::{aes128_ecb_encrypt, zero_pad},
    xor::xor,
};

pub fn aes128_ctr_iteration(plaintext_block: &[u8], nonce: u64, counter: u64) -> Vec<u8> {
    assert!(plaintext_block.len() <= 16);
    let key = (u128::from(counter) << 64 | u128::from(nonce)).to_le_bytes();
    let data = zero_pad(plaintext_block);
    let iteration_block = aes128_ecb_encrypt(&key.try_into().unwrap(), &data);
    xor(&iteration_block, plaintext_block)
}

pub fn aes128_ctr_encrypt(data: &[u8], nonce: u64, start_counter: u64) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    for (offset, block) in data.chunks(16).enumerate() {
        let counter = start_counter.wrapping_add(u64::try_from(offset).unwrap());
        let plaintext_block = block.try_into().unwrap();
        let ciphertext_block = aes128_ctr_iteration(plaintext_block, nonce, counter);
        output.extend(ciphertext_block);
    }
    output
}
