use openssl::symm::{Cipher, encrypt, decrypt};
pub fn aes128_ecb_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    encrypt(Cipher::aes_128_ecb(), key, None, data).unwrap()
}

pub fn aes128_ecb_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    decrypt(Cipher::aes_128_ecb(), key, None, data).unwrap()
}

pub fn pkcs7_pad(data: &[u8], to_size: usize) -> Vec<u8> {
    assert!(data.len() <= to_size && to_size - data.len() <= usize::from(u8::MAX));
    let mut output = data.to_vec();
    let pad = u8::try_from(to_size - data.len()).unwrap();
    output.extend([pad].iter().cycle().take(usize::from(pad)));
    output
}
