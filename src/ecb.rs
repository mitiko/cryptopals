use openssl::symm::{Cipher, Crypter, Mode};

#[derive(Debug)]
pub struct PlaintextNotAligned;

// https://www.rfc-editor.org/rfc/rfc5652#section-6.3
pub fn pkcs7_pad_to(to_size: usize, data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= to_size && to_size - data.len() <= usize::from(u8::MAX));
    let mut output = data.to_vec();
    let pad = u8::try_from(to_size - data.len()).unwrap();
    output.extend([pad].iter().cycle().take(usize::from(pad)));
    output
}

/// Pads to a block size of 16
pub fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let rem = 16 - (data.len() % 16);
    pkcs7_pad_to(data.len() + rem, data)
}

pub fn pkcs7_unpad(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() % 16 != 0 { return None; }
    let pad_byte = data.last().unwrap_or(&0xff).to_owned();
    if pad_byte > 0x10 { return None; }
    let pad_start = data.len() - usize::from(pad_byte);
    let unpadded = data[pad_start..].to_vec();
    if unpadded.iter().all(|&byte| byte == pad_byte)
    { Some(data[..pad_start].to_vec()) } else { None }
}

/// Panics if plaintext is not 16-byte aligned
pub fn aes128_ecb_encrypt(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    // openssl::symm::encrypt uses padding
    encrypt(Cipher::aes_128_ecb(), key, plaintext)
}

pub fn aes128_ecb_decrypt(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    // openssl::symm::decrypt uses padding
    decrypt(Cipher::aes_128_ecb(), key, ciphertext)
}

fn encrypt(cipher: Cipher, key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
    encrypter.pad(false);
    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let count = encrypter.update(plaintext, &mut ciphertext).unwrap();
    let rest = encrypter
        .finalize(&mut ciphertext[count..])
        .map_err(|_| PlaintextNotAligned)
        .unwrap();
    ciphertext.resize(count + rest, 0);
    ciphertext
}

fn decrypt(cipher: Cipher, key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut encrypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
    encrypter.pad(false);
    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let count = encrypter.update(ciphertext, &mut plaintext).unwrap();
    let rest = encrypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.resize(count + rest, 0);
    plaintext
}
