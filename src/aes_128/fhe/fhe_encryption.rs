use crate::aes_128::fhe::data_model::{Block, Byte, Word};
use crate::aes_128::plain;
use crate::tfhe::ClientKeyT;
use crate::{aes_128, util};
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use tfhe::core_crypto::entities::Cleartext;

pub fn encrypt_blocks<CK: ClientKeyT>(
    client_key: &CK,
    blocks: &[aes_128::Block],
) -> Vec<Block<CK::Bit>> {
    blocks
        .par_iter()
        .map(|block| encrypt_byte_array(client_key, block))
        .collect()
}

pub fn encrypt_word_array<const N: usize, CK: ClientKeyT>(
    client_key: &CK,
    array: &[plain::data_model::Word; N],
) -> [Word<CK::Bit>; N] {
    array.map(|word| Word::new(encrypt_byte_array(client_key, &word.0)))
}

pub fn encrypt_byte_array<const N: usize, CK: ClientKeyT>(
    client_key: &CK,
    array: &[u8; N],
) -> [Byte<CK::Bit>; N] {
    array.map(|byte| encrypt_byte(client_key, byte))
}

pub fn encrypt_byte<CK: ClientKeyT>(client_key: &CK, byte: u8) -> Byte<CK::Bit> {
    Byte::new(util::byte_to_bits(byte).map(|b| client_key.encrypt(Cleartext(b as u64))))
}

pub fn decrypt_blocks<CK: ClientKeyT>(
    client_key: &CK,
    blocks: &[Block<CK::Bit>],
) -> Vec<aes_128::Block> {
    blocks
        .par_iter()
        .map(|block| decrypt_byte_array(client_key, block))
        .collect()
}

pub fn decrypt_word_array<const N: usize, CK: ClientKeyT>(
    client_key: &CK,
    array: &[Word<CK::Bit>; N],
) -> [plain::data_model::Word; N] {
    array
        .each_ref()
        .map(|word| plain::data_model::Word(decrypt_byte_array(client_key, &word.0)))
}

pub fn decrypt_byte_array<const N: usize, CK: ClientKeyT>(
    client_key: &CK,
    array: &[Byte<CK::Bit>; N],
) -> [u8; N] {
    array.each_ref().map(|byte| decrypt_byte(client_key, byte))
}

pub fn decrypt_byte<CK: ClientKeyT>(client_key: &CK, byte: &Byte<CK::Bit>) -> u8 {
    util::bits_to_byte(byte.0.each_ref().map(|bit| client_key.decrypt(bit).0 as u8))
}
