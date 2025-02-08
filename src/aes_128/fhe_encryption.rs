use crate::aes_128::fhe::data_model::{Byte, Word};
use crate::aes_128::plain;
use crate::tfhe::ClientKeyT;
use crate::util;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use tfhe::core_crypto::entities::Cleartext;

pub fn fhe_encrypt_word_array<const N: usize, Bit: Send + Sync, CK: ClientKeyT<Bit> + Sync>(
    client_key: &CK,
    array: &[plain::data_model::Word; N],
) -> [Word<Bit>; N] {
    util::par_collect_array(
        array
            .par_iter()
            .map(|word| Word::new(fhe_encrypt_byte_array(client_key, &word.0))),
    )
}

pub fn fhe_encrypt_byte_array<const N: usize, Bit: Send + Sync, CK: ClientKeyT<Bit> + Sync>(
    client_key: &CK,
    array: &[u8; N],
) -> [Byte<Bit>; N] {
    util::par_collect_array(
        array
            .par_iter()
            .map(|&byte| fhe_encrypt_byte(client_key, byte)),
    )
}

pub fn fhe_encrypt_byte<Bit: Send + Sync, CK: ClientKeyT<Bit> + Sync>(
    client_key: &CK,
    byte: u8,
) -> Byte<Bit> {
    Byte::new(util::par_collect_array(
        util::byte_to_bits(byte).map(|b| client_key.encrypt(Cleartext(b as u64))),
    ))
}

pub fn fhe_decrypt_word_array<const N: usize, Bit: Send + Sync, CK: ClientKeyT<Bit> + Sync>(
    client_key: &CK,
    array: &[Word<Bit>; N],
) -> [plain::data_model::Word; N] {
    util::par_collect_array(
        array
            .par_iter()
            .map(|word| plain::data_model::Word(fhe_decrypt_byte_array(client_key, &word.0))),
    )
}

pub fn fhe_decrypt_byte_array<const N: usize, Bit: Send + Sync, CK: ClientKeyT<Bit> + Sync>(
    client_key: &CK,
    array: &[Byte<Bit>; N],
) -> [u8; N] {
    util::par_collect_array(
        array
            .par_iter()
            .map(|byte| fhe_decrypt_byte(client_key, byte)),
    )
}

pub fn fhe_decrypt_byte<Bit: Send + Sync, CK: ClientKeyT<Bit> + Sync>(
    client_key: &CK,
    byte: &Byte<Bit>,
) -> u8 {
    util::bits_to_byte(byte.bits().map(|bit| client_key.decrypt(bit).0 as u8))
}
