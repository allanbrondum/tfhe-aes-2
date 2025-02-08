use crate::aes_128::fhe::data_model::{Block, Byte, ByteT, Word};
use crate::aes_128::{fhe, plain, Key, SBOX};
use crate::tfhe::shortint_woppbs_8bit::*;
use crate::{aes_128, util};
use rayon::iter::ParallelIterator;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator};
use std::sync::OnceLock;
use std::time::Instant;
use tfhe::core_crypto::entities::Cleartext;
use tfhe::shortint::wopbs::ShortintWopbsLUT;
use tracing::debug;

impl ByteT for Byte<BitCt> {
    fn bootstrap(&self) -> Self {
        let context = &self.bits().find_first(|_| true).unwrap().context;

        static IDENTITY_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();
        let lut = IDENTITY_LUT.get_or_init(|| IntByte::generate_lookup_table(context, |byte| byte));

        self.bootstrap_with_lut(lut)
    }

    fn aes_substitute(&self) -> Self {
        let context = &self.bits().find_first(|_| true).unwrap().context;

        static SBOX_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();
        let lut = SBOX_LUT.get_or_init(|| {
            IntByte::generate_lookup_table(context, |byte| SBOX[byte as usize].into())
        });

        self.bootstrap_with_lut(lut)
    }
}

impl Byte<BitCt> {
    fn bootstrap_with_lut(&self, lut: &ShortintWopbsLUT) -> Self {
        let start = Instant::now();
        let int_byte = IntByte::bootstrap_from_bits(&self, &lut);
        debug!("boot int {:?}", start.elapsed());

        let start = Instant::now();
        let byte = Byte::extract_bits_from_int_byte(&int_byte);
        debug!("extract bits {:?}", start.elapsed());

        byte
    }
}

pub fn expand_key_and_encrypt_blocks(
    key_clear: aes_128::Key,
    blocks_clear: &[aes_128::Block],
    rounds: usize,
) -> Vec<aes_128::Block> {
    debug!("start");

    // Client side: generate keys
    let (client_key, context) = FheContext::generate_keys();
    debug!("keys generated");

    // Client side: FHE encrypt AES key and block
    let key = fhe_encrypt_byte_array(&client_key, &key_clear);
    let blocks: Vec<_> = blocks_clear
        .iter()
        .map(|block| fhe_encrypt_byte_array(&client_key, &block))
        .collect();
    debug!("aes key and block encrypted");

    // Server side (optional): AES encrypt blocks
    let start = Instant::now();
    let key_schedule = fhe::key_schedule(&key);
    debug!("key schedule created {:?}", start.elapsed());

    // Server side: AES encrypt blocks
    let start = Instant::now();
    let encrypted_blocks: Vec<_> = blocks
        .into_par_iter()
        .map(|block| fhe::encrypt_block(&key_schedule, block, rounds))
        .collect();

    debug!("block encrypted (rounds: {}) {:?}", rounds, start.elapsed());

    // Client side (optional): FHE decrypt AES encrypted blocks
    encrypted_blocks
        .iter()
        .map(|block| fhe_decrypt_byte_array(&client_key, block))
        .collect()
}

pub fn fhe_encrypt_word_array<const N: usize>(
    client_key: &ClientKey,
    array: &[plain::data_model::Word; N],
) -> [Word<BitCt>; N] {
    util::par_collect_array(
        array
            .par_iter()
            .map(|word| Word::new(fhe_encrypt_byte_array(client_key, &word.0))),
    )
}

pub fn fhe_encrypt_byte_array<const N: usize>(
    client_key: &ClientKey,
    array: &[u8; N],
) -> [Byte<BitCt>; N] {
    util::par_collect_array(
        array
            .par_iter()
            .map(|&byte| fhe_encrypt_byte(client_key, byte.into())),
    )
}

pub fn fhe_encrypt_byte(client_key: &ClientKey, byte: u8) -> Byte<BitCt> {
    Byte::new(util::par_collect_array(
        util::byte_to_bits(byte).map(|b| client_key.encrypt(Cleartext(b as u64))),
    ))
}

pub fn fhe_decrypt_word_array<const N: usize>(
    client_key: &ClientKey,
    array: &[Word<BitCt>; N],
) -> [plain::data_model::Word; N] {
    util::par_collect_array(
        array
            .par_iter()
            .map(|word| plain::data_model::Word(fhe_decrypt_byte_array(client_key, &word.0))),
    )
}

pub fn fhe_decrypt_byte_array<const N: usize>(
    client_key: &ClientKey,
    array: &[Byte<BitCt>; N],
) -> [u8; N] {
    util::par_collect_array(
        array
            .par_iter()
            .map(|byte| fhe_decrypt_byte(client_key, byte).into()),
    )
}

pub fn fhe_decrypt_byte(client_key: &ClientKey, byte: &Byte<BitCt>) -> u8 {
    util::bits_to_byte(byte.bits().map(|bit| client_key.decrypt(bit).0 as u8))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::aes_128::{test_helper, ROUNDS};
    use tracing::debug;

    #[test]
    fn test_tfhe_pbssub_wop_shortint_two_rounds() {
        // rayon::ThreadPoolBuilder::new()
        //     .num_threads(16)
        //     .build_global()
        //     .unwrap();
        // debug!("current_num_threads: {}", rayon::current_num_threads());

        test_helper::test_vs_plain(expand_key_and_encrypt_blocks, 2);
    }

    #[test]
    fn test_tfhe_pbssub_wop_shortint_all_rounds() {
        test_helper::test_vs_plain(expand_key_and_encrypt_blocks, ROUNDS);
    }
}
