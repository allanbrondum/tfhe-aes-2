// fn substitute_part1(byte: &BoolByteFhe) -> IntByteFhe {
//     let context = &byte.bits().next().unwrap().context;
//
//     let lut = SBOX_LUT.get_or_init(|| {
//         IntByteFhe::generate_lookup_table(context, |byte| SBOX[byte as usize].into())
//     });
//     let start = Instant::now();
//     let int_byte = IntByteFhe::bootstrap_from_bool_byte(&byte, &lut);
//     debug!("boot int {:?}", start.elapsed());
//
//     int_byte
// }
//
// fn substitute_part2(byte: IntByteFhe) -> BoolByteFhe {
//     let start = Instant::now();
//     let bool_byte = BoolByteFhe::bootstrap_from_int_byte(&byte);
//     debug!("boot bools {:?}", start.elapsed());
//
//     bool_byte
// }

// pub fn encrypt_single_block(key: Key, block: Block, rounds: usize) -> Block {
//     debug!("start");
//
//
//
//     debug!("keys generated");
//
//     BOOL_FHE_DEFAULT
//         .set(BoolFhe::trivial(false, context.clone()))
//         .expect("only set once");
//
//     INT_BYTE_FHE_DEFAULT
//         .set(IntByteFhe::new(
//             context.server_key.create_trivial(0),
//             context.clone(),
//         ))
//         .expect("only set once");
//
//     let key_fhe = fhe_model::fhe_encrypt_byte_array(&context.client_key, &context, &key);
//     let block_fhe = fhe_model::fhe_encrypt_byte_array(&context.client_key, &context, &block);
//
//     debug!("aes key and block encrypted");
//
//     let start = Instant::now();
//
//     let key_schedule_fhe = key_schedule(&context, &key_fhe);
//
//     let key_schedule_plain = key_schedule_plain(&key);
//     let key_schedule_decrypted = fhe_decrypt_word_array(&context.client_key, &key_schedule_fhe);
//     if key_schedule_decrypted != key_schedule_plain {
//         edebug!("wrong key schedule encryption");
//         panic!();
//     }
//
//     let key_schedule_fhe =
//         fhe_encrypt_word_array(&context.client_key, &context, &key_schedule_plain);
//
//     debug!("key schedule created {:?}", start.elapsed());
//
//     let encrypted = encrypt_block(&context, &key_schedule_fhe, block_fhe, rounds);
//
//     debug!("block encrypted (rounds: {}) {:?}", rounds, start.elapsed());
//
//     fhe_model::fhe_decrypt_byte_array(&context.client_key, &encrypted)
// }
//
//
//
//

use crate::aes_128::fhe::data_model::{Byte, Word};
use crate::aes_128::plain;
use crate::tfhe::shortint_woppbs_8bit::*;
use crate::util;
use rayon::iter::ParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use tfhe::core_crypto::entities::Cleartext;

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


//
// todo allan use borrowed types for list ciphertexts?
// todo allan test non-trivial lut



//     use crate::impls::{ tfhe_pbssub_wop_shortint};
//     use crate::{impls, ROUNDS};
//
//     // #[test]
//     // fn test_tfhe_pbssub_wop_shortint_two_rounds() {
//     //     rayon::ThreadPoolBuilder::new()
//     //         .num_threads(16)
//     //         .build_global()
//     //         .unwrap();
//     //     debug!("current_num_threads: {}", rayon::current_num_threads());
//     //
//     //     impls::test::test_vs_plain(tfhe_pbssub_wop_shortint::encrypt_single_block, 2);
//     // }
//     //
//     // #[test]
//     // fn test_tfhe_pbssub_wop_shortint_all_rounds() {
//     //     rayon::ThreadPoolBuilder::new()
//     //         .num_threads(16)
//     //         .build_global()
//     //         .unwrap();
//     //
//     //     impls::test::test_vs_plain(tfhe_pbssub_wop_shortint::encrypt_single_block, ROUNDS);
//     // }
// }
