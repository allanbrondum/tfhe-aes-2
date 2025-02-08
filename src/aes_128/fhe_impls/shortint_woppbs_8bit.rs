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
use rayon::iter::{IntoParallelRefIterator, ParallelBridge};
use tfhe::core_crypto::entities::Cleartext;

pub fn fhe_encrypt_word_array<const N: usize>(
    client_key: &ClientKey,
    array: &[plain::data_model::Word; N],
) -> [Word<BitCt>; N] {
    array
        .par_iter()
        .map(|word| Word::new(fhe_encrypt_byte_array(client_key, &word.0)))
        .collect::<Vec<_>>()
        .try_into()
        .expect("constant length")
}

pub fn fhe_encrypt_byte_array<const N: usize>(
    client_key: &ClientKey,
    array: &[u8; N],
) -> [Byte<BitCt>; N] {
    array
        .par_iter()
        .map(|&byte| fhe_encrypt_byte(client_key, byte.into()))
        .collect::<Vec<_>>()
        .try_into()
        .expect("constant length")
}

pub fn fhe_encrypt_byte(client_key: &ClientKey, byte: u8) -> Byte<BitCt> {
    Byte::new(util::par_collect_array(
        util::byte_to_bits(byte)
            .par_bridge()
            .map(|b| client_key.encrypt(Cleartext(b as u64))),
    ))
}
//
//
//
// pub fn fhe_decrypt_word_array<const N: usize>(
//     client_key: &shortint::client_key::ClientKey,
//     array: &[WordFhe; N],
// ) -> [Word; N] {
//     array
//         .par_iter()
//         .map(|word| Word(fhe_decrypt_bool_byte_array(client_key, &word.0)))
//         .collect::<Vec<_>>()
//         .try_into()
//         .expect("constant length")
// }
//
// pub fn fhe_decrypt_byte_array<const N: usize>(
//     client_key: &shortint::client_key::ClientKey,
//     array: &[BoolByteFhe; N],
// ) -> [u8; N] {
//     array
//         .par_iter()
//         .map(|byte| fhe_decrypt_byte(client_key, byte).into())
//         .collect::<Vec<_>>()
//         .try_into()
//         .expect("constant length")
// }
//
//
//
// pub fn fhe_decrypt_byte(
//     client_key: &shortint::client_key::ClientKey,
//     byte: &BoolByteFhe,
// ) -> BoolByte {
//     BoolByte(
//         byte.0
//             .par_iter()
//             .map(|b| fhe_decrypt_bool(client_key, b))
//             .collect::<Vec<_>>()
//             .try_into()
//             .expect("constant length"),
//     )
// }

// #[cfg(test)]
// mod test {
//     use super::*;
//     use std::sync::{Arc, LazyLock};
//     use std::time::Instant;
//     use tfhe::core_crypto::prelude::*;
//     use tfhe::shortint::wopbs::WopbsKey;
//     use tfhe::shortint::{
//         CarryModulus, ClassicPBSParameters, MaxNoiseLevel, MessageModulus, ShortintParameterSet,
//         WopbsParameters,
//     };
//
//
//     static KEYS: LazyLock<(Arc<shortint::ClientKey>, FheContext)> = LazyLock::new(|| keys_impl());
//
//     fn keys_impl() -> (Arc<shortint::ClientKey>, FheContext) {
//         let (client_key, server_key) = shortint::gen_keys(params());
//
//         // debug!("server key: {:#?}", server_key);
//
//         let wops_key = WopbsKey::new_wopbs_key_only_for_wopbs(&client_key, &server_key);
//
//         let context = FheContext {
//             client_key: client_key.clone().into(),
//             server_key: server_key.into(),
//             wopbs_key: wops_key.into(),
//         };
//
//         BOOL_FHE_DEFAULT
//             .set(BoolFhe::trivial(false, context.clone()))
//             .expect("only set once");
//
//         INT_BYTE_FHE_DEFAULT
//             .set(IntByteFhe::new(
//                 context.server_key.create_trivial(0),
//                 context.clone(),
//             ))
//             .expect("only set once");
//
//         (context.client_key.clone(), context)
//     }
//
//     #[test]
//     fn test_bool_fhe_encode() {
//         assert_eq!(BoolFhe::encode(false), Plaintext(0));
//         assert_eq!(BoolFhe::encode(true), Plaintext(1 << 63));
//     }
//
//     #[test]
//     fn test_bool_fhe_decode() {
//         assert_eq!(BoolFhe::decode(Plaintext(0)), false);
//         assert_eq!(BoolFhe::decode(Plaintext(1)), false);
//         assert_eq!(BoolFhe::decode(Plaintext(u64::MAX)), false);
//         assert_eq!(BoolFhe::decode(Plaintext(1 << 63)), true);
//         assert_eq!(BoolFhe::decode(Plaintext((1 << 63) - 1)), true);
//         assert_eq!(BoolFhe::decode(Plaintext((1 << 63) + 1)), true);
//     }
//
//     #[test]
//     fn test_pbssub_wop_shortint_bool_fhe() {
//         let (client_key, context) = KEYS.clone();
//
//         let mut b1 = fhe_encrypt_bool(&client_key, &context, false);
//         let b2 = fhe_encrypt_bool(&client_key, &context, true);
//
//         assert_eq!(fhe_decrypt_bool(&client_key, &b1), false);
//         assert_eq!(fhe_decrypt_bool(&client_key, &b2), true);
//
//         assert_eq!(
//             fhe_decrypt_bool(&client_key, &(b1.clone() ^ b2.clone())),
//             true
//         );
//         assert_eq!(
//             fhe_decrypt_bool(&client_key, &(b1.clone() ^ b1.clone())),
//             false
//         );
//         assert_eq!(
//             fhe_decrypt_bool(&client_key, &(b2.clone() ^ b2.clone())),
//             false
//         );
//
//         // default/trivial
//         assert_eq!(fhe_decrypt_bool(&client_key, &BoolFhe::default()), false);
//         assert_eq!(
//             fhe_decrypt_bool(&client_key, &(b2.clone() ^ BoolFhe::default())),
//             true
//         );
//         assert_eq!(
//             fhe_decrypt_bool(&client_key, &BoolFhe::trivial(false, context.clone())),
//             false
//         );
//         assert_eq!(
//             fhe_decrypt_bool(&client_key, &BoolFhe::trivial(true, context.clone())),
//             true
//         );
//     }
//
//     #[test]
//     fn test_pbssub_wop_shortint_bool_byte_fhe() {
//         let (client_key, context) = KEYS.clone();
//
//         // default/trivial
//         assert_eq!(
//             u8::from(fhe_decrypt_byte(&client_key, &BoolByteFhe::default())),
//             0
//         );
//         assert_eq!(
//             u8::from(fhe_decrypt_byte(
//                 &client_key,
//                 &BoolByteFhe::trivial(123, context.clone())
//             )),
//             123
//         );
//     }
//
//     #[test]
//     fn test_pbssub_wop_shortint_word_fhe() {
//         let (client_key, context) = KEYS.clone();
//
//         // default/trivial
//         assert_eq!(
//             fhe_decrypt_byte_array(&client_key, &WordFhe::default().0),
//             [0, 0, 0, 0]
//         );
//     }
//
//     #[test]
//     fn test_pbssub_wop_shortint_int_byte_boostrap_from_bool_byte_fhe() {
//         let (client_key, context) = KEYS.clone();
//
//         let bool_byte = BoolByte::from(0b10110101);
//         let bool_byte_fhe = fhe_encrypt_byte(&client_key, &context, bool_byte);
//
//         let lut = IntByteFhe::generate_lookup_table(&context, |val| val);
//         let int_byte_fhe = IntByteFhe::bootstrap_from_bool_byte(&bool_byte_fhe, &lut);
//
//         let decrypted = client_key.decrypt_without_padding(&int_byte_fhe.ct);
//         assert_eq!(decrypted, 0b10110101);
//     }
//
//     #[test]
//     fn test_pbssub_wop_shortint_int_byte_boostrap_from_bool_byte_fhe2() {
//         let (client_key, context) = KEYS.clone();
//
//         let bool_byte = BoolByte::from(0b10110101);
//         let bool_byte_fhe = fhe_encrypt_byte(&client_key, &context, bool_byte);
//
//         let bool_byte2 = BoolByte::from(0b01100110);
//         let bool_byte_fhe2 = fhe_encrypt_byte(&client_key, &context, bool_byte2);
//
//         let bool_byte_fhe = bool_byte_fhe ^ bool_byte_fhe2.clone();
//
//         let lut = IntByteFhe::generate_lookup_table(&context, |val| val);
//         let int_byte_fhe = IntByteFhe::bootstrap_from_bool_byte(&bool_byte_fhe, &lut);
//
//         let decrypted_int = client_key.decrypt_without_padding(&int_byte_fhe.ct) as u8;
//         let decrypted_bool = u8::from(fhe_decrypt_byte(&client_key, &bool_byte_fhe));
//         assert_eq!(decrypted_int, decrypted_bool);
//     }
//
//     #[test]
//     fn test_pbssub_wop_shortint_int_byte_boostrap_from_bool_byte_fhe_lut() {
//         let (client_key, context) = KEYS.clone();
//
//         let bool_byte = BoolByte::from(0b10110101);
//         let bool_byte_fhe = fhe_encrypt_byte(&client_key, &context, bool_byte);
//
//         let lut = IntByteFhe::generate_lookup_table(&context, |val| val + 3);
//         let int_byte_fhe = IntByteFhe::bootstrap_from_bool_byte(&bool_byte_fhe, &lut);
//
//         let decrypted = client_key.decrypt_without_padding(&int_byte_fhe.ct);
//         assert_eq!(decrypted, 0b10110101 + 3);
//     }
//
//     #[test]
//     fn test_pbssub_wop_shortint_bool_byte_boostrap_from_int_byte_fhe() {
//         let (client_key, context) = KEYS.clone();
//
//         let int_byte_fhe = IntByteFhe::new(client_key.encrypt_without_padding(0b10110101), context);
//         let bool_byte_fhe = BoolByteFhe::bootstrap_from_int_byte(&int_byte_fhe);
//
//         let bool_byte = fhe_decrypt_byte(&client_key, &bool_byte_fhe);
//         assert_eq!(u8::from(bool_byte), 0b10110101);
//     }
//
//     #[test]
//     fn test_pbssub_wob_shortint_perf() {
//         let start = Instant::now();
//         let (client_key, context) = KEYS.clone();
//         debug!("keys generated: {:?}", start.elapsed());
//
//         let start = Instant::now();
//         let mut b1 = client_key.encrypt_without_padding(1);
//         let b2 = client_key.encrypt_without_padding(3);
//         debug!(
//             "data encrypted: {:?}, dim: {}",
//             start.elapsed(),
//             b2.ct.data.len()
//         );
//
//         let start = Instant::now();
//         context.server_key.unchecked_add_assign(&mut b1, &b2);
//         debug!("add elapsed: {:?}", start.elapsed());
//
//         let lut = context
//             .wopbs_key
//             .generate_lut_without_padding(&b1, |a| a)
//             .into();
//         let start = Instant::now();
//         _ = context
//             .wopbs_key
//             .programmable_bootstrapping_without_padding(&b1, &lut);
//         debug!("bootstrap elapsed: {:?}", start.elapsed());
//     }
//
//     #[test]
//     fn test_pbssub_wob_shortint_extract_bits() {
//         let start = Instant::now();
//         let (client_key, context) = KEYS.clone();
//         debug!("keys generated: {:?}", start.elapsed());
//
//         let cte1 = client_key.encrypt_without_padding(0b0110100);
//
//         let start = Instant::now();
//         let delta = (1u64 << (64 - 8));
//         let delta_log = DeltaLog(delta.ilog2() as usize);
//         let bit_cts = context
//             .wopbs_key
//             .extract_bits(delta_log, &cte1, ExtractedBitsCount(8));
//         debug!("bootstrap elapsed: {:?}", start.elapsed());
//
//         // let lwe_decryption_key = client_key.glwe_secret_key.as_lwe_secret_key();
//         let lwe_decryption_key = &client_key.lwe_secret_key;
//         for (i, bit_ct) in bit_cts.iter().enumerate() {
//             let decrypted = lwe_encryption::decrypt_lwe_ciphertext(&lwe_decryption_key, &bit_ct);
//             let decoded = decrypted.0 >> (64 - 8);
//             debug!("bit {}: {:b}", i, decoded);
//         }
//     }
// }
//
// // todo allan use borrowed types for list ciphertexts?
// // todo allan test non-trivial lut
//
//
//
// #[cfg(test)]
// mod test {
//     use crate::impls::tfhe_pbssub_wop_shortint::model::BoolByte;
//     use crate::impls::tfhe_pbssub_wop_shortint::shl_array;
//
//     #[test]
//     fn test_bool_byte() {
//         let byte = 0x12;
//         assert_eq!(u8::from(BoolByte::from(byte)), byte);
//     }
//
//     #[test]
//     fn test_shl_array() {
//         let mut array = [3, 4, 5, 6];
//         shl_array(&mut array, 2);
//         assert_eq!(array, [5, 6, 0, 0]);
//
//         let mut array = [3, 4, 5, 6];
//         shl_array(&mut array, 0);
//         assert_eq!(array, [3, 4, 5, 6]);
//
//         let mut array = [3, 4, 5, 6];
//         shl_array(&mut array, 5);
//         assert_eq!(array, [0, 0, 0, 0]);
//     }
//
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
