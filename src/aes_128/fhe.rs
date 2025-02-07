//! Generic implementation based on one ciphertext representing one bit. This means that "xor" can be
//! evaluated and a simple addition of ciphertext. Byte substitution is calculated via bootstrapping.

pub mod data_model;

use crate::aes_128::fhe::data_model::{BitT, Byte, State, Word};
use crate::util;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelBridge};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use std::array;
use std::fmt::{Debug, Formatter};
use std::ops::{BitXor, BitXorAssign, Index, IndexMut, ShlAssign};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tfhe::core_crypto::prelude::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, LweDimension, PolynomialSize, StandardDev,
};
use tfhe::shortint;
use tfhe::shortint::wopbs::{ShortintWopbsLUT, WopbsKey};
use tfhe::shortint::{
    CarryModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel, MessageModulus,
    ShortintParameterSet, WopbsParameters,
};

fn substitute<Bit>(byte: &Byte<Bit>) -> Byte<Bit> {
    todo!()
}

fn xor_state<Bit: BitT>(state: &mut State<Bit>, key: &[Word<Bit>; 4]) {
    for (j, word) in key.iter().enumerate() {
        state.column_mut(j).bitxor_assign(word);
    }
}

fn sub_bytes<Bit>(state: &mut State<Bit>) {
    state.bytes_mut().par_bridge().for_each(|byte| {
        *byte = substitute(byte);
    })
}

fn shift_rows<Bit>(state: &mut State<Bit>) {
    for (i, row) in state.rows_mut().enumerate() {
        row.rotate_left_assign(i);
    }
}

/// Multiplication in F_2[X]/(X^8 + X^4 + X^3 + X + 1)
fn gf_256_mul<Bit: BitT>(a: &Byte<Bit>, mut b: u8) -> Byte<Bit> {
    let mut a = a.clone();
    let mut res = Byte::default();
    for _ in 0..8 {
        if b & 1 == 1 {
            res ^= &a;
        }
        let reduce_x8 = a.shl_assign_1();

        a[3] ^= &reduce_x8;
        a[4] ^= &reduce_x8;
        a[6] ^= &reduce_x8;
        a[7] ^= &reduce_x8;

        b >>= 1;
    }

    res
}

fn mix_columns<Bit: BitT>(state: &mut State<Bit>) {
    let new_columns: [Word<Bit>; 4] = util::collect_array(
        state
            .columns()
            .collect::<Vec<_>>()
            .par_iter()
            .map(|column| {
                Word(util::collect_array((0..4).into_par_iter().map(|i| {
                    gf_256_mul(&column[i], 2)
                        ^ gf_256_mul(&column[(i - 1) % 4], 1)
                        ^ gf_256_mul(&column[(i - 2) % 4], 1)
                        ^ gf_256_mul(&column[(i - 3) % 4], 3)
                })))
            }),
    );

    for (j, column) in new_columns.into_iter().enumerate() {
        state.column_mut(j).assign(column);
    }
}

pub fn encrypt_block<Bit: BitT>(
    expanded_key_fhe: &[Word<Bit>; 44],
    block: Block<Bit>,
    rounds: usize,
) -> Block<Bit> {
    let mut state_fhe = State::from_array(block);

    xor_state(
        &mut state_fhe,
        expanded_key_fhe[0..4].try_into().expect("array length 4"),
    );

    for i in 1..rounds {
        println!("starting round");
        println!("sub_bytes");
        sub_bytes(&mut state_fhe);
        println!("shift_rows");
        shift_rows(&mut state_fhe);
        println!("mix_columns");
        mix_columns(&mut state_fhe);
        println!("xor_state");
        xor_state(
            &mut state_fhe,
            expanded_key_fhe[i * 4..(i + 1) * 4]
                .try_into()
                .expect("array length 4"),
        );
    }

    println!("starting last round");
    println!("sub_bytes");
    sub_bytes(&mut state_fhe);
    println!("shift_rows");
    shift_rows(&mut state_fhe);
    println!("xor_state");
    xor_state(
        &mut state_fhe,
        expanded_key_fhe[40..44].try_into().expect("array length 4"),
    );

    state_fhe.into_array()
}

pub fn key_schedule(context: &FheContext, key_slice: &[BoolByteFhe; 16]) -> [WordFhe; 44] {
    let mut key: [WordFhe; 4] = Default::default();
    let mut expanded_key: [WordFhe; 44] = array::from_fn(|_| WordFhe::default());

    for i in 0..4 {
        for j in 0..4 {
            expanded_key[i][j] = key_slice[i * 4 + j].clone();
        }
    }

    for i in 4..44 {
        if i % 4 == 0 {
            expanded_key[i] =
                expanded_key[i - 4].clone() ^ &sub_word(expanded_key[i - 1].clone().rotate_left(1));
            expanded_key[i][0] ^= &BoolByteFhe::trivial(RC[i / 4], context.clone());
        } else {
            expanded_key[i] = expanded_key[i - 4].clone() ^ &expanded_key[i - 1];
        }

        // bootstrap all words to control noise level
        if i % 4 == 3 {
            expanded_key[i - 3..=i].par_iter_mut().for_each(|word| {
                boot_word(word);
            });
        }
    }

    expanded_key
}

fn boot_word<Bit>(word: &mut Word<Bit>) {
    word.bytes_mut().par_bridge().for_each(|byte| {
        *byte = boot_byte(byte);
    });
}

fn boot_byte<Bit>(byte: &Byte<Bit>) -> Byte<Bit> {
    todo!()
}

fn sub_word<Bit>(mut word: Word<Bit>) -> Word<Bit> {
    word.bytes_mut().par_bridge().for_each(|byte| {
        *byte = substitute(byte);
    });

    word
}
