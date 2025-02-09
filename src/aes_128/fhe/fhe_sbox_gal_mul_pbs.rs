//! Generic implementation based on one ciphertext representing one bit. This means that "xor" can be
//! evaluated and a simple addition of ciphertext.
//! SBOX byte substitution composed with Galois multiplication is calculated via programmable bootstrapping.

pub trait ByteT: Sized {
    /// Bootstrap to reset noise
    fn bootstrap_assign(&mut self);

    /// Perform AES SubBytes on this byte while also resetting noise.
    fn sbox_substitute(&self) -> Self;

    /// Perform AES SubBytes on this byte while also resetting noise. Additionally, composes
    /// with Galois multiplication with respectively 1, 2 and 3 and returns three bytes resulting from that.
    fn sbox_substitute_and_gal_mul(&self) -> [Self; 3];
}

use crate::aes_128::fhe::data_model;
use crate::aes_128::fhe::data_model::{BitT, Block, Byte, State, Word};
use crate::aes_128::RC;
use crate::tfhe::ContextT;
use crate::util;
use itertools::Itertools;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use std::array;

use tracing::debug;

/// SubBytes step in AES composed with Galois multiplication for MixColumns
fn sub_bytes_with_gal_mul<Bit: BitT>(state: State<Bit>) -> [State<Bit>; 3]
where
    Byte<Bit>: ByteT,
{
    let bytes = state.into_array();

    let (bytes_mul1, bytes_mul2, bytes_mul3): (Vec<_>, Vec<_>, Vec<_>) = bytes
        .into_par_iter()
        .map(|byte| {
            let muls = byte.sbox_substitute_and_gal_mul();
            <(Byte<Bit>, Byte<Bit>, Byte<Bit>)>::from(muls)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .multiunzip();

    [
        State::from_array(bytes_mul1.try_into().expect("16 bytes")),
        State::from_array(bytes_mul2.try_into().expect("16 bytes")),
        State::from_array(bytes_mul3.try_into().expect("16 bytes")),
    ]
}

/// SubBytes step in AES
fn sub_bytes<Bit: BitT>(state: &mut State<Bit>)
where
    Byte<Bit>: ByteT,
{
    state.bytes_mut().for_each(|byte| {
        *byte = byte.sbox_substitute();
    })
}

/// MixColumns step in AES
fn mix_columns<Bit: BitT>(state_muls: [State<Bit>; 3]) -> State<Bit> {
    let new_columns: [Word<Bit>; 4] = util::par_collect_array(
        state_muls[0]
            .columns()
            .zip_eq(state_muls[1].columns())
            .zip_eq(state_muls[2].columns())
            .map(|((column_mul1, column_mul2), column_mul3)| {
                Word::new(util::par_collect_array((0..4).into_par_iter().map(|i| {
                    column_mul2[i].clone()
                        ^ &column_mul1[(i - 1) % 4]
                        ^ &column_mul1[(i - 2) % 4]
                        ^ &column_mul3[(i - 3) % 4]
                })))
            }),
    );

    let mut state = state_muls.into_iter().next().expect("three states");
    for (j, column) in new_columns.into_iter().enumerate() {
        state.column_mut(j).assign(column);
    }
    state
}

pub fn encrypt_block_for_rounds<Ctx: ContextT>(
    _ctx: &Ctx,
    expanded_key: &[Word<Ctx::Bit>; 44],
    block: Block<Ctx::Bit>,
    rounds: usize,
) -> Block<Ctx::Bit>
where
    Ctx::Bit: BitT,
    Byte<Ctx::Bit>: ByteT,
{
    let mut state = State::from_array(block);

    data_model::xor_state(
        &mut state,
        expanded_key[0..4].try_into().expect("array length 4"),
    );

    for i in 1..rounds {
        debug!("starting round {}", i);
        debug!("sub_bytes");
        let mut state_muls = sub_bytes_with_gal_mul(state);
        debug!("shift_rows");
        for state in &mut state_muls {
            data_model::shift_rows(state);
        }
        debug!("mix_columns");
        state = mix_columns(state_muls);
        debug!("xor_state");
        data_model::xor_state(
            &mut state,
            expanded_key[i * 4..(i + 1) * 4]
                .try_into()
                .expect("array length 4"),
        );
    }

    debug!("starting last round");
    debug!("sub_bytes");
    sub_bytes(&mut state);
    debug!("shift_rows");
    data_model::shift_rows(&mut state);
    debug!("xor_state");
    data_model::xor_state(
        &mut state,
        expanded_key[40..44].try_into().expect("array length 4"),
    );

    state.into_array()
}

pub fn key_schedule<Ctx: ContextT>(
    ctx: &Ctx,
    key_slice: &[Byte<Ctx::Bit>; 16],
) -> [Word<Ctx::Bit>; 44]
where
    Ctx::Bit: BitT,
    Byte<Ctx::Bit>: ByteT,
{
    let mut expanded_key: [Word<Ctx::Bit>; 44] = array::from_fn(|_| Word::zero(ctx));

    for i in 0..4 {
        for j in 0..4 {
            expanded_key[i][j] = key_slice[i * 4 + j].clone();
        }
    }

    for i in 4..44 {
        debug!("key schedule index {}", i);
        if i % 4 == 0 {
            expanded_key[i] =
                expanded_key[i - 4].clone() ^ &sub_word(expanded_key[i - 1].clone().rotate_left(1));
            expanded_key[i][0] ^= &Byte::trivial(ctx, RC[i / 4]);
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

fn boot_word<Bit: BitT>(word: &mut Word<Bit>)
where
    Byte<Bit>: ByteT,
{
    word.bytes_mut().for_each(|byte| {
        boot_byte(byte);
    });
}

fn boot_byte<Bit>(byte: &mut Byte<Bit>)
where
    Byte<Bit>: ByteT,
{
    byte.bootstrap_assign();
}

fn sub_word<Bit: BitT>(mut word: Word<Bit>) -> Word<Bit>
where
    Byte<Bit>: ByteT,
{
    word.bytes_mut().for_each(|byte| {
        *byte = byte.sbox_substitute();
    });

    word
}
