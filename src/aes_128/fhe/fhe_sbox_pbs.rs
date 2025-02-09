use crate::aes_128::fhe::data_model;
use crate::aes_128::fhe::data_model::{BitT, Block};
use crate::aes_128::fhe::data_model::{Byte, State, Word};
use crate::aes_128::RC;
use crate::tfhe::ContextT;
use crate::util;

use rayon::iter::IntoParallelIterator;
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use std::array;

use tracing::debug;

pub trait ByteT: Sized {
    /// Bootstrap to reset noise
    fn bootstrap_assign(&mut self);

    /// Perform AES SubBytes on this byte while also resetting noise
    fn sbox_substitute(&self) -> Self;
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

/// Multiplication in F_2[X]/(X^8 + X^4 + X^3 + X + 1)
fn gf_256_mul<Ctx: ContextT>(ctx: &Ctx, a: &Byte<Ctx::Bit>, mut b: u8) -> Byte<Ctx::Bit>
where
    Ctx::Bit: BitT,
{
    let mut a = a.clone();
    let mut res = Byte::trivial(ctx, 0);
    for _ in 0..8 {
        if b & 1 == 1 {
            res ^= &a;
        }
        let reduce_x8 = a.shl_assign_1(ctx);

        a[3] ^= &reduce_x8;
        a[4] ^= &reduce_x8;
        a[6] ^= &reduce_x8;
        a[7] ^= &reduce_x8;

        b >>= 1;
    }

    res
}

/// MixColumns step in AES
fn mix_columns<Ctx: ContextT>(ctx: &Ctx, state: &mut State<Ctx::Bit>)
where
    Ctx::Bit: BitT,
{
    let new_columns: [Word<Ctx::Bit>; 4] = util::par_collect_array(state.columns().map(|column| {
        Word::new(util::par_collect_array((0..4).into_par_iter().map(|i| {
            gf_256_mul(ctx, &column[i], 2)
                ^ gf_256_mul(ctx, &column[(i - 1) % 4], 1)
                ^ gf_256_mul(ctx, &column[(i - 2) % 4], 1)
                ^ gf_256_mul(ctx, &column[(i - 3) % 4], 3)
        })))
    }));

    for (j, column) in new_columns.into_iter().enumerate() {
        state.column_mut(j).assign(column);
    }
}

pub fn encrypt_block_for_rounds<Ctx: ContextT>(
    ctx: &Ctx,
    expanded_key: &[Word<Ctx::Bit>; 44],
    block: Block<Ctx::Bit>,
    rounds: usize,
) -> Block<Ctx::Bit>
where
    Ctx::Bit: BitT,
    Byte<Ctx::Bit>: ByteT,
{
    let mut state_fhe = State::from_array(block);

    data_model::xor_state(
        &mut state_fhe,
        expanded_key[0..4].try_into().expect("array length 4"),
    );

    for i in 1..rounds {
        debug!("starting round {}", i);
        debug!("sub_bytes");
        sub_bytes(&mut state_fhe);
        debug!("shift_rows");
        data_model::shift_rows(&mut state_fhe);
        debug!("mix_columns");
        mix_columns(ctx, &mut state_fhe);
        debug!("xor_state");
        data_model::xor_state(
            &mut state_fhe,
            expanded_key[i * 4..(i + 1) * 4]
                .try_into()
                .expect("array length 4"),
        );
    }

    debug!("starting last round");
    debug!("sub_bytes");
    sub_bytes(&mut state_fhe);
    debug!("shift_rows");
    data_model::shift_rows(&mut state_fhe);
    debug!("xor_state");
    data_model::xor_state(
        &mut state_fhe,
        expanded_key[40..44].try_into().expect("array length 4"),
    );

    state_fhe.into_array()
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
