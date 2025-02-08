use std::time::Instant;

use crate::aes_128;
use crate::aes_128::fhe::data_model::{BitT, Block, Byte, ByteT};
use crate::aes_128::{aes_lib, fhe, fhe_encryption, plain, ROUNDS};
use crate::tfhe::{ClientKeyT, ContextT};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

pub fn test_vs_aes<CK, Ctx>(client_key: &CK, ctx: &Ctx)
where
    CK::Bit: BitT,
    Byte<CK::Bit>: ByteT,
    CK: ClientKeyT,
    Ctx: ContextT<Bit = CK::Bit>,
{
    let seed: [u8; 32] = Default::default();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut key_clear: aes_128::Key = Default::default();
    let mut block1_clear: aes_128::Block = Default::default();
    let mut block2_clear: aes_128::Block = Default::default();
    rng.fill(&mut key_clear);
    rng.fill(&mut block1_clear);
    rng.fill(&mut block2_clear);
    let blocks_clear = &[block1_clear, block2_clear];

    let key = fhe_encryption::encrypt_byte_array(client_key, &key_clear);
    let blocks = fhe_encryption::encrypt_blocks(client_key, blocks_clear);

    let encrypted = expand_key_and_encrypt_blocks(ctx, key, blocks, ROUNDS);
    let encrypted_clear = fhe_encryption::decrypt_blocks(client_key, &encrypted);

    assert_eq!(
        encrypted_clear,
        aes_lib::encrypt_blocks(key_clear, blocks_clear)
    );
}

pub fn test_vs_plain<CK, Ctx>(client_key: &CK, ctx: &Ctx, rounds: usize)
where
    CK::Bit: BitT,
    Byte<CK::Bit>: ByteT,
    CK: ClientKeyT,
    Ctx: ContextT<Bit = CK::Bit>,
{
    let seed: [u8; 32] = Default::default();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut key_clear: aes_128::Key = Default::default();
    let mut block1_clear: aes_128::Block = Default::default();
    rng.fill(&mut key_clear);
    rng.fill(&mut block1_clear);
    let blocks_clear = &[block1_clear];

    let key = fhe_encryption::encrypt_byte_array(client_key, &key_clear);
    let blocks = fhe_encryption::encrypt_blocks(client_key, blocks_clear);

    let encrypted = expand_key_and_encrypt_blocks(ctx, key, blocks, rounds);
    let encrypted_clear = fhe_encryption::decrypt_blocks(client_key, &encrypted);

    assert_eq!(
        encrypted_clear,
        plain::expand_key_and_encrypt_blocks(key_clear, blocks_clear, rounds)
    );
}

fn expand_key_and_encrypt_blocks<Ctx: ContextT>(
    ctx: &Ctx,
    key: [Byte<Ctx::Bit>; 16],
    blocks: Vec<Block<Ctx::Bit>>,
    rounds: usize,
) -> Vec<Block<Ctx::Bit>>
where
    Ctx::Bit: BitT,
    Byte<Ctx::Bit>: ByteT,
{
    // Server side (optional): AES encrypt blocks
    let start = Instant::now();
    let key_schedule = fhe::key_schedule(ctx, &key);
    println!("AES key expansion took: {:?}", start.elapsed());

    // Server side: AES encrypt blocks
    let start = Instant::now();
    let encrypted_blocks: Vec<_> = blocks
        .into_par_iter()
        .map(|block| fhe::encrypt_block_for_rounds(ctx, &key_schedule, block, rounds))
        .collect();
    println!(
        "AES ({} rounds) of #{} outputs computed in: {:?}",
        rounds,
        encrypted_blocks.len(),
        start.elapsed()
    );
    encrypted_blocks
}
