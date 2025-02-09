use std::time::Instant;

use crate::aes_128;
use crate::aes_128::fhe::data_model::{Block, Byte, Word};
use crate::aes_128::fhe::{fhe_encryption, Aes128Encrypt};
use crate::aes_128::{aes_lib, plain, ROUNDS};
use crate::tfhe::{ClientKeyT, ContextT};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

pub fn test_full<Enc: Aes128Encrypt, CK>(client_key: &CK, ctx: &Enc::Ctx)
where
    CK: ClientKeyT<Bit = <Enc::Ctx as ContextT>::Bit>,
{
    test_key_expansion_and_block_encryption_vs_aes::<Enc, _>(client_key, ctx);
    test_key_expansion_and_block_encryption_fips_197::<Enc, _>(client_key, ctx);
}

/// Full test against `aes` Rust library
pub fn test_key_expansion_and_block_encryption_vs_aes<Enc: Aes128Encrypt, CK>(
    client_key: &CK,
    ctx: &Enc::Ctx,
) where
    CK: ClientKeyT<Bit = <Enc::Ctx as ContextT>::Bit>,
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

    let key_schedule = expand_key::<Enc>(ctx, key);
    let encrypted = encrypt_blocks::<Enc>(ctx, key_schedule, blocks, ROUNDS);
    let encrypted_clear = fhe_encryption::decrypt_blocks(client_key, &encrypted);

    assert_eq!(
        encrypted_clear,
        aes_lib::encrypt_blocks(key_clear, blocks_clear)
    );
}

/// Full test against test vector in FIPS 197 appendix C.1
pub fn test_key_expansion_and_block_encryption_fips_197<Enc: Aes128Encrypt, CK>(
    client_key: &CK,
    ctx: &Enc::Ctx,
) where
    CK: ClientKeyT<Bit = <Enc::Ctx as ContextT>::Bit>,
{
    let key_clear: aes_128::Key = hex::decode("000102030405060708090a0b0c0d0e0f")
        .unwrap()
        .try_into()
        .unwrap();
    let block1_clear: aes_128::Block = hex::decode("00112233445566778899aabbccddeeff")
        .unwrap()
        .try_into()
        .unwrap();
    let blocks_clear = &[block1_clear];

    let key = fhe_encryption::encrypt_byte_array(client_key, &key_clear);
    let blocks = fhe_encryption::encrypt_blocks(client_key, blocks_clear);

    let key_schedule = expand_key::<Enc>(ctx, key);
    let encrypted = encrypt_blocks::<Enc>(ctx, key_schedule, blocks, ROUNDS);
    let encrypted_clear = fhe_encryption::decrypt_blocks(client_key, &encrypted);

    let expected_encrypted_clear: aes_128::Block = hex::decode("69c4e0d86a7b0430d8cdb78070b4c55a")
        .unwrap()
        .try_into()
        .unwrap();

    assert_eq!(encrypted_clear, vec![expected_encrypted_clear],);
}

pub fn test_light<Enc: Aes128Encrypt, CK>(client_key: &CK, ctx: &Enc::Ctx)
where
    CK: ClientKeyT<Bit = <Enc::Ctx as ContextT>::Bit>,
{
    test_block_encryption_vs_plain::<Enc, _>(client_key, ctx, 2);
}

/// Short(er) running test that only tests a limited number of AES rounds and does not test key expansion
pub fn test_block_encryption_vs_plain<Enc: Aes128Encrypt, CK>(
    client_key: &CK,
    ctx: &Enc::Ctx,
    rounds: usize,
) where
    CK: ClientKeyT<Bit = <Enc::Ctx as ContextT>::Bit>,
{
    let seed: [u8; 32] = Default::default();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut key_clear: aes_128::Key = Default::default();
    let mut block1_clear: aes_128::Block = Default::default();
    rng.fill(&mut key_clear);
    rng.fill(&mut block1_clear);
    let blocks_clear = &[block1_clear];

    let key_schedule_clear = plain::key_schedule(&key_clear);
    let key_schedule = fhe_encryption::encrypt_word_array(client_key, &key_schedule_clear);
    let blocks = fhe_encryption::encrypt_blocks(client_key, blocks_clear);

    let encrypted = encrypt_blocks::<Enc>(ctx, key_schedule, blocks, rounds);
    let encrypted_clear = fhe_encryption::decrypt_blocks(client_key, &encrypted);

    assert_eq!(
        encrypted_clear,
        plain::expand_key_and_encrypt_blocks(key_clear, blocks_clear, rounds)
    );
}

fn expand_key<Enc: Aes128Encrypt>(
    ctx: &Enc::Ctx,
    key: [Byte<<Enc::Ctx as ContextT>::Bit>; 16],
) -> [Word<<Enc::Ctx as ContextT>::Bit>; 44] {
    // Server side (optional): AES encrypt blocks
    let start = Instant::now();
    let key_schedule = Enc::key_schedule(ctx, &key);
    println!("AES key expansion took: {:?}", start.elapsed());

    key_schedule
}

fn encrypt_blocks<Enc: Aes128Encrypt>(
    ctx: &Enc::Ctx,
    key_schedule: [Word<<Enc::Ctx as ContextT>::Bit>; 44],
    blocks: Vec<Block<<Enc::Ctx as ContextT>::Bit>>,
    rounds: usize,
) -> Vec<Block<<Enc::Ctx as ContextT>::Bit>> {
    // Server side: AES encrypt blocks
    let start = Instant::now();
    let encrypted_blocks: Vec<_> = blocks
        .into_par_iter()
        .map(|block| Enc::encrypt_block_for_rounds(ctx, &key_schedule, block, rounds))
        .collect();
    println!(
        "AES ({} rounds) of #{} outputs computed in: {:?}",
        rounds,
        encrypted_blocks.len(),
        start.elapsed()
    );
    encrypted_blocks
}
