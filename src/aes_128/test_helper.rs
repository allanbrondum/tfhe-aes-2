
use aes::cipher::{BlockEncrypt, KeyInit};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use crate::aes_128::{plain, Block, Key, ROUNDS};

fn encrypt_aes_lib(key: Key, blocks: &[Block]) -> Vec<Block> {
    let aes = aes::Aes128::new_from_slice(&key).unwrap();
    blocks
        .iter()
        .map(|block| {
            let mut block = (*block).into();
            aes.encrypt_block(&mut block);
            block.into()
        })
        .collect()
}

pub fn test_vs_aes(encrypt_fn: fn(key: Key, blocks: &[Block], rounds: usize) -> Vec<Block>) {
    let seed: [u8; 32] = Default::default();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut key: Key = Default::default();
    let mut block1: Block = Default::default();
    let mut block2: Block = Default::default();
    rng.fill(&mut key);
    rng.fill(&mut block1);
    rng.fill(&mut block2);
    let blocks = &[block1, block2];

    let encrypted = (encrypt_fn)(key, blocks, ROUNDS);

    assert_eq!(encrypted, encrypt_aes_lib(key, blocks));
}

pub fn test_vs_plain(
    encrypt_fn: fn(key: Key, blocks: &[Block], rounds: usize) -> Vec<Block>,
    rounds: usize,
) {
    let seed: [u8; 32] = Default::default();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut key: Key = Default::default();
    let mut block: Block = Default::default();
    rng.fill(&mut key);
    rng.fill(&mut block);
    let blocks = &[block];

    let encrypted = (encrypt_fn)(key, blocks, rounds);

    assert_eq!(
        encrypted,
        plain::expand_key_and_encrypt_blocks(key, blocks, rounds)
    );
}
