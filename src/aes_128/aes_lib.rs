

use aes::cipher::{BlockEncrypt, KeyInit};
use crate::aes_128::{Block, Key};

pub fn encrypt_blocks(key: Key, blocks: &[Block]) -> Vec<Block> {
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