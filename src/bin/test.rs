use aes::cipher::{BlockEncrypt, KeyInit};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

// use tfhe_aes::{Block, Key, ROUNDS};
//
fn main() {
//     let seed: [u8; 32] = [0; 32];
//
//     let mut rng = ChaCha20Rng::from_seed(seed);
//
//     let mut key = [0u8; 16];
//     let mut iv = [0u8; 8];
//     rng.fill(&mut key);
//     rng.fill(&mut iv);
//
//     let counter: u64 = 1;
//     let mut block = [0u8; 16];
//     block[0..8].copy_from_slice(&iv);
//     block[8..16].copy_from_slice(&counter.to_be_bytes());
//
//     println!("block: {}", hex::encode(&block));
//
//     let encrypted = encrypt_plain(key, block);
//     println!("encrypted plain: {}", hex::encode(&encrypted));
//
//     let encrypted = encrypt_aes_lib(key, block);
//     println!("encrypted aes lib: {}", hex::encode(&encrypted));
}
//
// fn encrypt_plain(key: Key, block: Block) -> Block {
//     let key_schedule = plain::key_schedule(&key);
//     let encrypted = plain::encrypt_block(&key_schedule, block, ROUNDS);
//     encrypted
// }
//
// fn encrypt_aes_lib(key: Key, block: Block) -> Block {
//     let aes = aes::Aes128::new_from_slice(&key).unwrap();
//     let mut block = block.into();
//     aes.encrypt_block(&mut block);
//     block.into()
// }
