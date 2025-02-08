use aes::cipher::{BlockEncrypt, KeyInit};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use std::time::Instant;
use tfhe_aes::aes_128;
use tfhe_aes::aes_128::fhe::data_model::{BitT, Block, Byte, ByteT};
use tfhe_aes::aes_128::{aes_lib, fhe, fhe_encryption};
use tfhe_aes::tfhe::{shortint_woppbs_8bit, ClientKeyT};
use tracing::debug;

fn main() {
    debug!("start");

    // Client side: generate keys
    let (client_key, _context) = shortint_woppbs_8bit::FheContext::generate_keys();
}

fn run_client_server_aes_scenario<Bit, CK>(
    client_key: &CK,
    key_clear: aes_128::Key,
    blocks_clear: &[aes_128::Block],
) where
    Bit: BitT,
    Byte<Bit>: ByteT,
    CK: ClientKeyT<Bit> + Sync,
{
    // Client side: FHE encrypt AES key and block
    let key = fhe_encryption::fhe_encrypt_byte_array(client_key, &key_clear);
    let blocks: Vec<_> = blocks_clear
        .iter()
        .map(|block| fhe_encryption::fhe_encrypt_byte_array(client_key, &block))
        .collect();
    debug!("aes key and block fhe encrypted");

    let encrypted_blocks = expand_key_and_encrypt_blocks(&key, &blocks);

    // Client side (optional): FHE decrypt AES encrypted blocks
    let encrypted_blocks_clear = encrypted_blocks
        .iter()
        .map(|block| fhe_encryption::fhe_decrypt_byte_array(client_key, block))
        .collect();

    let aes_lib_encrypted_blocks = aes_lib::encrypt_blocks(key_clear, blocks_clear);

    assert_eq!(encrypted_blocks_clear, aes_lib_encrypted_blocks);
}

fn expand_key_and_encrypt_blocks<Bit, CK>(
    key: &[Byte<Bit>; 16],
    blocks: &[Block<Bit>],
) -> Vec<Block<Bit>>
where
    Bit: BitT,
    Byte<Bit>: ByteT,
    CK: ClientKeyT<Bit> + Sync,
{
    // Server side (optional): AES encrypt blocks
    let start = Instant::now();
    let key_schedule = fhe::key_schedule(&key);
    println!("AES key expansion took: {:?}", start.elapsed());

    // Server side: AES encrypt blocks
    let start = Instant::now();
    let encrypted_blocks: Vec<_> = blocks
        .into_par_iter()
        .map(|block| fhe::encrypt_block(&key_schedule, block))
        .collect();
    println!(
        "AES of #{} outputs computed in: {:?}",
        encrypted_blocks.len(),
        start.elapsed()
    );
}
