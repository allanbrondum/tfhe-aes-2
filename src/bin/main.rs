use anyhow::Context;
use clap::Parser;

use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use std::time::Instant;
use tfhe_aes::aes_128;
use tfhe_aes::aes_128::fhe::data_model::{BitT, Block, Byte, ByteT};
use tfhe_aes::aes_128::{aes_lib, fhe, fhe_encryption, Key};
use tfhe_aes::tfhe::{shortint_woppbs_8bit, ClientKeyT};
use tracing::debug;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    number_of_outputs: usize,
    iv: String,
    key: String,
}

fn main() -> anyhow::Result<()> {
    let args: Args = Args::parse();

    let key: Key = hex::decode(&args.key)
        .context("hex decode key")?
        .try_into()
        .ok()
        .context("invalid key length, must be 16 bytes")?;

    let iv: [u8; 8] = hex::decode(&args.key)
        .context("hex decode iv")?
        .try_into()
        .ok()
        .context("invalid iv length, must be 8 bytes")?;

    // Client side: generate keys
    let (client_key, _context) = shortint_woppbs_8bit::FheContext::generate_keys();

    run_client_server_aes_scenario(&client_key, key, iv, args.number_of_outputs);

    Ok(())
}

fn run_client_server_aes_scenario<Bit, CK>(
    client_key: &CK,
    key_clear: aes_128::Key,
    iv: [u8; 8],
    block_count: usize,
) where
    Bit: BitT,
    Byte<Bit>: ByteT,
    CK: ClientKeyT<Bit> + Sync,
{
    // Client side: FHE encrypt AES key and block
    let key = fhe_encryption::fhe_encrypt_byte_array(client_key, &key_clear);
    let blocks_clear: Vec<_> = (1..=block_count)
        .map(|ctr| {
            let mut block = aes_128::Block::default();
            block[0..8].copy_from_slice(&iv);
            block[8..16].copy_from_slice(&ctr.to_be_bytes());
            block
        })
        .collect();
    let blocks: Vec<_> = blocks_clear
        .iter()
        .map(|block| fhe_encryption::fhe_encrypt_byte_array(client_key, &block))
        .collect();
    debug!("aes key and block fhe encrypted");

    let encrypted_blocks = expand_key_and_encrypt_blocks(key, blocks);

    // Client side (optional): FHE decrypt AES encrypted blocks
    let encrypted_blocks_clear: Vec<_> = encrypted_blocks
        .iter()
        .map(|block| fhe_encryption::fhe_decrypt_byte_array(client_key, block))
        .collect();

    let aes_lib_encrypted_blocks = aes_lib::encrypt_blocks(key_clear, &blocks_clear);

    assert_eq!(encrypted_blocks_clear, aes_lib_encrypted_blocks);
}

fn expand_key_and_encrypt_blocks<Bit>(
    key: [Byte<Bit>; 16],
    blocks: Vec<Block<Bit>>,
) -> Vec<Block<Bit>>
where
    Bit: BitT,
    Byte<Bit>: ByteT,
{
    // Server side (optional): AES encrypt blocks
    let start = Instant::now();
    let key_schedule = fhe::key_schedule(&key);
    println!("AES key expansion took: {:?}", start.elapsed());

    // Server side: AES encrypt blocks
    let start = Instant::now();
    let encrypted_blocks: Vec<_> = blocks
        .into_par_iter()
        // todo limit
        .map(|block| fhe::encrypt_block(&key_schedule, block))
        .collect();
    println!(
        "AES of #{} outputs computed in: {:?}",
        encrypted_blocks.len(),
        start.elapsed()
    );
    encrypted_blocks
}
