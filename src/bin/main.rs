use anyhow::Context;
use clap::{Parser, ValueEnum};

use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use std::time::Instant;
use tfhe_aes::aes_128::fhe::data_model::{Block, Byte, Word};
use tfhe_aes::aes_128::{aes_lib, fhe::fhe_encryption};
use tfhe_aes::{aes_128, logger};

use tfhe_aes::aes_128::fhe::fhe_impls::shortint_1bit::Shortint1BitSboxPbsAesEncrypt;
use tfhe_aes::aes_128::fhe::fhe_impls::shortint_woppbs_1bit::ShortintWoppbs1BitSboxGalMulPbsAesEncrypt;
use tfhe_aes::aes_128::fhe::fhe_impls::shortint_woppbs_8bit::ShortintWoppbs8BitSboxPbsAesEncrypt;
use tfhe_aes::aes_128::fhe::Aes128Encrypt;
use tfhe_aes::tfhe::{
    shortint_1bit, shortint_woppbs_1bit, shortint_woppbs_8bit, ClientKeyT, ContextT,
};
use tracing::debug;
use tracing::metadata::LevelFilter;

#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "kebab-case")]
enum Implementation {
    Shortint1bit,
    ShortintWoppbs8bit,
    ShortintWoppbs1bit,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    number_of_outputs: usize,
    #[arg(long)]
    iv: String,
    #[arg(long)]
    key: String,
    #[arg(long,value_enum, default_value_t = Implementation::ShortintWoppbs1bit)]
    implementation: Implementation,
}

fn main() -> anyhow::Result<()> {
    logger::init(LevelFilter::INFO);

    let args: Args = Args::parse();

    println!("using implementation: {:?}", args.implementation);

    let key: aes_128::Key = hex::decode(&args.key)
        .context("hex decode key")?
        .try_into()
        .ok()
        .context("invalid key length, must be 16 bytes")?;

    let iv: [u8; 8] = hex::decode(&args.iv)
        .context("hex decode iv")?
        .try_into()
        .ok()
        .context("invalid iv length, must be 8 bytes")?;

    match args.implementation {
        Implementation::Shortint1bit => {
            let (client_key, context) = shortint_1bit::FheContext::generate_keys();
            run_client_server_aes_scenario::<Shortint1BitSboxPbsAesEncrypt, _>(
                &client_key,
                &context,
                key,
                iv,
                args.number_of_outputs,
            );
        }
        Implementation::ShortintWoppbs8bit => {
            let (client_key, context) = shortint_woppbs_8bit::FheContext::generate_keys();
            run_client_server_aes_scenario::<ShortintWoppbs8BitSboxPbsAesEncrypt, _>(
                &client_key,
                &context,
                key,
                iv,
                args.number_of_outputs,
            );
        }
        Implementation::ShortintWoppbs1bit => {
            let (client_key, context) = shortint_woppbs_1bit::FheContext::generate_keys_lvl_5();
            run_client_server_aes_scenario::<ShortintWoppbs1BitSboxGalMulPbsAesEncrypt, _>(
                &client_key,
                &context,
                key,
                iv,
                args.number_of_outputs,
            );
        }
    }

    Ok(())
}

fn run_client_server_aes_scenario<Enc: Aes128Encrypt, CK>(
    client_key: &CK,
    ctx: &Enc::Ctx,
    key_clear: aes_128::Key,
    iv: [u8; 8],
    block_count: usize,
) where
    CK: ClientKeyT<Bit = <Enc::Ctx as ContextT>::Bit>,
{
    // Client side: FHE encrypt AES key and block
    let key = fhe_encryption::encrypt_byte_array(client_key, &key_clear);
    let blocks_clear: Vec<_> = (1..=block_count)
        .map(|ctr| {
            let mut block = aes_128::Block::default();
            block[0..8].copy_from_slice(&iv);
            block[8..16].copy_from_slice(&ctr.to_be_bytes());
            block
        })
        .collect();
    let blocks = fhe_encryption::encrypt_blocks(client_key, &blocks_clear);
    debug!("aes key and block fhe encrypted");

    let key_schedule = expand_key::<Enc>(ctx, key);
    let encrypted_blocks = encrypt_blocks::<Enc>(ctx, key_schedule, blocks);

    // Client side (optional): FHE decrypt AES encrypted blocks
    let encrypted_blocks_clear = fhe_encryption::decrypt_blocks(client_key, &encrypted_blocks);

    let aes_lib_encrypted_blocks = aes_lib::encrypt_blocks(key_clear, &blocks_clear);

    assert_eq!(encrypted_blocks_clear, aes_lib_encrypted_blocks);
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
) -> Vec<Block<<Enc::Ctx as ContextT>::Bit>> {
    // Server side: AES encrypt blocks
    let start = Instant::now();
    let encrypted_blocks: Vec<_> = blocks
        .into_par_iter()
        // todo limit parallelization of blocks?
        .map(|block| Enc::encrypt_block(ctx, &key_schedule, block))
        .collect();
    println!(
        "AES of #{} outputs computed in: {:?}",
        encrypted_blocks.len(),
        start.elapsed()
    );
    encrypted_blocks
}
