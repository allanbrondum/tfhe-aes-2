use crate::aes_128::fhe::data_model::{Block, Byte, Word};
use crate::aes_128::ROUNDS;
use crate::tfhe::ContextT;

/// Data model used by the AES-128 FHE implementations
pub mod data_model;
/// Utilities to (FHE) encrypt clear data (e.g. keys and blocks) into FHE data model
pub mod fhe_encryption;
/// FHE AES-128 implementations instantiated in concrete FHE models
pub mod fhe_impls;
/// Implementation of AES-128 encryption that relies on programmatic bootstrapping for SBOX lookup and Galois multiplication.
pub mod fhe_sbox_gal_mul_pbs;
/// Implementation of AES-128 encryption that relies on programmatic bootstrapping for SBOX lookup.
pub mod fhe_sbox_pbs;

pub trait Aes128Encrypt {
    type Ctx: ContextT;

    fn encrypt_block(
        ctx: &Self::Ctx,
        expanded_key: &[Word<<Self::Ctx as ContextT>::Bit>; 44],
        block: Block<<Self::Ctx as ContextT>::Bit>,
    ) -> Block<<Self::Ctx as ContextT>::Bit> {
        Self::encrypt_block_for_rounds(ctx, expanded_key, block, ROUNDS)
    }

    fn encrypt_block_for_rounds(
        ctx: &Self::Ctx,
        expanded_key: &[Word<<Self::Ctx as ContextT>::Bit>; 44],
        block: Block<<Self::Ctx as ContextT>::Bit>,
        rounds: usize,
    ) -> Block<<Self::Ctx as ContextT>::Bit>;

    fn key_schedule(
        ctx: &Self::Ctx,
        key_slice: &[Byte<<Self::Ctx as ContextT>::Bit>; 16],
    ) -> [Word<<Self::Ctx as ContextT>::Bit>; 44];
}
