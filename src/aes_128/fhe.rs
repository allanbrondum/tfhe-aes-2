use crate::aes_128::fhe::data_model::{Block, Byte, Word};
use crate::aes_128::ROUNDS;
use crate::tfhe::ContextT;

pub mod data_model;
/// Utilities to encrypt clear data (e.g. keys and blocks) into FHE data model
pub mod fhe_encryption;
/// Data model and logic for AES-128 encryption executed in an FHE context. Based on XOR's of individual bits
/// and using programmable bootstrap for SubBytes and the Galois multiplication in MixColumns. Generic over the TFHE model used.
/// Requires shallower leveled computation than [`fhe_sbox_pbs`] but has higher requirements on
/// programmatic bootstrap output dimension.
pub mod fhe_sbox_gal_mul_pbs;
/// FHE AES-128 implementations using different TFHE models
pub mod fhe_sbox_gal_mul_pbs_impls;
/// Data model and logic for AES-128 encryption executed in an FHE context. Based on XOR's of individual bits
/// and using programmable bootstrap for SubBytes. Generic over the TFHE model used.
/// Requires deeper leveled computation than [`fhe_sbox_pbs`] but has lesser requirements on
/// programmatic bootstrap output dimension.
pub mod fhe_sbox_pbs;
/// FHE AES-128 implementations using different TFHE models
pub mod fhe_sbox_pbs_impls;

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
