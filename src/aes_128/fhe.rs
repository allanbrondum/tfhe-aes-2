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
