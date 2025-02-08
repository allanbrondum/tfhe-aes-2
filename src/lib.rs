// pub mod impls;

/// EAS encryption implementations
pub mod aes_128;
/// Implementation of different TFHE models (defines keys, encodings and parameters).
/// All build on `tfhe-rs`. Implements no AES specific logic
pub mod tfhe;
mod util;
pub mod logger;
