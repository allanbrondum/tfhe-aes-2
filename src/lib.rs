pub mod impls;
mod tree_lut;
/// Implementation of different TFHE models (defines keys, encodings and parameters).
/// All build on `tfhe-rs`
pub mod tfhe;


pub type Block = [u8; 16];
pub type Key = [u8; 16];
pub const ROUNDS: usize = 10;
