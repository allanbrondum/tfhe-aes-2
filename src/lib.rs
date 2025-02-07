pub mod impls;
mod tree_lut;

pub type Block = [u8; 16];
pub type Key = [u8; 16];
pub const ROUNDS: usize = 10;
