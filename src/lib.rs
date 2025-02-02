pub mod impls;

pub type Block = [u8; 16];
pub type Key = [u8; 16];
pub const ROUNDS: usize = 10;