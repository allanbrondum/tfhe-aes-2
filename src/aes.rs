/// Plain AES-128 implementation used for testing reference (e.g. running less than 10 rounds)
pub mod plain;
#[cfg(test)]
mod test_helper;

pub type Block = [u8; 16];
pub type Key = [u8; 16];
const ROUNDS: usize = 10;