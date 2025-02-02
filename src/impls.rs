pub mod boolean;
pub mod tfhe_boolean;
pub mod plain;

#[cfg(test)]
mod test {
    use crate::impls::{boolean, plain, tfhe_boolean};
    use crate::{Block, Key, ROUNDS};
    use aes::cipher::{BlockEncrypt, KeyInit};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn encrypt_aes_lib(key: Key, block: Block) -> Block {
        let aes = aes::Aes128::new_from_slice(&key).unwrap();
        let mut block = block.into();
        aes.encrypt_block(&mut block);
        block.into()
    }

    fn test_vs_aes(encrypt_fn: fn(key: Key, block: Block, rounds: usize) -> Block) {
        let seed: [u8; 32] = Default::default();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut key: Key = Default::default();
        let mut block: Block = Default::default();
        rng.fill(&mut key);
        rng.fill(&mut block);

        let encrypted = (encrypt_fn)(key, block, ROUNDS);

        assert_eq!(encrypted, encrypt_aes_lib(key, block));
    }

    fn test_vs_plain(
        encrypt_fn: fn(key: Key, block: Block, rounds: usize) -> Block,
        rounds: usize,
    ) {
        let seed: [u8; 32] = Default::default();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut key: Key = Default::default();
        let mut block: Block = Default::default();
        rng.fill(&mut key);
        rng.fill(&mut block);

        let encrypted = (encrypt_fn)(key, block, rounds);

        assert_eq!(encrypted, plain::encrypt_single_block(key, block, rounds));
    }

    #[test]
    fn test_plain() {
        test_vs_aes(plain::encrypt_single_block);
    }

    #[test]
    fn test_plain2() {
        test_vs_aes(plain::encrypt_single_block);
    }

    #[test]
    fn test_boolean() {
        test_vs_plain(boolean::encrypt_single_block, 2);
    }

    #[test]
    fn test_tfhe_boolean() {
        test_vs_plain(tfhe_boolean::encrypt_single_block, 2);
    }
}
