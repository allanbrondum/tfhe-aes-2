use rayon::iter::ParallelIterator;
use rayon::iter::{IntoParallelRefIterator, ParallelBridge};
use std::fmt::Debug;
use std::ops::{BitAnd, BitXor, BitXorAssign, Index, IndexMut, ShlAssign};
use std::sync::Arc;
use tfhe::shortint;


#[derive(Clone)]
struct FheContext {
    client_key: Arc<shortint::client_key::ClientKey>,
    server_key: Arc<shortint::server_key::ServerKey>,
}


#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Arc;
    use tfhe::core_crypto::prelude::*;
    use tfhe::shortint::{CarryModulus, ClassicPBSParameters, MaxNoiseLevel, MessageModulus};

    // 1 bit
    const PARAMS1: ClassicPBSParameters = ClassicPBSParameters {
        lwe_dimension: LweDimension(692),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.5539902359442825e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(12),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(20),
        log2_p_fail: -64.074,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };



    fn keys() -> (Arc<shortint::ClientKey>, FheContext) {
        let (client_key, server_key) = shortint::gen_keys(PARAMS1);

        let context = FheContext {
            client_key: client_key.clone().into(),
            server_key: server_key.into(),
        };

        (context.client_key.clone(), context)
    }

    #[test]
    fn test_tree_lut_2() {
        let (client_key, context) = keys();

        let f= |idx0:u64, idx1:u64| -> u64 {
            const TABLE: [[u64; 2]; 2] = [[1, 0], [1, 0]];
            TABLE[idx0 as usize][idx1 as usize]
        };

        let m0_clear = 0;
        let m1_clear = 1;
        let m0 = client_key.encrypt(m0_clear);
        let m1 = client_key.encrypt(m1_clear);

        let lut_0 = context.server_key.generate_lookup_table(|idx0| f(idx0, 0));
        let lut_1 = context.server_key.generate_lookup_table(|idx0| f(idx0, 1));

        let d_0 = context.server_key.apply_lookup_table(&m0, &lut_0);
        let d_1 = context.server_key.apply_lookup_table(&m0, &lut_1);

        assert_eq!(client_key.decrypt(&d_0), f(m0_clear, 0));
        assert_eq!(client_key.decrypt(&d_1), f(m0_clear, 1));
    }


}
