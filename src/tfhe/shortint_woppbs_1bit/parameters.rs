use tfhe::core_crypto::prelude::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, LweDimension, PolynomialSize, StandardDev,
};
use tfhe::shortint::{
    CarryModulus, EncryptionKeyChoice, MaxNoiseLevel, MessageModulus, WopbsParameters,
};

#[derive(Debug, Clone)]
pub struct Shortint1bitWopbsParameters {
    pub inner: WopbsParameters,
    pub max_noise_level_squared: MaxNoiseLevel,
}

/// Parameters created from
///
/// ```text
/// ./optimizer  --min-precision 1 --max-precision 1 --p-error 5.42101086e-20 --ciphertext-modulus-log 64 --wop-pbs
/// security level: 128
/// target p_error: 5.4e-20
/// per precision and log norm2:
///
/// - 1: # bits
/// -ln2:   k,  N,    n, br_l,br_b, ks_l,ks_b, cb_l,cb_b, pp_l,pp_b,  cost, p_error
/// ...
/// - 0 :   2, 10,  671,    2, 15,     4,  3,     1, 10,     1, 24,    111, 4.2e-20
/// ...
/// ```
pub fn params_sqrd_lvl_1() -> Shortint1bitWopbsParameters {
    let inner = WopbsParameters {
        lwe_dimension: LweDimension(671),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.676348397087967e-5,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        pbs_level: DecompositionLevelCount(2),
        pbs_base_log: DecompositionBaseLog(15),
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(3),
        cbs_level: DecompositionLevelCount(1),
        cbs_base_log: DecompositionBaseLog(10),
        pfks_level: DecompositionLevelCount(1),
        pfks_base_log: DecompositionBaseLog(24),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

    Shortint1bitWopbsParameters {
        inner,
        max_noise_level_squared: MaxNoiseLevel::new(1),
    }
}

/// Parameters created from
///
/// ```text
/// ./optimizer  --min-precision 1 --max-precision 1 --p-error 5.42101086e-20 --ciphertext-modulus-log 64 --wop-pbs
/// security level: 128
/// target p_error: 5.4e-20
/// per precision and log norm2:
///
/// - 1: # bits
/// -ln2:   k,  N,    n, br_l,br_b, ks_l,ks_b, cb_l,cb_b, pp_l,pp_b,  cost, p_error
/// ...
/// - 5 :   2, 10,  649,    6,  7,     6,  2,     1, 15,     3, 12,    268, 4.8e-20
/// ...
/// ```
pub fn params_sqrd_lvl_32() -> Shortint1bitWopbsParameters {
    let inner = WopbsParameters {
        lwe_dimension: LweDimension(649),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.27510880527384e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        pbs_level: DecompositionLevelCount(6),
        pbs_base_log: DecompositionBaseLog(7),
        ks_level: DecompositionLevelCount(6),
        ks_base_log: DecompositionBaseLog(2),
        cbs_level: DecompositionLevelCount(1),
        cbs_base_log: DecompositionBaseLog(15),
        pfks_level: DecompositionLevelCount(3),
        pfks_base_log: DecompositionBaseLog(12),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

    Shortint1bitWopbsParameters {
        inner,
        max_noise_level_squared: MaxNoiseLevel::new(32),
    }
}

/// Parameters created from
///
/// ```text
/// ./optimizer  --min-precision 1 --max-precision 1 --p-error 5.42101086e-20 --ciphertext-modulus-log 64 --wop-pbs
/// security level: 128
/// target p_error: 5.4e-20
/// per precision and log norm2:
///
/// - 1: # bits
/// -ln2:   k,  N,    n, br_l,br_b, ks_l,ks_b, cb_l,cb_b, pp_l,pp_b,  cost, p_error
/// ...
/// - 6 :   2, 10,  634,    3, 12,     6,  2,     2,  8,     2, 16,    308, 3.7e-20
/// ...
/// ```
pub fn params_sqrd_lvl_64() -> Shortint1bitWopbsParameters {
    let inner = WopbsParameters {
        lwe_dimension: LweDimension(634),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.27510880527384e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        pbs_level: DecompositionLevelCount(3),
        pbs_base_log: DecompositionBaseLog(12),
        ks_level: DecompositionLevelCount(6),
        ks_base_log: DecompositionBaseLog(2),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(8),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(16),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

    Shortint1bitWopbsParameters {
        inner,
        max_noise_level_squared: MaxNoiseLevel::new(64),
    }
}

/// Parameters created from
///
/// ```text
/// ./optimizer  --min-precision 1 --max-precision 1 --p-error 5.42101086e-20 --ciphertext-modulus-log 64 --wop-pbs
/// security level: 128
/// target p_error: 5.4e-20
/// per precision and log norm2:
///
/// - 1: # bits
/// -ln2:   k,  N,    n, br_l,br_b, ks_l,ks_b, cb_l,cb_b, pp_l,pp_b,  cost, p_error
/// ...
/// - 7 :   4,  9,  661,    3, 12,     6,  2,     2,  9,     2, 16,    353, 5.3e-20
/// ...
/// ```
pub fn params_sqrd_lvl_128() -> Shortint1bitWopbsParameters {
    let inner = WopbsParameters {
        lwe_dimension: LweDimension(661),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.676348397087967e-5,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_level: DecompositionLevelCount(3),
        pbs_base_log: DecompositionBaseLog(12),
        ks_level: DecompositionLevelCount(6),
        ks_base_log: DecompositionBaseLog(2),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(16),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

    Shortint1bitWopbsParameters {
        inner,
        max_noise_level_squared: MaxNoiseLevel::new(128),
    }
}

/// Parameters created from
///
/// ```text
/// ./optimizer  --min-precision 1 --max-precision 1 --p-error 5.42101086e-20 --ciphertext-modulus-log 64 --wop-pbs
/// security level: 128
/// target p_error: 5.4e-20
/// per precision and log norm2:
///
/// - 1: # bits
/// -ln2:   k,  N,    n, br_l,br_b, ks_l,ks_b, cb_l,cb_b, pp_l,pp_b,  cost, p_error
/// ...
/// - 8 :   2, 10,  655,    4,  9,     6,  2,     2,  9,     2, 16,    368, 4.2e-20
/// ...
/// ```
pub fn params_sqrd_lvl_256() -> Shortint1bitWopbsParameters {
    let inner = WopbsParameters {
        lwe_dimension: LweDimension(655),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00003604499526942373,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        pbs_level: DecompositionLevelCount(4),
        pbs_base_log: DecompositionBaseLog(9),
        ks_level: DecompositionLevelCount(6),
        ks_base_log: DecompositionBaseLog(2),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(16),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

    Shortint1bitWopbsParameters {
        inner,
        max_noise_level_squared: MaxNoiseLevel::new(256),
    }
}

/// Parameters created from
///
/// ```text
/// ./optimizer  --min-precision 1 --max-precision 1 --p-error 5.42101086e-20 --ciphertext-modulus-log 64 --wop-pbs
/// security level: 128
/// target p_error: 5.4e-20
/// per precision and log norm2:
///
///   - 1: # bits
///     -ln2:   k,  N,    n, br_l,br_b, ks_l,ks_b, cb_l,cb_b, pp_l,pp_b,  cost, p_error
/// ...
///     - 11:   2, 10,  640,    5,  8,     6,  2,     3,  7,     3, 12,    687, 4.2e-20
/// ...
/// ```
pub fn params_sqrd_lvl_2048() -> Shortint1bitWopbsParameters {
    let inner = WopbsParameters {
        lwe_dimension: LweDimension(640),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.27510880527384e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        pbs_level: DecompositionLevelCount(5),
        pbs_base_log: DecompositionBaseLog(8),
        ks_level: DecompositionLevelCount(6),
        ks_base_log: DecompositionBaseLog(2),
        cbs_level: DecompositionLevelCount(3),
        cbs_base_log: DecompositionBaseLog(7),
        pfks_level: DecompositionLevelCount(3),
        pfks_base_log: DecompositionBaseLog(12),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

    Shortint1bitWopbsParameters {
        inner,
        max_noise_level_squared: MaxNoiseLevel::new(2048),
    }
}

// let pbs_params = ClassicPBSParameters {
//     lwe_dimension: wopbs_params.lwe_dimension,
//     glwe_dimension: wopbs_params.glwe_dimension,
//     polynomial_size: wopbs_params.polynomial_size,
//     lwe_noise_distribution: wopbs_params.lwe_noise_distribution,
//     glwe_noise_distribution: wopbs_params.glwe_noise_distribution,
//     pbs_base_log: wopbs_params.pbs_base_log,
//     pbs_level: wopbs_params.pbs_level,
//     ks_base_log: wopbs_params.ks_base_log,
//     ks_level: wopbs_params.ks_level,
//     message_modulus: wopbs_params.message_modulus,
//     carry_modulus: wopbs_params.carry_modulus,
//     max_noise_level: MaxNoiseLevel::new(1),
//     log2_p_fail: -64.074,
//     ciphertext_modulus: wopbs_params.ciphertext_modulus,
//     encryption_key_choice: wopbs_params.encryption_key_choice,
// };

// ShortintParameterSet::try_new_pbs_and_wopbs_param_set((pbs_params, wopbs_params)).unwrap()
