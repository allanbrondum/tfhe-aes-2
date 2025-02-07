use rayon::iter::ParallelIterator;
use rayon::iter::{IntoParallelRefIterator, ParallelBridge};
use std::fmt::Debug;
use std::ops::{BitAnd, BitXor, BitXorAssign, Index, IndexMut, ShlAssign};
use std::sync::Arc;
use tfhe::core_crypto::algorithms::{
    glwe_sample_extraction, lwe_keyswitch, lwe_programmable_bootstrapping,
};
use tfhe::core_crypto::entities::{
    Cleartext, GlweCiphertext, GlweCiphertextMutView, GlweCiphertextOwned, LweCiphertextView,
};
use tfhe::core_crypto::prelude::{
    CiphertextModulus, ComputationBuffers, Fft, GlweSize, LweCiphertextOwned, MonomialDegree,
    Plaintext, PolynomialSize,
};
use tfhe::shortint;
use tfhe::shortint::ciphertext::NoiseLevel;
use tfhe::shortint::engine::ShortintEngine;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::Ciphertext;

#[derive(Clone)]
struct FheContext {
    client_key: Arc<shortint::client_key::ClientKey>,
    server_key: Arc<shortint::server_key::ServerKey>,
}

impl FheContext {
    pub fn test_vector(&self, f: impl Fn(u64) -> u64) -> GlweCiphertextOwned<u64> {
        test_vector(
            self.server_key.bootstrapping_key.polynomial_size(),
            self.server_key.bootstrapping_key.glwe_size(),
            f,
        )
    }

    pub fn bootstrap(&self, ct: &Ciphertext, test_vector: &GlweCiphertextOwned<u64>) -> Ciphertext {
        let mut ct = ct.clone();
        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffers, buffers) = engine.get_buffers(&self.server_key);

            lwe_keyswitch::keyswitch_lwe_ciphertext(
                &self.server_key.key_switching_key,
                &ct.ct,
                &mut ciphertext_buffers.buffer_lwe_after_ks,
            );

            apply_programmable_bootstrap(
                &self.server_key.bootstrapping_key,
                &ciphertext_buffers.buffer_lwe_after_ks.as_view(),
                &mut ct.ct,
                &test_vector,
                buffers,
            );
        });

        ct.set_noise_level(NoiseLevel::NOMINAL, self.server_key.max_noise_level);
        ct
    }
}

fn apply_programmable_bootstrap(
    bootstrapping_key: &ShortintBootstrappingKey,
    in_buffer: &LweCiphertextView<u64>,
    out_buffer: &mut LweCiphertextOwned<u64>,
    acc: &GlweCiphertext<Vec<u64>>,
    buffers: &mut ComputationBuffers,
) {
    let mut glwe_out: GlweCiphertext<_> = acc.clone();

    apply_blind_rotate(
        bootstrapping_key,
        in_buffer,
        &mut glwe_out.as_mut_view(),
        buffers,
    );

    glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext(
        &glwe_out,
        out_buffer,
        MonomialDegree(0),
    );
}

fn apply_blind_rotate(
    bootstrapping_key: &ShortintBootstrappingKey,
    in_buffer: &LweCiphertextView<u64>,
    acc: &mut GlweCiphertext<&mut [u64]>,
    buffers: &mut ComputationBuffers,
) {
    let ShortintBootstrappingKey::Classic(fourier_bsk) = bootstrapping_key else {
        panic!("unsupported bootstrapping key type");
    };

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();
    buffers.resize(
        lwe_programmable_bootstrapping::programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    // Compute the blind rotation
    lwe_programmable_bootstrapping::blind_rotate_assign_mem_optimized(
        in_buffer,
        acc,
        fourier_bsk,
        fft,
        stack,
    );
}

fn encode(clear: Cleartext<u64>) -> Plaintext<u64> {
    Plaintext(clear.0 << 62)
}

fn test_vector(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    f: impl Fn(u64) -> u64,
) -> GlweCiphertextOwned<u64> {
    let mut acc = GlweCiphertext::new(
        0,
        glwe_size,
        polynomial_size,
        CiphertextModulus::new_native(),
    );

    // Modulus of the msg contained in the msg bits and operations buffer
    let input_modulus_sup = 2;

    // N/(p/2) = size of each block
    let box_size = polynomial_size.0 / input_modulus_sup;

    let mut acc_body = acc.get_mut_body();
    let mut body_slice = acc_body.as_mut();

    // Tracking the max value of the function to define the degree later

    for i in 0..input_modulus_sup {
        let index = i * box_size;
        let f_eval = f(i as u64);
        body_slice[index..index + box_size].fill(encode(Cleartext(f_eval)).0);
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients
    for a_i in body_slice[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    body_slice.rotate_left(half_box_size);

    acc
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

        let f = |idx0: u64, idx1: u64| -> u64 {
            const TABLE: [[u64; 2]; 2] = [[1, 0], [1, 0]];
            TABLE[idx0 as usize][idx1 as usize]
        };

        let m0_clear = 0;
        let m1_clear = 1;
        let m0 = client_key.encrypt(m0_clear);
        let m1 = client_key.encrypt(m1_clear);

        let tv_0 = context.test_vector(|idx0| f(idx0, 0));
        let tv_1 = context.test_vector(|idx0| f(idx0, 1));

        // let lut_0 = context.server_key.generate_lookup_table(|idx0| f(idx0, 0));
        // let lut_1 = context.server_key.generate_lookup_table(|idx0| f(idx0, 1));
        //
        // let d_0 = context.server_key.apply_lookup_table(&m0, &lut_0);
        // let d_1 = context.server_key.apply_lookup_table(&m0, &lut_1);

        let d_0 = context.bootstrap(&m0, &tv_0);
        let d_1 = context.bootstrap(&m0, &tv_1);

        assert_eq!(client_key.decrypt(&d_0), f(m0_clear, 0));
        assert_eq!(client_key.decrypt(&d_1), f(m0_clear, 1));
    }
}
