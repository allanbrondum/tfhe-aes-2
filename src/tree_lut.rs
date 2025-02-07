use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::iter::{IntoParallelRefIterator, ParallelBridge};
use std::fmt::Debug;
use std::iter;
use std::ops::{BitAnd, BitXor, BitXorAssign, Index, IndexMut, ShlAssign};
use std::sync::Arc;
use tfhe::core_crypto::algorithms::{
    glwe_sample_extraction, lwe_keyswitch, lwe_programmable_bootstrapping,
};
use tfhe::core_crypto::entities::{
    Cleartext, GlweCiphertext, GlweCiphertextMutView, GlweCiphertextOwned, LweCiphertextView,
};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint;
use tfhe::shortint::ciphertext::NoiseLevel;
use tfhe::shortint::engine::ShortintEngine;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{
    CarryModulus, Ciphertext, ClassicPBSParameters, MaxNoiseLevel, MessageModulus,
};

const PARAMS: ClassicPBSParameters = ClassicPBSParameters {
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
    encryption_key_choice: EncryptionKeyChoice::Small,
};

#[derive(Clone)]
pub struct Shortint1BitFheContext {
    client_key: Arc<shortint::client_key::ClientKey>,
    server_key: Arc<shortint::server_key::ServerKey>,
    packing_keyswitch_key: Arc<LwePackingKeyswitchKeyOwned<u64>>,
}

pub struct TestVector(GlweCiphertextOwned<u64>);

impl Shortint1BitFheContext {
    pub fn generate_keys() -> (Arc<shortint::ClientKey>, Self) {
        Self::generate_keys_with_params(PARAMS)
    }

    fn generate_keys_with_params(params: ClassicPBSParameters) -> (Arc<shortint::ClientKey>, Self) {
        let (client_key, server_key) = shortint::gen_keys(params);

        let packing_keyswitch_key = ShortintEngine::with_thread_local_mut(|engine| {
            lwe_packing_keyswitch_key_generation::allocate_and_generate_new_lwe_packing_keyswitch_key(
                &client_key.lwe_secret_key,
                &client_key.glwe_secret_key,
                params.ks_base_log,
                params.ks_level,
                params.lwe_noise_distribution,
                params.ciphertext_modulus,
                &mut engine.encryption_generator,
            )
        });

        let context = Shortint1BitFheContext {
            client_key: client_key.clone().into(),
            server_key: server_key.into(),
            packing_keyswitch_key: packing_keyswitch_key.into(),
        };

        (context.client_key.clone(), context)
    }

    pub fn test_vector_from_cleartext_fn(&self, f: impl Fn(u64) -> u64) -> TestVector {
        TestVector(test_vector_from_cleartext_fn(
            self.server_key.bootstrapping_key.polynomial_size(),
            self.server_key.bootstrapping_key.glwe_size(),
            f,
        ))
    }

    pub fn test_vector_from_ciphertexts(
        &self,
        ct0: &shortint::Ciphertext,
        ct1: &shortint::Ciphertext,
    ) -> TestVector {
        TestVector(test_vector_from_ciphertexts(
            &self.packing_keyswitch_key.as_view(),
            self.server_key.bootstrapping_key.polynomial_size(),
            &ct0.ct,
            &ct1.ct,
        ))
    }

    pub fn packing_keyswitch(&self, cts: &[&shortint::Ciphertext]) -> GlweCiphertextOwned<u64> {
        let in_data: Vec<u64> = cts
            .iter()
            .flat_map(|ct| ct.ct.as_ref().iter().copied())
            .collect();

        let ins = LweCiphertextListOwned::from_container(
            in_data,
            self.packing_keyswitch_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            CiphertextModulus::new_native(),
        );
        keyswitch_and_pack_ciphertext_list(&self.packing_keyswitch_key.as_view(), &ins.as_view())
    }

    pub fn bootstrap(
        &self,
        ct: &shortint::Ciphertext,
        test_vector: &TestVector,
    ) -> shortint::Ciphertext {
        let mut ct = ct.clone();
        self.bootstrap_assign(&mut ct, test_vector);
        ct
    }

    pub fn bootstrap_assign(&self, ct: &mut shortint::Ciphertext, test_vector: &TestVector) {
        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffers, buffers) = engine.get_buffers(&self.server_key);

            apply_programmable_bootstrap(
                &self.server_key.bootstrapping_key,
                &ct.ct.as_view(),
                &mut ciphertext_buffers.buffer_lwe_after_pbs.as_mut_view(),
                &test_vector.0,
                buffers,
            );

            lwe_keyswitch::keyswitch_lwe_ciphertext(
                &self.server_key.key_switching_key,
                &ciphertext_buffers.buffer_lwe_after_pbs.as_view(),
                &mut ct.ct,
            );
        });

        ct.set_noise_level(NoiseLevel::NOMINAL, self.server_key.max_noise_level);
    }

    // pub fn packing_key_switch_single(&self, ct: &shortint::Ciphertext) -> GlweCiphertextOwned<u64> {
    //     let out = ShortintEngine::with_thread_local_mut(|engine| {
    //         let mut out = GlweCiphertextOwned::new(
    //             0,
    //             self.packing_keyswitch_key.output_glwe_size(),
    //             self.packing_keyswitch_key.output_polynomial_size(),
    //             CiphertextModulus::new_native(),
    //         );
    //         lwe_packing_keyswitch::keyswitch_lwe_ciphertext_into_glwe_ciphertext(
    //             &self.packing_keyswitch_key,
    //             &ct.ct,
    //             &mut out,
    //         );
    //         out
    //     });
    //
    //     out
    // }
}

fn apply_programmable_bootstrap(
    bootstrapping_key: &ShortintBootstrappingKey,
    in_buffer: &LweCiphertextView<u64>,
    out_buffer: &mut LweCiphertextMutView<u64>,
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
    acc: &mut GlweCiphertextMutView<u64>,
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
    // 0/1 bit is represented at next highest bit
    Plaintext(clear.0 << 62)
}

fn decode(plain: Plaintext<u64>) -> Cleartext<u64> {
    let decomposer = SignedDecomposer::new(DecompositionBaseLog(2), DecompositionLevelCount(1));
    // 0/1 bit is represented at next highest bit
    Cleartext((decomposer.closest_representable(plain.0) >> 62) & 1)
}

fn test_vector_from_cleartext_fn(
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

    let mut acc_body = acc.get_mut_body();
    let mut body_slice = acc_body.as_mut();

    // Fill accumulator with f evaluated at 0 and 1
    let box_size = polynomial_size.0 / 2;
    body_slice[0..box_size].fill(encode(Cleartext(f(0))).0);
    body_slice[box_size..2 * box_size].fill(encode(Cleartext(f(1))).0);

    // Rotate the accumulator
    let half_box_size = box_size / 2;
    body_slice.rotate_left(half_box_size);

    acc
}

fn test_vector_from_ciphertexts(
    packing_keyswitch_key: &LwePackingKeyswitchKeyView<u64>,
    polynomial_size: PolynomialSize,
    ct0: &LweCiphertextOwned<u64>,
    ct1: &LweCiphertextOwned<u64>,
) -> GlweCiphertextOwned<u64> {
    // Create ciphertext list to be transformed to test vector
    let box_size = polynomial_size.0 / 2;
    let half_box_size = box_size / 2;
    // todo reuse buffers
    let list_data: Vec<u64> = iter::repeat(ct0)
        .take(half_box_size)
        .chain(iter::repeat(ct1).take(box_size))
        .chain(iter::repeat(ct0).take(box_size - half_box_size))
        .flat_map(|ct| ct.as_ref())
        .copied()
        .collect();
    let mut ciphertext_list = LweCiphertextListOwned::from_container(
        list_data,
        packing_keyswitch_key
            .input_key_lwe_dimension()
            .to_lwe_size(),
        CiphertextModulus::new_native(),
    );

    keyswitch_and_pack_ciphertext_list(packing_keyswitch_key, &ciphertext_list.as_view())
}

fn keyswitch_and_pack_ciphertext_list(
    packing_keyswitch_key: &LwePackingKeyswitchKeyView<u64>,
    ciphertext_list: &LweCiphertextListView<u64>,
) -> GlweCiphertextOwned<u64> {
    let mut out = GlweCiphertextOwned::new(
        0,
        packing_keyswitch_key.output_glwe_size(),
        packing_keyswitch_key.output_polynomial_size(),
        CiphertextModulus::new_native(),
    );
    lwe_packing_keyswitch::keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        &packing_keyswitch_key,
        &ciphertext_list,
        &mut out,
    );
    out
}

pub fn apply_2bit_multivariate_function(
    ct0: &shortint::Ciphertext,
    ct1: &shortint::Ciphertext,
    f: impl Fn(u8) -> Cleartext<u64>,
) {
    for m0 in 0..1 {
        for m1 in 0..1 {}
    }
}

fn apply_selectors_rec<'a>(
    context: &Shortint1BitFheContext,
    selectors: &[shortint::Ciphertext],
    test_vectors: &'a [TestVector],
) -> shortint::Ciphertext {
    let (selector, selectors_rec) = selectors.split_first().expect("at least one selector");

    if selectors_rec.is_empty() {
        assert_eq!(test_vectors.len(), 1);
        context.bootstrap(selector, &test_vectors[0])
    } else {
        assert!(!test_vectors.is_empty());
        assert_eq!(test_vectors.len() % 2, 0);
        let test_vectors_rec: Vec<_> = test_vectors
            .par_iter()
            .map(|tv| context.bootstrap(selector, tv))
            .chunks(2)
            .map(|tv| context.test_vector_from_ciphertexts(&tv[0], &tv[1]))
            .collect();
        apply_selectors_rec(context, selectors_rec, &test_vectors_rec)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Arc;
    use tfhe::core_crypto::prelude::*;
    use tfhe::shortint::{CarryModulus, ClassicPBSParameters, MaxNoiseLevel, MessageModulus};

    #[test]
    fn test_packing_keyswitch() {
        let (client_key, context) = Shortint1BitFheContext::generate_keys();

        let ct0_clear = 0;
        let ct1_clear = 1;
        let ct0 = client_key.encrypt(ct0_clear);
        let ct1 = client_key.encrypt(ct1_clear);

        let packed = context.packing_keyswitch(&[&ct0, &ct1]);
        let mut packed_plain = PlaintextList::new(0, PlaintextCount(packed.polynomial_size().0));
        glwe_encryption::decrypt_glwe_ciphertext(
            &client_key.glwe_secret_key,
            &packed,
            &mut packed_plain,
        );

        assert_eq!(
            decode(Plaintext(packed_plain.as_ref()[0])),
            Cleartext(0),
            "plain: {:064b}",
            packed_plain.as_ref()[0]
        );
        assert_eq!(
            decode(Plaintext(packed_plain.as_ref()[1])),
            Cleartext(1),
            "plain: {:064b}",
            packed_plain.as_ref()[1]
        );
        assert_eq!(
            decode(Plaintext(packed_plain.as_ref()[2])),
            Cleartext(0),
            "plain: {:064b}",
            packed_plain.as_ref()[1]
        );
        assert_eq!(
            decode(Plaintext(packed_plain.as_ref()[3])),
            Cleartext(0),
            "plain: {:064b}",
            packed_plain.as_ref()[1]
        );
        assert_eq!(
            decode(Plaintext(packed_plain.as_ref()[4])),
            Cleartext(0),
            "plain: {:064b}",
            packed_plain.as_ref()[1]
        );
    }

    #[test]
    fn test_tree_lut_2() {
        let (client_key, context) = Shortint1BitFheContext::generate_keys();

        let f = |idx0: u64, idx1: u64| -> u64 {
            const TABLE: [[u64; 2]; 2] = [[1, 0], [1, 0]];
            TABLE[idx0 as usize][idx1 as usize]
        };

        let m0_clear = 0;
        let m1_clear = 1;
        let m0 = client_key.encrypt(m0_clear);
        let m1 = client_key.encrypt(m1_clear);

        let tv_0 = context.test_vector_from_cleartext_fn(|idx0| f(idx0, 0));
        let tv_1 = context.test_vector_from_cleartext_fn(|idx0| f(idx0, 1));

        let d_0 = context.bootstrap(&m0, &tv_0);
        let d_1 = context.bootstrap(&m0, &tv_1);

        assert_eq!(client_key.decrypt(&d_0), f(m0_clear, 0));
        assert_eq!(client_key.decrypt(&d_1), f(m0_clear, 1));

        let tv = context.test_vector_from_ciphertexts(&d_0, &d_1);
        let d = context.bootstrap(&m1, &tv);
        assert_eq!(client_key.decrypt(&d), f(m0_clear, m1_clear));
    }
}
