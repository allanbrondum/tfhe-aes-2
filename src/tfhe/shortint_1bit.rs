//! Model with each ciphertext representing 1 bit. Build on `tfhe-rs` `shortint` module but with
//! additional primitives for multivariate function bootstrapping

use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::iter::{IntoParallelRefIterator, ParallelBridge};
use std::fmt::Debug;
use std::iter;
use std::ops::{BitAnd, BitXor, BitXorAssign, Index, IndexMut, ShlAssign};
use std::sync::Arc;
use std::time::Instant;
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
use tfhe::shortint::{CarryModulus, ClassicPBSParameters, MaxNoiseLevel, MessageModulus};
use tracing::debug;
use crate::tfhe::ClientKeyT;

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
pub struct BitCt {
    ct: shortint::Ciphertext,
    context: FheContext,
}

impl BitCt {
    fn new(ct: shortint::Ciphertext, context: FheContext) -> Self {
        Self { ct, context }
    }

    // pub fn trivial(bit: u64, context: FheContext) -> Self {
    //     let ct = lwe_encryption::allocate_and_trivially_encrypt_new_lwe_ciphertext(
    //         context
    //             .server_key
    //             .bootstrapping_key
    //             .input_lwe_dimension()
    //             .to_lwe_size(),
    //         Self::encode(b),
    //         CiphertextModulus::new_native(),
    //     );
    //
    //     Self {
    //         ct,
    //         context,
    //     }
    // }
}

#[derive(Clone)]
pub struct FheContext {
    server_key: Arc<shortint::server_key::ServerKey>,
    packing_keyswitch_key: Arc<LwePackingKeyswitchKeyOwned<u64>>,
}

pub struct ClientKey(shortint::ClientKey, FheContext);

impl ClientKeyT<BitCt> for ClientKey {
    fn encrypt(&self, bit: Cleartext<u64>) -> BitCt {
        let ct = self.0.encrypt(bit.0);
        BitCt::new(ct, self.1.clone())
    }

    fn decrypt(&self, bit: &BitCt) -> Cleartext<u64> {
        Cleartext(self.0.decrypt(&bit.ct))
    }
}

impl FheContext {
    pub fn generate_keys() -> (ClientKey, Self) {
        Self::generate_keys_with_params(PARAMS)
    }

    fn generate_keys_with_params(params: ClassicPBSParameters) -> (ClientKey, Self) {
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

        let context = FheContext {
            server_key: server_key.into(),
            packing_keyswitch_key: packing_keyswitch_key.into(),
        };

        (ClientKey(client_key, context.clone()), context)
    }

    /// Create test vector from a cleartext function. The returned test vector can be used
    /// for functional bootstrapping
    pub fn test_vector_from_cleartext_fn(
        &self,
        f: impl Fn(Cleartext<u64>) -> Cleartext<u64>,
    ) -> TestVector {
        TestVector(test_vector_from_cleartext_fn(
            self.server_key.bootstrapping_key.polynomial_size(),
            self.server_key.bootstrapping_key.glwe_size(),
            f,
        ))
    }

    /// Create test vector from two ciphertexts. Can be used to select one of the ciphertexts
    /// when bootstrapping another ciphertext.
    pub fn test_vector_from_ciphertexts(&self, bit0: &BitCt, bit1: &BitCt) -> TestVector {
        let start = Instant::now();
        // todo optimize encryption

        let res = TestVector(test_vector_from_ciphertexts(
            &self.packing_keyswitch_key.as_view(),
            self.server_key.bootstrapping_key.polynomial_size(),
            &bit0.ct.ct,
            &bit1.ct.ct,
        ));

        debug!("test vector from ciphertexts {:?}", start.elapsed());
        res
    }

    /// Switches key and packs the given LWE ciphertexts in a GLWE ciphertext
    pub fn packing_keyswitch(&self, cts: &[&BitCt]) -> GlweCiphertextOwned<u64> {
        let in_data: Vec<u64> = cts
            .iter()
            .flat_map(|ct| ct.ct.ct.as_ref().iter().copied())
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

    /// Bootstrap the given ciphertext. This resets noise and additionally applies the given test vector.
    pub fn bootstrap(&self, ct: &BitCt, test_vector: &TestVector) -> BitCt {
        let mut ct = ct.clone();
        self.bootstrap_assign(&mut ct, test_vector);
        ct
    }

    /// Bootstrap the given ciphertext. This resets noise and additionally applies the given test vector.
    pub fn bootstrap_assign(&self, ct: &mut BitCt, test_vector: &TestVector) {
        let start = Instant::now();

        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffers, buffers) = engine.get_buffers(&self.server_key);

            apply_programmable_bootstrap(
                &self.server_key.bootstrapping_key,
                &ct.ct.ct.as_view(),
                &mut ciphertext_buffers.buffer_lwe_after_pbs.as_mut_view(),
                &test_vector.0,
                buffers,
            );

            lwe_keyswitch::keyswitch_lwe_ciphertext(
                &self.server_key.key_switching_key,
                &ciphertext_buffers.buffer_lwe_after_pbs.as_view(),
                &mut ct.ct.ct,
            );
        });

        debug!("bootstrap {:?}", start.elapsed());

        ct.ct
            .set_noise_level(NoiseLevel::NOMINAL, self.server_key.max_noise_level);
    }
}

/// Test vector (lookup table) to apply at bootstrap
#[derive(Debug)]
pub struct TestVector(GlweCiphertextOwned<u64>);

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

fn encode_bit(clear: Cleartext<u64>) -> Plaintext<u64> {
    // 0/1 bit is represented at next highest bit
    Plaintext(clear.0 << 62)
}

fn decode_bit(plain: Plaintext<u64>) -> Cleartext<u64> {
    let decomposer = SignedDecomposer::new(DecompositionBaseLog(2), DecompositionLevelCount(1));
    // 0/1 bit is represented at next highest bit
    Cleartext((decomposer.closest_representable(plain.0) >> 62) & 1)
}

fn test_vector_from_cleartext_fn(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    f: impl Fn(Cleartext<u64>) -> Cleartext<u64>,
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
    body_slice[0..box_size].fill(encode_bit(f(Cleartext(0))).0);
    body_slice[box_size..2 * box_size].fill(encode_bit(f(Cleartext(1))).0);

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

    // todo
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

/// Test vector
#[derive(Debug)]
pub struct MultivariateTestVector {
    bits: usize,
    test_vectors: Vec<TestVector>,
}

/// Generate test vector that used for multivariable bootstrapping
pub fn generate_multivariate_test_vector(
    context: &FheContext,
    bits: usize,
    f: impl Fn(u8) -> Cleartext<u64>,
) -> MultivariateTestVector {
    let start = Instant::now();
    assert_ne!(bits, 0);

    let test_vectors = (0..(1u8 << bits))
        .step_by(2)
        .map(|val| context.test_vector_from_cleartext_fn(|bit_val| f(val + bit_val.0 as u8)))
        .collect();

    debug!("generated mv test vector {:?}", start.elapsed());

    MultivariateTestVector { bits, test_vectors }
}

/// Performs a multivariate bootstrapping.
pub fn calculate_multivariate_function(
    context: &FheContext,
    bit_cts: &[&BitCt],
    mv_test_vector: &MultivariateTestVector,
) -> BitCt {
    assert_eq!(bit_cts.len(), mv_test_vector.bits);
    apply_selectors_rec(context, bit_cts, &mv_test_vector.test_vectors)
}

fn apply_selectors_rec<'a>(
    context: &FheContext,
    selectors: &[&BitCt],
    test_vectors: &'a [TestVector],
) -> BitCt {
    let (selector, selectors_rec) = selectors.split_last().expect("at least one selector");

    if selectors_rec.is_empty() {
        assert_eq!(test_vectors.len(), 1);
        context.bootstrap(selector, &test_vectors[0])
    } else {
        let start = Instant::now();
        assert!(!test_vectors.is_empty());
        assert_eq!(test_vectors.len() % 2, 0);
        let test_vectors_rec: Vec<_> = test_vectors
            .par_iter()
            .map(|tv| context.bootstrap(selector, tv))
            .chunks(2)
            .map(|tv| context.test_vector_from_ciphertexts(&tv[0], &tv[1]))
            .collect();
        debug!(
            "applied mv selectors {:?}, missing {} levels",
            start.elapsed(),
            selectors_rec.len()
        );
        apply_selectors_rec(context, selectors_rec, &test_vectors_rec)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::{LazyLock, OnceLock};
    use tfhe::core_crypto::prelude::*;

    static KEYS: LazyLock<(Arc<ClientKey>, FheContext)> = LazyLock::new(|| keys_impl());

    fn keys_impl() -> (Arc<ClientKey>, FheContext) {
        let (client_key, context) = FheContext::generate_keys();
        (client_key.into(), context)
    }

    #[test]
    fn test_packing_keyswitch() {
        let (client_key, context) = KEYS.clone();

        let ct0_clear = 0;
        let ct1_clear = 1;
        let ct0 = client_key.encrypt(Cleartext(ct0_clear));
        let ct1 = client_key.encrypt(Cleartext(ct1_clear));

        let packed = context.packing_keyswitch(&[&ct0, &ct1]);
        let mut packed_plain = PlaintextList::new(0, PlaintextCount(packed.polynomial_size().0));
        glwe_encryption::decrypt_glwe_ciphertext(
            &client_key.0.glwe_secret_key,
            &packed,
            &mut packed_plain,
        );

        assert_eq!(
            decode_bit(Plaintext(packed_plain.as_ref()[0])),
            Cleartext(0),
            "plain: {:064b}",
            packed_plain.as_ref()[0]
        );
        assert_eq!(
            decode_bit(Plaintext(packed_plain.as_ref()[1])),
            Cleartext(1),
            "plain: {:064b}",
            packed_plain.as_ref()[1]
        );
        assert_eq!(
            decode_bit(Plaintext(packed_plain.as_ref()[2])),
            Cleartext(0),
            "plain: {:064b}",
            packed_plain.as_ref()[1]
        );
        assert_eq!(
            decode_bit(Plaintext(packed_plain.as_ref()[3])),
            Cleartext(0),
            "plain: {:064b}",
            packed_plain.as_ref()[1]
        );
        assert_eq!(
            decode_bit(Plaintext(packed_plain.as_ref()[4])),
            Cleartext(0),
            "plain: {:064b}",
            packed_plain.as_ref()[1]
        );
    }

    #[test]
    fn test_bivariate_fn_2() {
        test_bivariate_fn_2_impl(0, 0);
        test_bivariate_fn_2_impl(0, 1);
        test_bivariate_fn_2_impl(1, 0);
        test_bivariate_fn_2_impl(1, 1);
    }

    fn test_bivariate_fn_2_impl(m0_clear: u64, m1_clear: u64) {
        let (client_key, context) = KEYS.clone();

        let f = |index: u8| -> Cleartext<u64> {
            const TABLE: [u64; 4] = [1, 0, 0, 1];
            Cleartext(TABLE[index as usize])
        };

        let m0 = client_key.encrypt(Cleartext(m0_clear));
        let m1 = client_key.encrypt(Cleartext(m1_clear));

        let tv = generate_multivariate_test_vector(&context, 2, f);
        let d = calculate_multivariate_function(&context, &[&m0, &m1], &tv);

        assert_eq!(
            client_key.decrypt(&d),
            f(((m0_clear as u8) << 1) + m1_clear as u8)
        );
    }

    #[test]
    fn test_bivariate_fn_3() {
        test_bivariate_fn_3_impl(0, 0, 0);
        test_bivariate_fn_3_impl(0, 1, 1);
        test_bivariate_fn_3_impl(1, 0, 1);
        test_bivariate_fn_3_impl(1, 1, 0);
    }

    fn test_bivariate_fn_3_impl(m0_clear: u64, m1_clear: u64, m2_clear: u64) {
        let (client_key, context) = KEYS.clone();

        let f = |index: u8| -> Cleartext<u64> {
            const TABLE: [u64; 8] = [1, 0, 0, 1, 0, 1, 1, 0];
            Cleartext(TABLE[index as usize])
        };

        let m0 = client_key.encrypt(Cleartext(m0_clear));
        let m1 = client_key.encrypt(Cleartext(m1_clear));
        let m2 = client_key.encrypt(Cleartext(m2_clear));

        let tv = generate_multivariate_test_vector(&context, 3, f);
        let d = calculate_multivariate_function(&context, &[&m0, &m1, &m2], &tv);

        assert_eq!(
            client_key.decrypt(&d),
            f(((m0_clear as u8) << 2) + ((m1_clear as u8) << 1) + m2_clear as u8)
        );
    }
}
