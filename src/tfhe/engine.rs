//! Unmodified (parts of it removed) copy of `shortint` engine since many fields were only accessible at crate level
//!
//! Module with the engine definitions.
//!
//! Engines are required to abstract cryptographic notions and efficiently manage memory from the
//! underlying `core_crypto` module.
//!
//! COPIED FROM `tfhe-rs` under the license
//!
//! BSD 3-Clause Clear License
//!
//! Copyright © 2024 ZAMA.
//! All rights reserved.
//!
//! Redistribution and use in source and binary forms, with or without modification,
//! are permitted provided that the following conditions are met:
//!
//! 1. Redistributions of source code must retain the above copyright notice, this
//! list of conditions and the following disclaimer.
//!
//! 2. Redistributions in binary form must reproduce the above copyright notice, this
//! list of conditions and the following disclaimer in the documentation and/or other
//! materials provided with the distribution.
//!
//! 3. Neither the name of ZAMA nor the names of its contributors may be used to endorse
//! or promote products derived from this software without specific prior written permission.
//!
//! NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE.
//! THIS SOFTWARE IS PROVIDED BY THE ZAMA AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
//! IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//! MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
//! ZAMA OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
//! OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//! OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//! ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//! NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
//! ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::cell::RefCell;
use std::fmt::Debug;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::entities::LweCiphertextMutView;
use tfhe::core_crypto::prelude::{
    ComputationBuffers, DefaultRandomGenerator, EncryptionRandomGenerator, LweDimension, Seeder,
};
use tfhe::core_crypto::seeders::new_seeder;
use tfhe::shortint::{CiphertextModulus, ServerKey};

thread_local! {
    static LOCAL_ENGINE: RefCell<ShortintEngine> = RefCell::new(ShortintEngine::new());
}

#[allow(unused)]
pub struct BuffersRef<'a> {
    // For the intermediate keyswitch result in the case of a big ciphertext
    pub(crate) buffer_lwe_after_ks: LweCiphertextMutView<'a, u64>,
    // For the intermediate PBS result in the case of a smallciphertext
    pub(crate) buffer_lwe_after_pbs: LweCiphertextMutView<'a, u64>,
}

#[derive(Default)]
struct Memory {
    buffer: Vec<u64>,
}

impl Memory {
    fn as_buffers(
        &mut self,
        in_dim: LweDimension,
        out_dim: LweDimension,
        ciphertext_modulus: CiphertextModulus,
    ) -> BuffersRef<'_> {
        let num_elem_in_lwe_after_ks = in_dim.to_lwe_size().0;
        let num_elem_in_lwe_after_pbs = out_dim.to_lwe_size().0;

        let total_elem_needed = num_elem_in_lwe_after_ks + num_elem_in_lwe_after_pbs;

        let all_elements = if self.buffer.len() < total_elem_needed {
            self.buffer.resize(total_elem_needed, 0u64);
            self.buffer.as_mut_slice()
        } else {
            &mut self.buffer[..total_elem_needed]
        };

        let (after_ks_elements, after_pbs_elements) =
            all_elements.split_at_mut(num_elem_in_lwe_after_ks);

        let buffer_lwe_after_ks =
            LweCiphertextMutView::from_container(after_ks_elements, ciphertext_modulus);
        let buffer_lwe_after_pbs =
            LweCiphertextMutView::from_container(after_pbs_elements, ciphertext_modulus);

        BuffersRef {
            buffer_lwe_after_ks,
            buffer_lwe_after_pbs,
        }
    }
}

/// Simple wrapper around [`std::error::Error`] to be able to
/// forward all the possible `EngineError` type from [`core_crypto`](crate::core_crypto)
#[allow(dead_code)]
#[derive(Debug)]
pub struct EngineError {
    error: Box<dyn std::error::Error>,
}

impl<T> From<T> for EngineError
where
    T: std::error::Error + 'static,
{
    fn from(error: T) -> Self {
        Self {
            error: Box::new(error),
        }
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.error)
    }
}

/// ShortintEngine
///
/// This 'engine' holds the necessary engines from [`core_crypto`](crate::core_crypto)
/// as well as the buffers that we want to keep around to save processing time.
///
/// This structs actually implements the logics into its methods.
pub struct ShortintEngine {
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    pub(crate) encryption_generator: EncryptionRandomGenerator<DefaultRandomGenerator>,
    pub(crate) computation_buffers: ComputationBuffers,
    ciphertext_buffers: Memory,
}

impl ShortintEngine {
    /// Safely gives access to the `thead_local` shortint engine
    /// to call one (or many) of its method.
    #[inline]
    pub fn with_thread_local_mut<F, R>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        LOCAL_ENGINE.with(|engine_cell| func(&mut engine_cell.borrow_mut()))
    }

    /// Create a new shortint engine
    ///
    /// Creating a `ShortintEngine` should not be needed, as each
    /// rust thread gets its own `thread_local` engine created automatically,
    /// see [ShortintEngine::with_thread_local_mut]
    ///
    ///
    /// # Panics
    ///
    /// This will panic if the `CoreEngine` failed to create.
    pub fn new() -> Self {
        let mut root_seeder = new_seeder();

        Self::new_from_seeder(root_seeder.as_mut())
    }

    pub fn new_from_seeder(root_seeder: &mut dyn Seeder) -> Self {
        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(root_seeder.seed());

        // Note that the operands are evaluated from left to right for Rust Struct expressions
        // See: https://doc.rust-lang.org/stable/reference/expressions.html?highlight=left#evaluation-order-of-operands
        Self {
            encryption_generator: EncryptionRandomGenerator::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            computation_buffers: ComputationBuffers::default(),
            ciphertext_buffers: Memory::default(),
        }
    }

    /// Return the [`BuffersRef`] and [`ComputationBuffers`] for the given `ServerKey`
    pub fn get_buffers(
        &mut self,
        server_key: &ServerKey,
    ) -> (BuffersRef<'_>, &mut ComputationBuffers) {
        (
            self.ciphertext_buffers.as_buffers(
                server_key
                    .key_switching_key
                    .output_lwe_size()
                    .to_lwe_dimension(),
                server_key.bootstrapping_key.output_lwe_dimension(),
                server_key.ciphertext_modulus,
            ),
            &mut self.computation_buffers,
        )
    }
}
