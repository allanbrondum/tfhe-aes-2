use tfhe::core_crypto::entities::Cleartext;

mod engine;
pub mod shortint_1bit;
pub mod shortint_woppbs_1bit;
pub mod shortint_woppbs_8bit;

pub trait ClientKeyT: Send + Sync {
    type Bit: Send + Sync;

    fn encrypt(&self, bit: Cleartext<u64>) -> Self::Bit;

    fn decrypt(&self, bit: &Self::Bit) -> Cleartext<u64>;
}

pub trait ContextT: Send + Sync {
    type Bit: Send + Sync;

    /// Returns unencrypted ciphertext
    fn trivial(&self, bit: Cleartext<u64>) -> Self::Bit;
}
