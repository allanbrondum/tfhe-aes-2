use tfhe::core_crypto::entities::Cleartext;

pub mod shortint_1bit;
pub mod shortint_woppbs_8bit;

pub trait ClientKeyT<Bit> {
    fn encrypt(&self, bit: Cleartext<u64>) -> Bit;

    fn decrypt(&self, bit: &Bit) -> Cleartext<u64>;
}
