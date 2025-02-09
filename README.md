# Running the binary

The binary may be run with the command

```
cargo run --release -- --key 76b8e0ada0f13d90405d6ae55386bd28 --iv bdd219b8a08ded1a --number-of-outputs 10
```

The binary by default uses the implementation `ShortintWoppbs1BitSboxGalMulPbsAesEncrypt`
and that should be considered the submitted solution. This implementation uses the FHE model `shortint_woppbs_1bit` 
and the AES-128 FHE implementation `fhe_sbox_gal_mul_pbs` which are the essential parts of the solution.
The other models in `tfhe_aes::tfhe` and the AES-128 FHE implementation `fhe_sbox_pbs` can
effectively be ignored.

# Overview of the library

The library consist of two parts. A set of models for doing FHE computation are defined in `tfhe_aes::tfhe`. 
They are all based on `tfhe-rs` but has some additional primitives that adds expressiveness or effectiveness.

There are two AES-128 FHE implementation in `tfhe_aes::aes_128::fhe` that are generic over the FHE model used. 

## AES-128 FHE implementations

The operations needed to implement AES-128 are the linear operation XOR and the (highly non-linear) SBOX permutation.
The linear operations are well suited for leveled homomorphic calculation whereas some kind of programmatic bootstrap
is needed for the SBOX. In order to reduce the depth required by leveled calculation, Galois multiplication by fixed constants
may also be "merged" into the programmatic bootstrapping.

The AES-128 implementations in the library all use ciphertexts representing 1 bit clear texts with no carry. XOR is 
implemented by adding ciphertexts and letting them overflow.

| Implementation         | Bootstrapping handles        | Required depth for leveled calculation (XORs) |
|------------------------|------------------------------|-----------------------------------------------|
| `fhe_sbox_pbs`         | SBOX                         | 11                                            |
| `fhe_sbox_gal_mul_pbs` | SBOX + Galois multiplication | 5                                             |


## FHE models

### `shorint_woppbs_1bit`

This model uses vertical packed circuit bootstrapping introduced in <https://eprint.iacr.org/2017/430.pdf> and implemented
in the WoP-PBS experimental features in `tfhe-rs`. Additional primitives are implement in the library at hand to support
multivariate and multivalued functions, but these higher level primitives still builds on the low-level primitives in `tfhe-rs`.

As a comment, the effectiveness if this model could be improved by running the bootstrapping of GGSW ciphertexts in
`fft64::crypto::wop_pbs::circuit_bootstrap_boolean` in parallel. 

### `shorint_woppbs_8bit`

This model is similar to the 1bit model, but uses an 8-bit ciphertext space for circuit bootstrapping 
(SBOX can then be evaluated on single ciphertexts). XOR is still performed on the 1-bit "dual" ciphertexts that are
extracted from the 8-bit ciphertexts. This model though seems outperformed by the 1-bit multivariate, multivalued 1-bit ciphertext
bootstrapping in `shorint_woppbs_1bit`

### `shorint_1bit`

Build on "plain" `tfhe-rs` shortint. Additional primitives are introduced to do multivariate (8-bit for SBOX)
bootstrapping. The primitive implemented is a tree based bootstrap as described in
<https://tches.iacr.org/index.php/TCHES/article/view/8793/8393>. During implementation, the noise aggregation seemed
hard to control though. And for the model to be effective, it would need further primitives in form of multivalued
bootstrapping via factoring test vectors as described in <https://eprint.iacr.org/2018/622.pdf>.