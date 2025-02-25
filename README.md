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

There are two AES-128 FHE implementations in `tfhe_aes::aes_128::fhe` that are generic over the FHE model used. 

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

For programmatic bootstrapping, this model uses bit extraction and circuit bootstrapping combined with vertical 
packed (CMux tree) lookup table introduced in <https://eprint.iacr.org/2017/430.pdf> and implemented
in the WoP-PBS experimental features in `tfhe-rs`. Each ciphertext represents 1 bit. XOR is implemented as leveled
operations by adding ciphertexts. Two additional mid-level primitives are introduced:

1) noise propagation that assumes independent noise when adding ciphertexts (XOR)  
2) lookup tables for multivariate and multivalued functions

The noise propagation when adding ciphertexts in the `tfhe-rs` `shortint` modules, does not make any assumption
of independent noise in the addends. There is a `max_noise_level` that is the L2 norm of the dot product of the atomic
pattern (see <https://github.com/zama-ai/concrete/blob/main/compilers/concrete-optimizer/v0-parameters/README.md> and 
also https://eprint.iacr.org/2022/704.pdf for deeper reference). 
And the `noise_level` on ciphertexts is the standard deviation of the ciphertext phase error relative to the "nominal"
noise. When adding to ciphertexts, the noise is propagated as the sum of the two `noise_level`. This assumes no independence
of noise and relies on the general relation for random variables: `stddev(X + Y) <= stddev(X) + stddev(Y)`. The additional
primitive introduced is the use the square of the L2 norm of the dot product instead: `max_noise_level_squared`. The
`noise_level_squared` on each ciphertext is the variance of the ciphertext phase error relative to the "nominal" noise level.
By applying the "independence heuristic" (introduced in https://eprint.iacr.org/2016/870.pdf) and assuming that the ciphertexts 
we add have independent noise, we can calculate the propagated noise 
by adding the two `noise_level_squared` when adding the ciphertexts. This is due to the relation `var(X + Y) = var(X) + var(Y)` for
independent random variables. It can also be seen as a dot product with weights (1, 1) of independent ciphertexts - the 
squared L2 norm of this dot product is 2.

To support multivariate and multivalued programmatic bootstrapping, additional primitives are implemented in the library at hand
to generate the lookup table, but evaluating the CMux tree still relies on the existing low-level primitives in `tfhe-rs`. In order to account for the additional
noise due to the multivariate input, the nominal (squared) noise level is multiplied with the number of input bits (which is 8 for the SBOX) - 
see the phase error variance bound in Lemma 3.2 in https://eprint.iacr.org/2017/430.pdf.

As a comment, the effectiveness if this model can be improved by running the boolean bootstrapping of GGSW ciphertexts in
`fft64::crypto::wop_pbs::circuit_bootstrap_boolean` in parallel. 

### `shorint_woppbs_8bit`

This model is similar to the 1bit model, but uses an 8-bit ciphertext space for circuit bootstrapping and lookup table.
(SBOX can then be evaluated on single ciphertexts). XOR is still performed on the 1-bit "dual" ciphertexts that are
extracted from the 8-bit ciphertexts. This model though seems outperformed by the multivariate, multivalued 1-bit ciphertext
bootstrapping in `shorint_woppbs_1bit`

### `shorint_1bit`

Build on "plain" `tfhe-rs` shortint. An additional primitive is introduced to do multivariate (8-bit for SBOX)
programmatic bootstrapping. The primitive is a tree based bootstrap as described in
<https://tches.iacr.org/index.php/TCHES/article/view/8793/8393>. During implementation, the noise aggregation seemed
hard to control though. And for the model to be effective, it would need further primitives in form of multivalued
bootstrapping via factoring test vectors as described in <https://eprint.iacr.org/2018/622.pdf>.