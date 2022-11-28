use bls12_381::{hash_to_curve::{ExpandMsgXmd, InitExpandMessage, ExpandMessageState}, Scalar};
use sha2::Sha256;
use rand::RngCore;

use super::{constants::{MAX_BYTES_NUM, SCALAR_LEN, EXPAND_LEN}};

/*
 Iterate through the "expander" and get "count" number of scalars (each scalar
 needing 48 bytes out of the expander)
*/
pub fn scalars_from_random_bytes<'a, X: ExpandMessageState<'a>>(count: usize, expander: &mut X, scalars: &mut Vec<Scalar>) -> Vec<Scalar> {
    for _ in 0..count {
        let mut tmp = [0u8; EXPAND_LEN];
        expander.read_into(&mut tmp);

        // pad to 64 bytes
        let rand_seed: [u8; 64] = [&tmp, &[0u8; 64 - EXPAND_LEN][0..]].concat().try_into().unwrap(); // must be little endian
        let scalar: Scalar = Scalar::from_bytes_wide(&rand_seed);
        scalars.push(scalar);
    }
    scalars.to_owned()
}

/*
 hash_to_scalar as defined in [https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-hash-to-scalar].
 The resulted scalars will be added to the provided scalars list.
*/
pub fn hash_to_scalar(msg: &[u8], count: usize, dst: &[u8], scalars: &mut Vec<Scalar>) -> Vec<Scalar>{
    if count > MAX_BYTES_NUM / EXPAND_LEN {
        panic!("hash_to_scalar: count cannot be larger than: {}", MAX_BYTES_NUM / EXPAND_LEN);
    }

    let mut expander = ExpandMsgXmd::<Sha256>::init_expand(msg, dst, count * EXPAND_LEN);

    // let mut scalars: Vec<Scalar> = Vec::new();
    scalars_from_random_bytes(count, &mut expander, scalars)
}

/*
 Get a random seed of 32 bytes (the length of a scalar)
*/
pub fn get_random_seed() -> [u8; SCALAR_LEN] {
    let mut buf = [0u8; SCALAR_LEN];
    // let mut rng = rand::thread_rng();
    // rng.fill_bytes(&mut buf);

    rand::thread_rng().fill_bytes(&mut buf);
    buf
}