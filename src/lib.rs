use bls12_381::{hash_to_curve::{ExpandMsgXmd, InitExpandMessage, ExpandMessageState}, Scalar};
use ff::Field;
use sha2::Sha256;

mod utils;
mod constants;
use utils::{scalars_from_random_bytes, hash_to_scalar, get_random_seed};
use constants::{EXPAND_LEN, SCALAR_LEN, MAX_BYTES_NUM};

const DST: &[u8; 5] = b"a dst";

/* 
 Call the PRF in a loop. Get 48 bytes and reduce mod the group order 
*/
pub fn prf_in_loop(count: usize) -> Vec<Scalar> {
    let mut m_tildes: Vec<Scalar> = Vec::new();
    for _ in 1..=count {
        m_tildes.push(Scalar::random(rand::thread_rng()));
    }
    m_tildes
}


/* 
 Call expand_message in a loop to get all the random scalars from a single
 random seed.
*/
pub fn expand_message_in_loop<'a>(count: usize) -> Vec<Scalar> {
    let mut rand_scalars: Vec<Scalar> = Vec::new();

    // The random seed from which all random scalars will be created
    let buf: [u8; SCALAR_LEN] = get_random_seed();

    const DST_BYTES_NUM: usize = 250;
    const REMAINING_BYTES_NUM: usize = MAX_BYTES_NUM - DST_BYTES_NUM;

    // the number of scalars we can get from REMAINING_BYTES_NUM bytes (170 for the current ciphersuites)
    let count_prime: usize = REMAINING_BYTES_NUM / EXPAND_LEN; 

    // get some random scalars
    let numexp = count / count_prime;
    let mut dst_next = [&(DST.len().to_be_bytes()[4..]).to_vec(), DST.as_ref()].concat();
    for i in 1..=numexp {
        let mut expander = ExpandMsgXmd::<Sha256>::init_expand(&buf, &dst_next, count_prime * EXPAND_LEN + DST_BYTES_NUM);

        // get count_prime scalars by iterating through the expander
        rand_scalars = scalars_from_random_bytes(count_prime, &mut expander, &mut rand_scalars);

        // read remaining 250 bytes to get the next dst
        let tmp = expander.into_vec();
        dst_next = [&(i.to_be_bytes()[4..]).to_vec(), &tmp[..DST_BYTES_NUM]].concat();
    }

    // get the remaining random scalars
    let mut expander = ExpandMsgXmd::<Sha256>::init_expand(&buf, &dst_next, EXPAND_LEN * (count % count_prime));
    rand_scalars = scalars_from_random_bytes(count % count_prime, &mut expander,  &mut rand_scalars);

    rand_scalars
}


/* 
 Call hash_to_scalar and a PRF in a loop to get as many random scalars
 from a single seed as possible without changing hash_to_scalar or introducing
 a new expand_message
*/
pub fn expand_message_and_prf_in_loop(count: usize) -> Vec<Scalar> {
    let mut scalars: Vec<Scalar> = Vec::new();

    // The maximum number of scalars we can get out of MAX_BYTES_NUM number of bytes (170 for the current ciphersuites)
    let max_count = MAX_BYTES_NUM / EXPAND_LEN;

    let numexp = count / max_count;
    for _ in 0..numexp {
        // get a random seed
        let buf: [u8; SCALAR_LEN] = get_random_seed();

        // get the maximum number of scalars from that seed (adding them to
        // the scalars list)
        scalars = hash_to_scalar(&buf, max_count, DST, &mut scalars);
    }

    // get the remaining scalars and add them to the scalars list
    let buf: [u8; SCALAR_LEN] = get_random_seed();
    scalars = hash_to_scalar(&buf, count % max_count, DST, &mut scalars);

    scalars
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_in_loop() {
        let count = 400;
        let result = prf_in_loop(count);
        assert_eq!(result.len(), count)
    }

    #[test]
    fn test_expand_message_in_loop() {
        let count = 400;
        let result = expand_message_in_loop(count);
        assert_eq!(result.len(), count)
    }

    #[test]
    fn test_expand_message_and_prf_in_loop() {
        let count = 400;
        let result = expand_message_and_prf_in_loop(count);
        assert_eq!(result.len(), count)
    }
}
