// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of anonymous bounded voting (ABV) solution.

use wedpr_s_protos::generated::abv::{RegistrationRequest, RegistrationResponse};
use wedpr_l_utils::error::WedprError;

use wedpr_s_protos::generated::abv::{SystemParametersStorage, VoteRequest};
use wedpr_l_crypto_zkp_utils::{point_to_bytes, bytes_to_point};
use crate::config::{SIGNATURE_SECP256K1, HASH_KECCAK256};
use wedpr_l_utils::traits::{Hash, Signature};
use curve25519_dalek::ristretto::RistrettoPoint;

pub fn verify_bounded_vote_request(
    param: &SystemParametersStorage,
    request: &VoteRequest,
    public_key: &[u8],
) -> Result<(), WedprError>
{
    let poll_point = bytes_to_point(param.get_poll_point())?;
    let signature = request.get_vote().get_signature();
    let blank_ballot = request.get_vote().get_blank_ballot();
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut blank_ballot.get_ciphertext1().to_vec());
    hash_vec.append(&mut blank_ballot.get_ciphertext2().to_vec());
    let message_hash: Vec<u8> = HASH_KECCAK256.hash(&hash_vec);

    if !SIGNATURE_SECP256K1.verify(&public_key, &message_hash.as_ref(), &signature) {
        return Err(WedprError::VerificationError);
    }

    let range_proof = request.get_range_proof();
    let mut commitments = Vec::new();
    let mut voted_ballot_sum = RistrettoPoint::default();
    for candidate_ballot_pair in request.get_vote().get_voted_ballot() {
        let ballot = candidate_ballot_pair.get_ballot();
        commitments.push(ballot.get_ciphertext1());
        voted_ballot_sum +=  bytes_to_point(&ballot.get_ciphertext1());
    }

    let rest_ballot = request
        .get_vote()
        .get_rest_ballot()
        .get_ciphertext1();

    commitments.push(rest_ballot.clone());
    pending_commitment_vec(&mut commitments);
    // if !utils::verify_aggregated_value_range(
    //     &commitments,
    //     range_proof,
    //     &h_point,
    // ) {
    //     wedpr_println!("verify range proof failed!");
    //     return false;
    // }
    //
    // for candidate_ballot in request.get_ballot_proof() {
    //     let candidate = candidate_ballot.get_key();
    //     let ballot_proof = candidate_ballot.get_value();
    //     let mut candidate_ballot = Ballot::new();
    //     for candidate_ballot_pair in request.get_vote().get_voted_ballot() {
    //         if candidate_ballot_pair.get_key() == candidate {
    //             candidate_ballot = candidate_ballot_pair.get_value().clone();
    //         }
    //     }
    //
    //     let ciphertext1 = string_to_point!(&candidate_ballot.get_ciphertext1());
    //     let ciphertext2 = string_to_point!(&candidate_ballot.get_ciphertext2());
    //     let format_proof = ballot_proof.get_format_proof();
    //     if !local_utils::verify_format(
    //         &ciphertext1,
    //         &ciphertext2,
    //         format_proof,
    //         &h_point,
    //     ) {
    //         wedpr_println!("verify_format failed!");
    //         return false;
    //     }
    // }
    // let balance_proof = request.get_balance_proof();
    // if !local_utils::verify_balance(
    //     &voted_ballot_sum,
    //     &string_to_point!(&&rest_ballot),
    //     &string_to_point!(&&blank_ballot.get_ciphertext1()),
    //     balance_proof,
    //     &h_point,
    // ) {
    //     wedpr_println!("verify_balance failed!");
    //     return false;
    // }
    Ok(())
}

pub fn pending_commitment_vec(v: &mut Vec<&[u8]>) {
    let length = v.len() as i32;
    let log_length = (length as f64).log2().ceil() as u32;
    let expected_len = 2_i32.pow(log_length);
    if expected_len == length {
        return;
    }
    let pending_length = expected_len - length;
    for _ in 0..pending_length {
        let tpm = RistrettoPoint::default();
        v.push(&point_to_bytes(&tpm));
    }
}