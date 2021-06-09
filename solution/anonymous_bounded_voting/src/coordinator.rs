// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of anonymous bounded voting (ABV) solution.

use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::abv::{SystemParametersStorage, CounterSystemParametersStorage, CandidateList, RegistrationRequest, RegistrationResponse, Ballot};
use curve25519_dalek::ristretto::RistrettoPoint;
use wedpr_l_crypto_zkp_utils::{BASEPOINT_G1, bytes_to_point, point_to_bytes};
use curve25519_dalek::scalar::Scalar;
use crate::config::{SIGNATURE_SECP256K1, HASH_KECCAK256};
use wedpr_l_utils::traits::{Hash, Signature};

pub fn make_system_parameters(candidates: &CandidateList, counter_storage: &CounterSystemParametersStorage) -> Result<SystemParametersStorage, WedprError> {
    let mut poll_point = RistrettoPoint::default();
    for counter_request in counter_storage.get_counter_parameters_request() {
        poll_point += bytes_to_point(counter_request.get_poll_point_share())?;
    }
    let mut storage = SystemParametersStorage::default();
    storage.set_candidates(candidates.clone());
    storage.set_poll_point(point_to_bytes(&poll_point));
    Ok(storage)
}

pub fn certify_bounded_voter(secret_key: &[u8], value: u32, registration_request: &RegistrationRequest,) -> Result<RegistrationResponse, WedprError> {
    // let blinding_basepoint_g2 = bytes_to_point(registration_request.get_weight_point().get_blinding_basepoint_g2())?;
    let blinding_poll_point = bytes_to_point(registration_request.get_weight_point().get_blinding_poll_point())?;
    let ciphertext1 =
        blinding_poll_point + (*BASEPOINT_G1 * Scalar::from(value));
    let mut ballot = Ballot::new();
    ballot.set_ciphertext1(point_to_bytes(&ciphertext1));
    ballot.set_ciphertext2(registration_request.get_weight_point().get_blinding_basepoint_g2().to_vec());
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut ballot.get_ciphertext1().to_vec());
    hash_vec.append(&mut ballot.get_ciphertext2().to_vec());
    let message_hash = HASH_KECCAK256.hash(&hash_vec);
    let signature = SIGNATURE_SECP256K1.sign(secret_key, &message_hash)?;
    let mut response = RegistrationResponse::new();
    response.set_signature(signature);
    response.set_ballot(ballot);
    response.set_voter_weight(value);
    Ok(response)
}