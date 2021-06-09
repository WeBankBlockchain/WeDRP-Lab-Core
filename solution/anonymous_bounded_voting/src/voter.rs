// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of anonymous bounded voting (ABV) solution.

use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::abv::{CandidateBallot, VoterSecret, RegistrationRequest, SystemParametersStorage, RegistrationResponse, VoteChoices, Ballot, BallotProof, CandidateBallotProofPair, VoteRequest};
use wedpr_l_crypto_zkp_utils::{get_random_scalar, scalar_to_bytes, BASEPOINT_G1, BASEPOINT_G2, bytes_to_scalar, point_to_bytes, bytes_to_point};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::MultiscalarMul;
use wedpr_l_crypto_zkp_discrete_logarithm_proof::{prove_format_proof,prove_sum_relationship};
use wedpr_l_protos::{proto_to_bytes};
use wedpr_l_crypto_zkp_range_proof::{prove_value_range_in_batch};

pub fn make_voter_secret() -> VoterSecret {
    let vote_secret = get_random_scalar();
    VoterSecret {
        vote_secret: scalar_to_bytes(&vote_secret),
        unknown_fields: Default::default(),
        cached_size: Default::default()
    }
}

pub fn make_bounded_registration_request(secret: &VoterSecret, param: &SystemParametersStorage) ->  Result<RegistrationRequest, WedprError> {
    let vote_secret = bytes_to_scalar(secret.get_vote_secret())?;
    let blinding_basepoint_g2 = vote_secret * *BASEPOINT_G2;
    let poll_point = bytes_to_point(param.get_poll_point())?;
    let blinding_poll_point = vote_secret * poll_point;
    let mut request = RegistrationRequest::new();
    request
        .mut_weight_point()
        .set_blinding_basepoint_g2(point_to_bytes(&blinding_basepoint_g2));
    request
        .mut_weight_point()
        .set_blinding_poll_point(point_to_bytes(&blinding_poll_point));
    Ok(request)
}

pub fn verify_blank_ballot(
    request: &RegistrationRequest,
    response: &RegistrationResponse,
) -> Result<bool, WedprError>
{
    let blinding_poll_point = bytes_to_point(
        request.get_weight_point().get_blinding_poll_point(),
    )?;
    // let blinding_basepoint_g2 = bytes_to_point(
    //     request.get_weight_point().get_blinding_basepoint_g2(),
    // )?;
    let voter_weight = response.get_voter_weight();
    let computed_ciphertext1 = point_to_bytes(&(blinding_poll_point + *BASEPOINT_G1 * Scalar::from(voter_weight)));

    let response_ciphertext1 =
        response.get_ballot().get_ciphertext1();

    let request_ciphertext2 = request.get_weight_point().get_blinding_basepoint_g2();
    let response_ciphertext2 = response.get_ballot().get_ciphertext2();

    Ok(&computed_ciphertext1 == response_ciphertext1
        && request_ciphertext2 == response_ciphertext2)
}

pub fn vote_bounded(secret: &VoterSecret,
                    choices: &VoteChoices,
                    response: &RegistrationResponse,
                    param: &SystemParametersStorage) -> Result<VoteRequest, WedprError> {
    let mut request = VoteRequest::new();
    let mut blinding_vote_sum = Scalar::zero();
    let mut blindings: Vec<Scalar> = Vec::new();
    let mut vote_value: Vec<u64> = Vec::new();
    let mut v_weight_rest = response.get_voter_weight() as i64;
    let poll_point = bytes_to_point(param.get_poll_point())?;
    let vote_secret = bytes_to_scalar(secret.get_vote_secret())?;

    for choice_keypair in choices.get_choice() {
        let candidate_address = choice_keypair.get_candidate();
        let value = choice_keypair.get_value();
        v_weight_rest -= value as i64;
        if v_weight_rest < 0 {
            return Err(WedprError::ArgumentError);
        }
        let mut vote_ballot = Ballot::new();
        let blinding = get_random_scalar();
        let ciphertext1 = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(value as u64), blinding],
            &[*BASEPOINT_G1, poll_point],
        );
        let format_proof = prove_format_proof(
            value as u64,
            &blinding,
            &*BASEPOINT_G1,
            &*BASEPOINT_G2,
            &poll_point
        );
        blinding_vote_sum += blinding;
        let ciphertext2 = *BASEPOINT_G2 * blinding;
        vote_ballot
            .set_ciphertext1(point_to_bytes(&ciphertext1));
        vote_ballot
            .set_ciphertext2(point_to_bytes(&ciphertext2));
        let mut ballot_proof = BallotProof::new();
        ballot_proof.set_format_proof(proto_to_bytes(&format_proof)?);
        let mut proof_keypair = CandidateBallotProofPair::new();
        proof_keypair.set_candidate(candidate_address.to_string());
        proof_keypair.set_value(ballot_proof);
        request.mut_ballot_proof().push(proof_keypair);

        blindings.push(blinding);
        vote_value.push(value as u64);
        let mut ballot_pair = CandidateBallot::new();
        ballot_pair.set_candidate(candidate_address.to_string());
        ballot_pair.set_ballot(vote_ballot);
        request.mut_vote().mut_voted_ballot().push(ballot_pair);
    }
    let v_vote_sum = (response.get_voter_weight() - v_weight_rest as u32) as u64;
    let blinding_rest = get_random_scalar();
    let rest_ballot = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(v_weight_rest as u64), blinding_rest],
        &[*BASEPOINT_G1, poll_point],
    );

    let balance_proof = prove_sum_relationship(
        v_vote_sum,
        v_weight_rest as u64,
        &blinding_vote_sum,
        &blinding_rest,
        &vote_secret,
        &BASEPOINT_G1,
        &poll_point,
    );
    vote_value.push(v_weight_rest as u64);
    blindings.push(blinding_rest);
    pending_u64_vec(&mut vote_value);
    pending_scalar_vec(&mut blindings);

    let (range_proof, _) =
        prove_value_range_in_batch(
            &vote_value,
            &blindings,
            &poll_point,
        )?;
    let signature = response.get_signature();
    request
        .mut_vote()
        .set_blank_ballot(response.get_ballot().clone());
    request.set_sum_balance_proof(proto_to_bytes(&balance_proof)?);
    request.set_range_proof(range_proof);
    request.mut_vote().set_signature(signature.to_vec());
    request
        .mut_vote()
        .mut_rest_ballot()
        .set_ciphertext1(point_to_bytes(&rest_ballot));
    Ok(request)

}

fn pending_u64_vec(v: &mut Vec<u64>) -> bool {
    let length = v.len() as i32;
    let log_length = (length as f64).log2().ceil() as u32;
    let expected_len = 2_i32.pow(log_length);
    if expected_len == length {
        return true;
    }
    let pending_length = expected_len - length;
    for _ in 0..pending_length {
        let tpm = 0u64;
        v.push(tpm);
    }
    true
}

fn pending_scalar_vec(v: &mut Vec<Scalar>) -> bool {
    let length = v.len() as i32;
    let log_length = (length as f64).log2().ceil() as u32;
    let expected_len = 2_i32.pow(log_length);
    if expected_len == length {
        return true;
    }
    let pending_length = expected_len - length;
    for _ in 0..pending_length {
        let tpm = Scalar::default();
        v.push(tpm);
    }
    true
}
