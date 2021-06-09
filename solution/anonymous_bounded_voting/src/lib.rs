// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of anonymous bounded voting (ABV) solution.

#[macro_use]
extern crate lazy_static;

pub mod coordinator;
pub mod counter;
pub mod verifier;
pub mod voter;
mod config;

#[cfg(test)]
mod tests {
    use wedpr_s_protos::generated::abv::{CandidateList, CounterSecret, CounterSystemParametersStorage, VoterSecret, VoteChoices, VoteChoice};
    use super::*;
    use crate::config::{SIGNATURE_SECP256K1};
    use wedpr_l_utils::traits::{Signature};

    #[test]
    fn test_bounded_voting() {
        // Generate coordinator's key pair
        let (_public_key, secret_key) = SIGNATURE_SECP256K1.generate_keypair();
        let mut candidate_list = CandidateList::new();
        // Init candidate list
        for candidate in vec!["Kitten", "Doge", "Bunny"] {
            candidate_list.mut_candidate().push(candidate.to_string());
        }
        let counter_id_list = vec!["1001", "1002", "1003"];
        let blank_ballot_count = vec![10, 100, 1000, 10000];

        let mut counter_secret_list: Vec<CounterSecret> = vec![];
        let mut counter_parameters_storage = CounterSystemParametersStorage::default();
        // Counter init
        for id in counter_id_list {
            let share_secret = counter::make_counter_secret();
            counter_secret_list.push(share_secret.clone());
            let counter_parameters_request = counter::make_system_parameters_share(id, &share_secret).unwrap();
            counter_parameters_storage.mut_counter_parameters_request().push(counter_parameters_request.clone());
        }
        // coordinator make system parameters
        let system_parameters = coordinator::make_system_parameters(&candidate_list, &counter_parameters_storage).unwrap();

        // voter init
        let mut voter_secret_list: Vec<VoterSecret> = vec![];
        let mut response_list = vec![];

        for blank_ballot in blank_ballot_count {
            let vote_secret = voter::make_voter_secret();
            voter_secret_list.push(vote_secret.clone());

            // voter -> coordinator generate blank ballot
            let vote_request = voter::make_bounded_registration_request(&vote_secret, &system_parameters).unwrap();
            let response = coordinator::certify_bounded_voter(&secret_key, blank_ballot, &vote_request).unwrap();
            response_list.push(response.clone());
            // verify blank ballot
            let result = voter::verify_blank_ballot(&vote_request, &response).unwrap();
            assert_eq!(true, result);
        }

        // voter vote
        let make_choice = |x: &Vec<u32>| {
            let mut choices = VoteChoices::new();
            for i in 0..candidate_list.get_candidate().len() {
                let mut pair = VoteChoice::new();
                pair.set_candidate(candidate_list.get_candidate()[i].clone());
                pair.set_value(x[i]);
                choices.mut_choice().push(pair);
            }
            choices
        };

        let voting_ballot_count:Vec<Vec<u32>> =
            vec![vec![1, 2, 3], vec![10, 20, 30], vec![100, 200, 300], vec![1000, 2000, 3000]];
        let mut vote_request_list = vec![];
        for index in 0..voting_ballot_count.len() {
            let ballot_choice = make_choice(&voting_ballot_count[index]);
            let vote_request = voter::vote_bounded(&voter_secret_list[index], &ballot_choice, &response_list[index], &system_parameters);
            vote_request_list.push(vote_request);
        }


    }
}
