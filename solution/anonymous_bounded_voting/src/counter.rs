// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of anonymous bounded voting (ABV) solution.

use wedpr_s_protos::generated::abv::{CounterSecret, CounterSystemParametersShareRequest};
use wedpr_l_crypto_zkp_utils::{get_random_scalar, scalar_to_bytes, BASEPOINT_G2, bytes_to_scalar, point_to_bytes};
use wedpr_l_utils::error::WedprError;


pub fn make_counter_secret() -> CounterSecret {
    let secret_share = get_random_scalar();
    CounterSecret {
        poll_secret_share: scalar_to_bytes(&secret_share),
        unknown_fields: Default::default(),
        cached_size: Default::default()
    }
}

pub fn make_system_parameters_share(counter_id: &str, counter_secret: &CounterSecret) -> Result<CounterSystemParametersShareRequest,WedprError > {
    let secret_scalar = bytes_to_scalar(counter_secret.get_poll_secret_share())?;
    let poll_point_share = secret_scalar * *BASEPOINT_G2;
    Ok(CounterSystemParametersShareRequest {
        counter_id: counter_id.to_string(),
        poll_point_share: point_to_bytes(&poll_point_share),
        unknown_fields: Default::default(),
        cached_size: Default::default()
    })
}