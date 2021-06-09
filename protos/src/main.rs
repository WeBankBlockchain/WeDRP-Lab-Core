// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Tool to compile proto files to rust files.

extern crate protoc_rust;
use protoc_rust::{Codegen, Customize};
use std::env;

/// Uses `cargo run` in this sub crate (wedpr_protos) to compile proto files to
/// rust files. You need to update the generated files every time you modify the
/// existing proto files or add new proto files.
#[cfg_attr(tarpaulin, skip)]
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        generate_proto_for_all();
    } else {
        // TODO: Add more control on compiling proto files to rust files.
    }
}

/// Compiles proto files to rust files.
#[cfg_attr(tarpaulin, skip)]
fn generate_proto_for_all() {
    Codegen::new()
        .out_dir("./src/generated/")
        .includes(&["."])
        // List all used proto files here.
        // You can remove any proto files that are not used by your project.
        .inputs(&["solution/vcl/vcl.proto","solution/scd/scd.proto","solution/ktb/hdk.proto", "solution/abv/abv.proto"])
        .customize(Customize {
            ..Default::default()
        })
        .run()
        .expect("protoc should not fail");
}
