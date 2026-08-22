// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("src/raft");

    // Collect the proto file(s)
    let protos = [proto_dir.join("raft.proto")];

    // Tell Cargo to rerun this build script if any proto file changes
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    // Use tonic_prost_build (not tonic_build) to configure and compile
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&protos, &[proto_dir])?;

    Ok(())
}
