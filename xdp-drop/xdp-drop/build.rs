use anyhow::{anyhow, Context as _};
use aya_build::{cargo_metadata, Toolchain};
use std::env;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    // Trouver le package eBPF
    let cargo_metadata::Metadata { packages, .. } =
        cargo_metadata::MetadataCommand::new()
            .no_deps()
            .exec()
            .context("MetadataCommand::exec")?;

    let ebpf_package = packages
        .iter()
        .find(|p| p.name == "xdp-drop-ebpf")
        .ok_or_else(|| anyhow!("xdp-drop-ebpf package not found"))?;

    // Compilation du code eBPF
    let _ = aya_build::build_ebpf([ebpf_package.clone()], Toolchain::default());

    // Compilation des fichiers proto
    let proto_file = "../proto/firewall.proto";
    let proto_include = "../proto";

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    tonic_build::compile_protos("proto/firewall.proto")?;
    Ok(())
}
