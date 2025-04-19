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

    // Dossier de sortie = src/generated
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&out_dir)
        .compile(&[proto_file], &[proto_include])
        .context("Échec de la compilation du fichier .proto")?;

    Ok(())
}
