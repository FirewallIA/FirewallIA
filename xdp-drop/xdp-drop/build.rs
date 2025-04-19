use anyhow::{anyhow, Context as _};
use aya_build::{cargo_metadata, Toolchain};

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } =
        cargo_metadata::MetadataCommand::new()
            .no_deps()
            .exec()
            .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "xdp-drop-ebpf")
        .ok_or_else(|| anyhow!("xdp-drop-ebpf package not found"))?;
    aya_build::build_ebpf([ebpf_package], Toolchain::default());
    
    let out_dir = std::env::var("src").expect("src not set");

    tonic_build::configure()
    .build_server(true)  // Générer le serveur gRPC
    .build_client(true)  // Générer le client gRPC
    .out_dir(std::env::var("src")?)     // Dossier où les fichiers générés seront placés
    .compile(
        &["../proto/firewall.proto"],  // Chemin vers ton fichier .proto
        &["../proto"],                  // Dossier contenant les fichiers .proto
    )
    .expect("Échec de la compilation du fichier .proto");
    Ok(())
}
