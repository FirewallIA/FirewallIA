// xdp-drop/build.rs
use anyhow::{anyhow, Context as _};
use aya_build::{cargo_metadata, Toolchain};
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").context("La variable d'environnement OUT_DIR n'est pas définie")?);

    println!("cargo:info=Début de la compilation eBPF et de la configuration...");

    let cargo_meta_output = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("Échec de l'exécution de la commande cargo metadata")?;

    let ebpf_package_ref = cargo_meta_output
        .packages
        .iter()
        .find(|p| p.name == "xdp-drop-ebpf")
        .ok_or_else(|| {
            anyhow!("Le package eBPF 'xdp-drop-ebpf' n'a pas été trouvé. Vérifiez son nom et sa présence dans le workspace.")
        })?;

    // Appel à build_ebpf. On clone ebpf_package_ref pour obtenir un Package par valeur.
    let compiled_ebpf_artifact_paths = aya_build::build_ebpf(
        std::iter::once(ebpf_package_ref.clone()), // MODIFICATION ICI: .clone()
        &Toolchain::default(),
    )
    .context(format!(
        "Échec de la compilation du programme eBPF à partir du package '{}'",
        ebpf_package_ref.name
    ))?;

    let ebpf_source_path = compiled_ebpf_artifact_paths.get(0).ok_or_else(|| {
        anyhow!(
            "aya_build::build_ebpf n'a retourné aucun chemin d'artefact pour le package eBPF '{}'",
            ebpf_package_ref.name
        )
    })?;

    let ebpf_dest_filename = "xdp-drop";
    let ebpf_dest_path = out_dir.join(ebpf_dest_filename);

    fs::copy(ebpf_source_path, &ebpf_dest_path).context(format!(
        "Échec de la copie de l'objet eBPF de '{:?}' vers '{:?}'",
        ebpf_source_path, ebpf_dest_path
    ))?;

    println!(
        "cargo:info=Objet eBPF copié avec succès de {:?} vers {:?}",
        ebpf_source_path, ebpf_dest_path
    );

    // --- Compilation des Protocol Buffers (tonic) ---
    println!("cargo:info=Début de la compilation des protocol buffers...");
    let proto_file = "../proto/firewall.proto";
    let proto_include_dir = "../proto";
    let google_wellknown_types_include_dir = "../proto/include";

    println!("cargo:rerun-if-changed={}", proto_file);

    tonic_build::configure()
        .compile_well_known_types(true)
        .build_server(true)
        .build_client(true)
        .out_dir(&out_dir)
        .compile(
            &[proto_file],
            &[proto_include_dir, google_wellknown_types_include_dir],
        )
        .context("Échec de la compilation des fichiers protocol buffer avec tonic_build")?;

    println!("cargo:info=Protocol buffers compilés avec succès.");
    println!("cargo:info=Le script de build s'est terminé avec succès.");

    Ok(())
}