// Fichier : /root/FirewallIA/xdp-drop/xdp-drop/build.rs

use anyhow::{Context, Result};
use aya_build::Build;
use std::env;
use std::path::PathBuf;

fn main() -> Result<()> {
    // Déclenche la recompilation si ces fichiers changent.
    println!("cargo:rerun-if-changed=../xdp-drop-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../xdp-drop-common/src/lib.rs");
    println!("cargo:rerun-if-changed=../proto/firewall.proto");
    println!("cargo:rerun-if-changed=build.rs");

    // --- Compilation eBPF ---
    println!("cargo:info=Compilation du programme eBPF...");

    // Le dossier de sortie pour les artefacts eBPF.
    let bpf_target_arch = "bpfel-unknown-none";
    let bpf_out_dir = "target-ebpf";

    // Lance la compilation du paquet 'xdp-drop-ebpf'
    let args = [
        "build",
        "--package=xdp-drop-ebpf",
        &format!("--target={bpf_target_arch}"),
        "--release",
        &format!("--target-dir={bpf_out_dir}"),
    ];
    let status = std::process::Command::new("cargo")
        .args(args)
        .status()
        .context("Échec du lancement de la commande de build eBPF")?;

    if !status.success() {
        anyhow::bail!("La commande de build eBPF a échoué");
    }

    println!("cargo:info=Compilation eBPF terminée.");

    // --- Compilation des Protocol Buffers (tonic) ---
    println!("cargo:info=Compilation des protocol buffers...");

    let out_dir = PathBuf::from(env::var("OUT_DIR").context("OUT_DIR non défini")?);
    let proto_file = "../proto/firewall.proto";
    let proto_include_dir = "../proto";

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&out_dir) // Important de spécifier le out_dir pour que `include!` fonctionne
        .compile(&[proto_file], &[proto_include_dir])
        .context("Échec de la compilation des fichiers protocol buffer")?;
    
    println!("cargo:info=Protocol buffers compilés.");
    println!("cargo:info=Script de build terminé avec succès.");

    Ok(())
}