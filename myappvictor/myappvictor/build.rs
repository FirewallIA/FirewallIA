use std::{env, path::PathBuf, process::Command};

use aya_tool::generate::InputFile;

fn main() {
    // Répertoire où le binaire eBPF compilé sera placé par ce script
    // Le code user-space lira depuis cet emplacement via include_bytes_aligned!
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let ebpf_crate_path = PathBuf::from("../myappvictor-ebpf"); // Chemin vers le crate eBPF

    // Nom du binaire eBPF tel que défini dans myappvictor-ebpf/Cargo.toml (ou par défaut)
    // Doit correspondre au nom utilisé dans `include_bytes_aligned!`
    let ebpf_binary_name = "xdp-drop"; // !! IMPORTANT: Doit correspondre à votre code !!

    // Définir la cible BPF. bpfel = little endian, bpfeb = big endian.
    // Choisissez en fonction de votre architecture ou laissez aya-tool décider si possible.
    // 'bpfel-unknown-none' est commun sur x86_64.
    let target = "bpfel-unknown-none";
    let target_arch = "bpf"; // Utilisé par aya_tool::build_ebpf

    println!("cargo:rerun-if-changed={}/src/main.rs", ebpf_crate_path.display());
    println!("cargo:rerun-if-changed={}/Cargo.toml", ebpf_crate_path.display());

    // Utiliser aya_tool::build_ebpf pour compiler le code eBPF
    let args = aya_tool::BuildArgs {
        input_file: InputFile::path(ebpf_crate_path.join("src/main.rs")), // Ou juste le dossier du crate
        target: Some(target.to_string()),
        target_arch: Some(target_arch.to_string()), // Nécessaire si target est spécifié
        profile: "release".to_string(), // Compiler en mode release pour l'optimisation
        dest_path: out_dir.clone(), // Où copier le binaire final
        dest_file_name: Some(ebpf_binary_name.to_string()), // Nom du fichier de sortie
        ..Default::default() // Utilise les autres valeurs par défaut
    };

    match aya_tool::build_ebpf(args) {
        Ok(path) => {
             println!("cargo:info=Successfully built eBPF program to {:?}", path);
             // Pas besoin de copier manuellement, aya_tool le fait avec dest_path/dest_file_name
        }
        Err(e) => {
            panic!("Failed to build eBPF program: {}", e);
        }
    }

    // // --- Alternative: Appel manuel de cargo build ---
    // // Chemin vers le répertoire cible pour le build eBPF
    // let target_dir = ebpf_crate_path.join("target");
    // let profile = "release"; // Compiler en mode release pour l'optimisation

    // let status = Command::new("cargo")
    //     .current_dir(&ebpf_crate_path) // Exécuter dans le répertoire du crate eBPF
    //     .arg("build")
    //     .arg("--target")
    //     .arg(target)
    //     .arg("--profile")
    //     .arg(profile)
    //     // Flags nécessaires pour la compilation no_std vers BPF
    //     .arg("-Z")
    //     .arg("build-std=core")
    //     // Spécifier explicitement le répertoire cible peut aider
    //     .env("CARGO_TARGET_DIR", &target_dir)
    //     .status()
    //     .expect("Failed to run cargo build for eBPF program");

    // if !status.success() {
    //     panic!("eBPF program build failed");
    // }

    // // Chemin vers le binaire eBPF compilé
    // let compiled_elf_path = target_dir
    //     .join(target)
    //     .join(profile)
    //     .join(ebpf_binary_name); // Utilise le nom défini plus haut

    // // Copier le binaire compilé vers OUT_DIR pour include_bytes_aligned!
    // let dest_path = out_dir.join(ebpf_binary_name);
    // std::fs::copy(&compiled_elf_path, &dest_path)
    //     .expect("Failed to copy compiled eBPF program to OUT_DIR");
    // // --- Fin de l'alternative ---

    println!("cargo:info=eBPF build script finished.");
}