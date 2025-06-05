// xdp-drop/build.rs
use anyhow::{anyhow, Context as _};
use aya_build::{cargo_metadata, Toolchain};
use std::env;
use std::fs;
use std::path::PathBuf; // Garder pour out_dir qui vient de env::var

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").context("La variable d'environnement OUT_DIR n'est pas définie")?);
    let profile = env::var("PROFILE").context("La variable d'environnement PROFILE n'est pas définie")?;

    println!("cargo:info=Script de build xdp-drop démarré.");
    println!("cargo:info=OUT_DIR: {}", out_dir.display()); // PathBuf a .display()
    println!("cargo:info=PROFILE: {}", profile);

    let cargo_meta = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("Échec de l'exécution de la commande cargo metadata")?;

    let ebpf_package = cargo_meta
        .packages
        .iter()
        .find(|p| p.name == "xdp-drop-ebpf")
        .ok_or_else(|| {
            anyhow!("Le package eBPF 'xdp-drop-ebpf' n'a pas été trouvé dans l'espace de travail.")
        })?;
    
    // Utf8PathBuf (de ebpf_package.manifest_path) implémente Display
    println!("cargo:info=Package eBPF trouvé: {} (manifest: {})", ebpf_package.name, ebpf_package.manifest_path);

    println!("cargo:info=Lancement de la compilation eBPF pour le package: {}", ebpf_package.name);
    aya_build::build_ebpf(
        std::iter::once(ebpf_package.clone()),
        Toolchain::default(),
    )
    .context(format!(
        "Échec de la compilation du programme eBPF à partir du package '{}'",
        ebpf_package.name
    ))?;
    println!("cargo:info=Compilation eBPF pour {} terminée (supposément avec succès).", ebpf_package.name);

    let target_directory = &cargo_meta.target_directory; // Ceci est un &camino::Utf8PathBuf
    let ebpf_crate_name = &ebpf_package.name;
    let bpf_target_triple = "bpfel-unknown-none";

    // Utf8PathBuf (target_directory) .join renvoie Utf8PathBuf
    let ebpf_source_path = target_directory
        .join(bpf_target_triple)
        .join(&profile)
        .join(ebpf_crate_name); // ebpf_source_path est Utf8PathBuf

    // Utf8PathBuf implémente Display, donc on peut l'utiliser directement dans format! ou println!
    println!("cargo:info=Chemin source eBPF construit: {}", ebpf_source_path); // MODIFIÉ

    if !ebpf_source_path.exists() { // .exists() fonctionne sur Utf8PathBuf
        let ebpf_source_path_o = ebpf_source_path.with_extension("o");
        let mut extra_msg = String::new();
        if ebpf_source_path_o.exists() {
            // Utf8PathBuf implémente Display
            extra_msg = format!(" (Note: un fichier existe à '{}' avec une extension .o, mais le chemin sans .o était attendu)", ebpf_source_path_o); // MODIFIÉ
        }

        return Err(anyhow!(
            // Utf8PathBuf et &Utf8PathBuf implémentent Display
            "L'objet eBPF compilé attendu n'a PAS été trouvé à '{}'.{}\n\
            Vérifiez les points suivants :\n\
            1. Que la compilation eBPF (étape précédente) s'est réellement terminée sans erreur masquée.\n\
            2. Que le chemin construit est correct (Target dir: '{}', Triple: '{}', Profil: '{}', Nom du crate: '{}').\n\
            3. Le nom exact de l'artefact produit par `aya-build` pour votre version.",
            ebpf_source_path, extra_msg, target_directory, bpf_target_triple, profile, ebpf_crate_name // MODIFIÉ
        ));
    }
    // Utf8PathBuf implémente Display
    println!("cargo:info=Artefact eBPF trouvé à: {}", ebpf_source_path); // MODIFIÉ

    let ebpf_dest_filename = "xdp-drop";
    let ebpf_dest_path = out_dir.join(ebpf_dest_filename); // out_dir est PathBuf, donc ebpf_dest_path est PathBuf

    // fs::copy attend des AsRef<Path>, Utf8PathBuf implémente AsRef<Path>
    fs::copy(&ebpf_source_path, &ebpf_dest_path).context(format!(
        // Pour fs::copy, les chemins sont convertis implicitement si nécessaire.
        // Pour l'affichage dans le message d'erreur, utilisons leur trait Display.
        "Échec de la copie de l'objet eBPF de '{}' vers '{:?}'", // {:?} pour PathBuf est ok
        ebpf_source_path, ebpf_dest_path
    ))?;

    println!(
        "cargo:info=Objet eBPF copié avec succès de {} vers {:?}",
        ebpf_source_path, // Utf8PathBuf
        ebpf_dest_path    // PathBuf
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