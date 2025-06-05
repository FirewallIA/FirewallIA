// xdp-drop/build.rs
use anyhow::{anyhow, Context as _};
use aya_build::{cargo_metadata, Toolchain};
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");

    // Récupérer OUT_DIR (où copier l'artefact final) et PROFILE (debug/release)
    let out_dir = PathBuf::from(env::var("OUT_DIR").context("La variable d'environnement OUT_DIR n'est pas définie")?);
    let profile = env::var("PROFILE").context("La variable d'environnement PROFILE n'est pas définie")?;

    println!("cargo:info=Script de build xdp-drop démarré.");
    println!("cargo:info=OUT_DIR: {}", out_dir.display());
    println!("cargo:info=PROFILE: {}", profile);

    // Obtenir les métadonnées du projet Cargo
    let cargo_meta = cargo_metadata::MetadataCommand::new()
        .no_deps() // Important pour ne cibler que les packages du workspace direct
        .exec()
        .context("Échec de l'exécution de la commande cargo metadata")?;

    // Trouver le package eBPF (par exemple, "xdp-drop-ebpf")
    let ebpf_package = cargo_meta
        .packages
        .iter()
        .find(|p| p.name == "xdp-drop-ebpf") // Assurez-vous que "xdp-drop-ebpf" est le nom correct
        .ok_or_else(|| {
            anyhow!("Le package eBPF 'xdp-drop-ebpf' n'a pas été trouvé dans l'espace de travail.")
        })?;
    
    println!("cargo:info=Package eBPF trouvé: {} (manifest: {})", ebpf_package.name, ebpf_package.manifest_path);

    // Étape 1: Compiler le code eBPF.
    // Nous supposons que cette fonction retourne Result<(), _> (ou équivalent menant à `()` après `?`)
    // d'après l'erreur E0599 précédente.
    println!("cargo:info=Lancement de la compilation eBPF pour le package: {}", ebpf_package.name);
    aya_build::build_ebpf(
        std::iter::once(ebpf_package.clone()), // `build_ebpf` attend un itérable de `Package`
        Toolchain::default(),                  // `Toolchain` passé par valeur
    )
    .context(format!(
        "Échec de la compilation du programme eBPF à partir du package '{}'",
        ebpf_package.name
    ))?;
    println!("cargo:info=Compilation eBPF pour {} terminée (supposément avec succès).", ebpf_package.name);


    // Étape 2: Construire manuellement le chemin vers l'artefact eBPF compilé.
    // L'artefact se trouve généralement dans `target/[TRIPLE_BPF]/[PROFIL]/[NOM_CRATE_EBPF]`
    
    // Le répertoire `target` global du workspace/projet
    let target_directory = &cargo_meta.target_directory;
    // Le nom du crate eBPF (ex: "xdp-drop-ebpf")
    let ebpf_crate_name = &ebpf_package.name; 
    // Le triple cible BPF par défaut. Aya utilise souvent 'bpfel-unknown-none' (little-endian).
    // Si votre crate eBPF spécifie un autre target dans son Cargo.toml ([package.metadata.aya.target]), ajustez ici.
    let bpf_target_triple = "bpfel-unknown-none"; 

    let ebpf_source_path = target_directory
        .join(bpf_target_triple)
        .join(&profile) // "debug" ou "release"
        .join(ebpf_crate_name); // Nom du crate eBPF

    println!("cargo:info=Chemin source eBPF construit: {}", ebpf_source_path.display());

    // Vérifier si l'artefact existe à cet emplacement
    if !ebpf_source_path.exists() {
        // Tentative avec une extension .o, juste au cas où (moins courant avec aya-build récent)
        let ebpf_source_path_o = ebpf_source_path.with_extension("o");
        let mut extra_msg = String::new();
        if ebpf_source_path_o.exists() {
            extra_msg = format!(" (Note: un fichier existe à '{}' avec une extension .o, mais le chemin sans .o était attendu)", ebpf_source_path_o.display());
        }

        return Err(anyhow!(
            "L'objet eBPF compilé attendu n'a PAS été trouvé à '{}'.{}\n\
            Vérifiez les points suivants :\n\
            1. Que la compilation eBPF (étape précédente) s'est réellement terminée sans erreur masquée.\n\
            2. Que le chemin construit est correct (Target dir: '{}', Triple: '{}', Profil: '{}', Nom du crate: '{}').\n\
            3. Le nom exact de l'artefact produit par `aya-build` pour votre version.",
            ebpf_source_path.display(), extra_msg, target_directory.display(), bpf_target_triple, profile, ebpf_crate_name
        ));
    }
    println!("cargo:info=Artefact eBPF trouvé à: {}", ebpf_source_path.display());

    // Étape 3: Copier l'artefact eBPF vers OUT_DIR sous le nom attendu par main.rs.
    let ebpf_dest_filename = "xdp-drop"; // Nom attendu par include_bytes_aligned! dans main.rs
    let ebpf_dest_path = out_dir.join(ebpf_dest_filename);

    fs::copy(&ebpf_source_path, &ebpf_dest_path).context(format!(
        "Échec de la copie de l'objet eBPF de '{:?}' vers '{:?}'",
        ebpf_source_path, ebpf_dest_path
    ))?;

    println!(
        "cargo:info=Objet eBPF copié avec succès de {:?} vers {:?}",
        ebpf_source_path, ebpf_dest_path
    );

    // --- Compilation des Protocol Buffers (tonic) ---
    // (Cette partie reste inchangée)
    println!("cargo:info=Début de la compilation des protocol buffers...");
    let proto_file = "../proto/firewall.proto"; // Relatif à xdp-drop/Cargo.toml
    let proto_include_dir = "../proto";
    let google_wellknown_types_include_dir = "../proto/include"; // Pour google.protobuf.Empty

    println!("cargo:rerun-if-changed={}", proto_file);
    // Ajoutez cargo:rerun-if-changed pour d'autres fichiers .proto ou répertoires d'include si nécessaire

    tonic_build::configure()
        .compile_well_known_types(true)
        .build_server(true)
        .build_client(true)
        .out_dir(&out_dir) // Les fichiers Rust générés pour les protos vont aussi dans OUT_DIR
        .compile(
            &[proto_file],
            &[proto_include_dir, google_wellknown_types_include_dir],
        )
        .context("Échec de la compilation des fichiers protocol buffer avec tonic_build")?;

    println!("cargo:info=Protocol buffers compilés avec succès.");
    println!("cargo:info=Le script de build s'est terminé avec succès.");

    Ok(())
}