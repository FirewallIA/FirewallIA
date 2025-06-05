// xdp-drop/build.rs
use anyhow::{anyhow, Context as _};
use aya_build::{cargo_metadata, BuildOptions, Toolchain};
use std::env;
use std::fs; // Ajout pour std::fs::copy
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    // S'assurer que ce script de build est ré-exécuté s'il change
    println!("cargo:rerun-if-changed=build.rs");

    // Récupérer le répertoire de sortie (OUT_DIR) pour ce crate (xdp-drop)
    let out_dir = PathBuf::from(env::var("OUT_DIR").context("La variable d'environnement OUT_DIR n'est pas définie")?);

    // --- Compilation eBPF et copie de l'artefact ---
    println!("cargo:info=Début de la compilation eBPF et de la configuration...");

    // Accéder aux métadonnées du projet Cargo pour trouver le package eBPF
    let cargo_meta_output = cargo_metadata::MetadataCommand::new()
        .no_deps() // Comme dans votre original, pour ne pas charger toutes les dépendances
        .exec()
        .context("Échec de l'exécution de la commande cargo metadata")?;

    // Trouver le package eBPF (par exemple, "xdp-drop-ebpf")
    let ebpf_package_ref = cargo_meta_output
        .packages
        .iter()
        .find(|p| p.name == "xdp-drop-ebpf") // Assurez-vous que "xdp-drop-ebpf" est le nom correct de votre crate eBPF
        .ok_or_else(|| {
            anyhow!("Le package eBPF 'xdp-drop-ebpf' n'a pas été trouvé dans l'espace de travail. Assurez-vous qu'il est membre et correctement nommé.")
        })?;

    // Options de build pour le programme eBPF. Les options par défaut sont généralement suffisantes.
    let build_options = BuildOptions {
        // Par défaut :
        // - respecte le profil actuel (debug/release)
        // - utilise le répertoire target de l'espace de travail pour les artefacts de build eBPF
        // - `rerun_if_changed` est `true` par défaut, donc aya_build gérera
        //   `cargo:rerun-if-changed` pour les fichiers sources eBPF.
        ..Default::default()
    };

    // Compiler le(s) programme(s) eBPF.
    // `aya_build::build_ebpf` retourne un Vec<PathBuf> des chemins vers les artefacts compilés.
    let compiled_ebpf_artifact_paths = aya_build::build_ebpf(
        std::iter::once(ebpf_package_ref), // `build_ebpf` attend un itérateur de &Package
        &Toolchain::default(),             // Passer en tant que référence
        &build_options,                    // Passer en tant que référence
    )
    .context(format!(
        "Échec de la compilation du programme eBPF à partir du package '{}'",
        ebpf_package_ref.name
    ))?;

    // Supposons que le package "xdp-drop-ebpf" produit un seul artefact,
    // qui est le fichier objet eBPF que nous voulons intégrer.
    let ebpf_source_path = compiled_ebpf_artifact_paths.get(0).ok_or_else(|| {
        anyhow!(
            "aya_build::build_ebpf n'a retourné aucun chemin d'artefact pour le package eBPF '{}'",
            ebpf_package_ref.name
        )
    })?;

    // Le programme userspace (main.rs) s'attend à ce que le fichier objet eBPF
    // soit nommé "xdp-drop" à l'intérieur de son OUT_DIR.
    let ebpf_dest_filename = "xdp-drop";
    let ebpf_dest_path = out_dir.join(ebpf_dest_filename);

    // Copier l'artefact eBPF compilé vers OUT_DIR/xdp-drop
    fs::copy(ebpf_source_path, &ebpf_dest_path).context(format!(
        "Échec de la copie de l'objet eBPF de la source '{:?}' vers la destination '{:?}'",
        ebpf_source_path, ebpf_dest_path
    ))?;

    println!(
        "cargo:info=Objet eBPF copié avec succès de {:?} vers {:?}",
        ebpf_source_path, ebpf_dest_path
    );

    // --- Compilation des Protocol Buffers (tonic) ---
    println!("cargo:info=Début de la compilation des protocol buffers...");
    let proto_file = "../proto/firewall.proto"; // Chemin relatif à xdp-drop/Cargo.toml
    let proto_include_dir = "../proto";
    // S'assurer que google/protobuf/empty.proto est trouvable via ce chemin
    // Par exemple, ../proto/include/google/protobuf/empty.proto
    let google_wellknown_types_include_dir = "../proto/include";

    println!("cargo:rerun-if-changed={}", proto_file);
    // Vous pourriez aussi ajouter des reruns pour d'autres .proto ou pour le répertoire google_wellknown_types_include_dir

    tonic_build::configure()
        .compile_well_known_types(true) // Gère google.protobuf.Empty si trouvable
        .build_server(true)
        .build_client(true) // Utile pour des tests ou d'autres composants
        .out_dir(&out_dir)  // Les fichiers Rust générés pour les protos vont aussi dans OUT_DIR
        .compile(
            &[proto_file],
            &[proto_include_dir, google_wellknown_types_include_dir], // Chemins d'inclusion pour protoc
        )
        .context("Échec de la compilation des fichiers protocol buffer avec tonic_build")?;

    println!("cargo:info=Protocol buffers compilés avec succès.");
    println!("cargo:info=Le script de build s'est terminé avec succès.");

    Ok(())
}