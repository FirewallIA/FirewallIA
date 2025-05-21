use anyhow::{Context as _, Result};
use std::env;
use std::path::PathBuf;

fn main() -> Result<()> {
    // Chemin vers le répertoire de sortie où Rust met les artefacts de build
    let out_dir = PathBuf::from(env::var("OUT_DIR").context("La variable d'environnement OUT_DIR n'est pas définie")?);

    // Chemin vers le répertoire contenant vos fichiers .proto
    // Relatif à la racine du crate xdp-drop-cli
    let proto_dir = PathBuf::from("proto");

    // Chemin vers le fichier .proto principal de votre service
    let proto_file = proto_dir.join("firewall.proto");

    // Répertoires à inclure pour que `protoc` puisse résoudre les `import`
    // Le premier est pour les imports relatifs (si vous en aviez dans firewall.proto
    // qui ne sont pas des types bien connus de Google).
    // Le second est pour les imports comme `import "google/protobuf/empty.proto";`
    let proto_includes = &[
        proto_dir.clone(), // Pour `import "autre_fichier.proto";` si `autre_fichier.proto` est dans `proto/`
        proto_dir.join("include"), // Pour `import "google/protobuf/empty.proto";`
    ];

    // S'assurer que les chemins existent (facultatif mais bon pour le débogage)
    if !proto_file.exists() {
        panic!("Fichier proto principal non trouvé : {:?}", proto_file);
    }
    if !proto_dir.join("include/google/protobuf/empty.proto").exists() {
        panic!("Fichier google/protobuf/empty.proto non trouvé dans le répertoire d'inclusion : {:?}", proto_dir.join("include"));
    }

    // Configuration de tonic_build
    tonic_build::configure()
        // Active la compilation des types "bien connus" de Google comme Empty, Timestamp, etc.
        // Cela s'attend à trouver les .proto correspondants dans les chemins d'inclusion.
        .compile_well_known_types(true)
        // Nous construisons un client, pas un serveur
        .build_client(true)
        .build_server(false)
        // Spécifie le répertoire où les fichiers Rust générés seront placés
        .out_dir(&out_dir)
        // Compile le fichier .proto spécifié, en utilisant les chemins d'inclusion fournis
        .compile(
            &[proto_file.clone()], // Fichiers .proto à compiler
            proto_includes,        // Répertoires où chercher les imports
        )
        .with_context(|| format!("Échec de la compilation du fichier .proto : {:?}", proto_file))?;

    // Indique à Cargo de ré-exécuter ce script de build si les fichiers .proto changent.
    // Utilisez des chemins relatifs à la racine du crate.
    println!("cargo:rerun-if-changed=proto/firewall.proto");
    println!("cargo:rerun-if-changed=proto/include/google/protobuf/empty.proto");

    Ok(())
}