// Fichier : xdp-drop/src/main.rs

use anyhow::Context;
use aya::{
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s3")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // On utilise env_logger pour une gestion simple des logs
    env_logger::init();

    // Compile et charge le programme eBPF.
    // Le chemin pointe vers le binaire compilé du projet xdp-drop-ebpf.
    let mut bpf = Bpf::load_file("xdp-drop-ebpf/target/bpfel-unknown-none/debug/xdp-drop-ebpf")?;
    
    // Initialise le logger pour remonter les logs du programme eBPF.
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Récupère le programme par son nom et le convertit en programme de type Xdp.
    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    
    // Attache le programme à l'interface spécifiée.
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}```

### **4. Dépendances du chargeur : `xdp-drop/Cargo.toml`**

Ce fichier contient les dépendances pour le programme qui s'exécute sur votre machine. J'ai nettoyé les dépendances inutiles (`postgres`, `tonic`, etc.) pour ne garder que le nécessaire.

```toml
# Fichier : xdp-drop/Cargo.toml

[package]
name = "xdp-drop"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
aya = { version = "0.12", features = ["async_tokio"] }
aya-log = "0.12"
xdp-drop-common = { path = "../xdp-drop-common", features = ["user"] }
anyhow = "1"
clap = { version = "4.1", features = ["derive"] }
log = "0.4"
tokio = { version = "1.25", features = ["macros", "rt-multi-thread", "signal"] }
env_logger = "0.11"

# On supprime la dépendance directe à aya-ebpf qui n'a rien à faire ici.

[build-dependencies]
aya-build = { git = "https://github.com/aya-rs/aya" }
anyhow = "1"

# Cette partie est nécessaire pour que `cargo build` compile aussi le code eBPF.
xdp-drop-ebpf = { path = "../xdp-drop-ebpf" }

[[bin]]
name = "xdp-drop"
path = "src/main.rs"