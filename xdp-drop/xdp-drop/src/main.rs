use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    util::online_cpus,
};
use aya_log::EbpfLogger;
use clap::Parser;
use flexi_logger::{Logger, FileSpec, Duplicate};
use log::{error, info, warn};
use std::net::Ipv4Addr;
use tokio::signal;

use xdp_drop_common::IpPort; // struct partagée

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s8")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // 🔥 Initialise flexi_logger pour enregistrer dans un fichier et afficher aussi dans stdout
    Logger::try_with_str("info")?
        .log_to_file()
        .directory("logs") // dossier où sera stocké le log
        .basename("firewall")  // nom du fichier : firewall.log
        .suppress_timestamp()  // pas de timestamp dans le nom de fichier
        .duplicate_to_stdout(Duplicate::Info) // Affiche aussi dans le terminal
        .start()
        .context("Erreur lors de l'initialisation de flexi_logger")?;

    let mut bpf = aya::Bpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-drop"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Logger eBPF non initialisé : {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&opt.iface, XdpFlags::default())
        .context("Échec de l'attachement du programme XDP")?;

    // 🧠 Ajouter une IP/port à bloquer
    let mut blocklist: HashMap<_, IpPort, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let key = IpPort {
        addr: u32::from_be_bytes([192, 168, 1, 101]),
        port: 1234,
        _pad: 0,
    };
    blocklist.insert(key, 1, 0)?;

    // ✅ Exemple de log
    info!("🔥 Le firewall est en marche !");
    info!("⏳ En attente de Ctrl-C pour arrêter...");

    signal::ctrl_c().await?;
    info!("🛑 Arrêt du firewall...");

    Ok(())
}
