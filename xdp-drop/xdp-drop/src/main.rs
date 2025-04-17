use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use flexi_logger::{Logger, FileSpec, Duplicate};
use log::{info, warn};
use tokio::signal;

use xdp_drop_common::IpPort;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s8")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // 📝 Initialisation du logger : log dans fichier + stdout
    Logger::try_with_str("info")?
        .log_to_file(
            FileSpec::default()
                .directory("logs")     // dossier où sera créé le log
                .basename("firewall")  // nom du fichier log : firewall.log
                .suppress_timestamp(), // pas de timestamp dans le nom de fichier
        )
        .duplicate_to_stdout(Duplicate::Info) // affiche aussi dans le terminal
        .start()
        .context("Erreur lors de l'initialisation du logger")?;

    // 🧠 Chargement du programme eBPF
    let mut bpf = aya::Bpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-drop"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Logger eBPF non initialisé : {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program
        .load()?
        .attach(&opt.iface, XdpFlags::default())
        .context("Échec de l'attachement du programme XDP")?;

    // 🔒 Ajout d'une IP + port à bloquer
    let mut blocklist: HashMap<_, IpPort, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let key = IpPort {
        addr: u32::from_be_bytes([192, 168, 1, 101]),
        port: 1234,
        _pad: 0,
    };
    blocklist.insert(key, 1, 0)?;

    // ✅ Logs de statut
    info!("🔥 Le firewall est en marche !");
    info!("⏳ Appuyez sur Ctrl-C pour arrêter...");

    signal::ctrl_c().await?;
    info!("🛑 Arrêt du firewall...");

    Ok(())
}
