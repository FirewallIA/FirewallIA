use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s8")]
    iface: String,
}

fn validate_args(opt: &Opt) {
    if opt.iface.is_none() {
        let mut cmd = Opt::command();
        eprintln!("Erreur : l'interface réseau est requise.\n");
        cmd.print_help().unwrap();
        std::process::exit(1);
    }
}

//  RUST_LOG=info cargo run -- -i enp0s1

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-drop"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // IP + port à bloquer
    let mut blocklist: HashMap<_, IpPortKey, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let ip: Ipv4Addr = "192.168.1.10".parse().unwrap();
    let ip_addr_be = u32::from(ip).to_be();
    let port: u16 = 80;

    let key = IpPortKey { ip: ip_addr_be, port };
    blocklist.insert(&key, &1, 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
