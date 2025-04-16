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

    let program: &mut Xdp =
        bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // IP blocklist
    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
    let block_addr: u32 = Ipv4Addr::new(192, 168, 1, 100).into();
    blocklist.insert(block_addr, 0, 0)?;

    // Port blocklist
    let mut blocked_ports: HashMap<_, u16, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKED_PORTS").unwrap())?;
    let block_port: u16 = 22; // SSH
    blocked_ports.insert(block_port, 0, 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
