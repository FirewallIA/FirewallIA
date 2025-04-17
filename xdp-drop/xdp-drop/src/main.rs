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

use aya::util::online_cpus;
use xdp_drop_common::IpPort; // bien sûr il faut que la struct soit partagée avec le user


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s8")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    let mut bpf = aya::Bpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-drop"
    )))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp =
        bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // (1)
    let mut blocklist: HashMap<_, IpPort, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let key = IpPort {
        addr: u32::from_be_bytes([192, 168, 1, 101]),
        port: 1234,
    };
    blocklist.insert(key, 1, 0)?;
    println!("INSERT: IP {}, PORT {}", key.addr, key.port);

    if let Some(val) = blocklist.get(&key, 0)? {
        println!("FOUND entry: {:?}", val);
    } else {
        println!("❌ Not found in map!");
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}