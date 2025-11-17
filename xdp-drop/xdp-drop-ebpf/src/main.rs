// In xdp-drop-ebpf/src/main.rs
#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)] // dead_code for unused parts during dev

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info; // For logging from eBPF
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use xdp_drop_common::{IpPort,PROTO_ANY, PROTO_ICMP, PROTO_TCP, PROTO_UDP}; // Import your shared struct

// Panic handler (required for no_std)
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The eBPF map for storing firewall rules.
// Key: IpPort (source IP, dest IP, dest port)
// Value: u32 (action code, e.g., 1 for DENY, 2 for ALLOW)
#[map]
static BLOCKLIST: HashMap<IpPort, u32> = HashMap::<IpPort, u32>::with_max_entries(1024, 0);

// Action constants (must match userspace definitions)
const ACTION_DENY_FROM_MAP: u32 = 1;
const ACTION_ALLOW_FROM_MAP: u32 = 2;
const IP_ANY_BE : u32 = 0;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED, // Abort on error (e.g., out-of-bounds access)
    }
}

// Helper to safely get a pointer to data in the packet.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(()); // Offset + size is out of bounds
    }

    Ok((start + offset) as *const T)
}

// Checks the BLOCKLIST map for a matching rule.
// Returns Some(action_value) if a rule is found, None otherwise.
#[inline(always)]
fn check_firewall_rule(key: &IpPort) -> Option<u32> {
    unsafe { BLOCKLIST.get(key).copied() }
}

// Main XDP processing logic
fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // 1. On parse juste assez pour avoir les informations de base
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_ip_be = unsafe { (*ipv4_hdr).src_addr };
    let dest_ip_be = unsafe { (*ipv4_hdr).dst_addr };
    let protocol = unsafe { (*ipv4_hdr).proto };

    // 2. On logne UNE SEULE FOIS pour prouver que le programme s'exécute
    info!(&ctx, "[TEST] Paquet vu: Proto={}", protocol as u8);

    // 3. On ne fait AUCUNE recherche et on laisse tout passer
    Ok(xdp_action::XDP_PASS)
}