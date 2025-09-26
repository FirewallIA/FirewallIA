#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
    helpers::bpf_ktime_get_ns,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
};

use xdp_drop_common::IpPort;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Stateless blocklist map (déjà présent)
#[map]
static BLOCKLIST: HashMap<IpPort, u32> = HashMap::<IpPort, u32>::with_max_entries(1024, 0);

const ACTION_DENY_FROM_MAP: u32 = 1;
const ACTION_ALLOW_FROM_MAP: u32 = 2;

// Mini-conntrack : clé 4-tuple (addr src,dst,ports,proto)
#[repr(C)]
#[derive(Clone, Copy)]
struct ConnKey {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    _pad: u8,
}

#[map]
static CONNTRACK: HashMap<ConnKey, u64> =
    HashMap::<ConnKey, u64>::with_max_entries(16_384, 0);

// timeout en nanosecondes (p.ex. 60s)
const CONNTRACK_TIMEOUT_NS: u64 = 60 * 1_000_000_000u64;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

// helpers pour lire ports safely
unsafe fn read_u16_be(ptr: *const u8) -> Result<u16, ()> {
    // assume caller checked bounds
    let b0 = *ptr;
    let b1 = *ptr.add(1);
    Ok(u16::from_be_bytes([b0, b1]))
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // parse Ethernet
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }
    let l3_offset = EthHdr::LEN;

    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, l3_offset)? };
    let source_ip_be = unsafe { (*ipv4_hdr).src_addr };
    let dest_ip_be = unsafe { (*ipv4_hdr).dst_addr };
    let protocol = unsafe { (*ipv4_hdr).proto };
    let ihl = unsafe { (*ipv4_hdr).ihl() } as usize;
    let transport_offset = l3_offset + ihl * 4;

    // --- Stateless blocklist check ---
    let stateless_key = IpPort { addr: source_ip_be, addr_dest: dest_ip_be, port: 0, _pad: 0 };
    if let Some(action) = unsafe { BLOCKLIST.get(&stateless_key) } {
        if *action == ACTION_DENY_FROM_MAP {
            return Ok(xdp_action::XDP_DROP);
        }
        if *action == ACTION_ALLOW_FROM_MAP {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // Only TCP/UDP handled by stateful part
    if protocol != IpProto::Tcp && protocol != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse transport ports (safe bounds checked by ptr_at)
    let sport: u16;
    let dport: u16;
    unsafe {
        let port_ptr = ptr_at::<u8>(&ctx, transport_offset)?;
        // first two bytes = src port (big endian)
        sport = read_u16_be(port_ptr)?; // network order
        dport = read_u16_be(port_ptr.add(2))?;
    }

    // Convert IPs to host order for bit ops
    let source_ip = u32::from_be(source_ip_be);
    const INTERNAL_NETWORK_PREFIX: u32 = 0xC0A80100; // 192.168.1.0
    const INTERNAL_NETWORK_MASK:   u32 = 0xFFFFFF00; // /24
    let is_from_internal = (source_ip & INTERNAL_NETWORK_MASK) == INTERNAL_NETWORK_PREFIX;

    // Build keys (store in network byte order to match incoming keys consistently)
    let fwd_key = ConnKey {
        src_ip: source_ip_be,
        dst_ip: dest_ip_be,
        src_port: sport,
        dst_port: dport,
        proto: protocol as u8,
        _pad: 0,
    };
    let rev_key = ConnKey {
        src_ip: dest_ip_be,
        dst_ip: source_ip_be,
        src_port: dport,
        dst_port: sport,
        proto: protocol as u8,
        _pad: 0,
    };

    // current time
    let now = unsafe { bpf_ktime_get_ns() };

    if is_from_internal {
        // Outgoing: insert forward tuple with expiry
        let expiry = now.saturating_add(CONNTRACK_TIMEOUT_NS);
        // insert or update
        unsafe {
            // CONNTRACK.insert can't be used in no_std macro; use HashMap::insert
            let _ = CONNTRACK.insert(&fwd_key, &expiry, 0);
        }
        return Ok(xdp_action::XDP_PASS);
    } else {
        // Incoming: check if reverse tuple exists and not expired
        if let Some(ts_ptr) = unsafe { CONNTRACK.get(&rev_key) } {
            // ts_ptr is a reference to u64
            let expiry = unsafe { *ts_ptr };
            if expiry > now {
                // refresh expiry (optional) to keep alive
                let new_expiry = now.saturating_add(CONNTRACK_TIMEOUT_NS);
                unsafe {
                    let _ = CONNTRACK.insert(&rev_key, &new_expiry, 0);
                }
                return Ok(xdp_action::XDP_PASS);
            } else {
                // expired: remove and drop
                unsafe { CONNTRACK.remove(&rev_key) };
                return Ok(xdp_action::XDP_DROP);
            }
        } else {
            // Unknown incoming connection → drop
            return Ok(xdp_action::XDP_DROP);
        }
    }
}
