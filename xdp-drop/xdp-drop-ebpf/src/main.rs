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
    // 1. Parse Ethernet Header
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // 2. Parse IPv4 Header
    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_ip_be = unsafe { (*ipv4_hdr).src_addr }; // Big-endian (network order)
    let dest_ip_be = unsafe { (*ipv4_hdr).dst_addr };   // Big-endian (network order)
    let protocol = unsafe { (*ipv4_hdr).proto };

    // Calculate offset to the transport layer header
    // IHL (Internet Header Length) is in 32-bit words, so multiply by 4 for bytes.
    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4_hdr).ihl() } as usize * 4);

    // 3. Parse Transport Header (TCP/UDP to get destination port)
    // We are primarily interested in the destination port for firewall rules.
     let dest_port_be: u16 = match protocol {
        IpProto::Tcp => unsafe { (*ptr_at::<TcpHdr>(&ctx, transport_offset)?).dest },
        IpProto::Udp => unsafe { (*ptr_at::<UdpHdr>(&ctx, transport_offset)?).dest },
        _ => 0, // Pour ICMP et autres, le port est 0
    };
    info!(&ctx, "[DEBUG eBPF] Paquet reçu: S_IP={:i}, D_IP={:i}, D_PORT={}, Proto={}",
        u32::from_be(source_ip_be),
        u32::from_be(dest_ip_be),
        u16::from_be(dest_port_be),
        protocol as u8
    );

     // (exact src, exact dest) - port exact
    let key_exact = IpPort {
        addr: source_ip_be,
        addr_dest: dest_ip_be,
        port: dest_port_be,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_exact) {
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (exact src, exact dest) - port ANY (0)
    let key_exact_port_any = IpPort {
        addr: source_ip_be,
        addr_dest: dest_ip_be,
        port: 0,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_exact_port_any) {
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (src, ANY dest) - port exact
    let key_src_anydest = IpPort {
        addr: source_ip_be,
        addr_dest: IP_ANY_BE,
        port: dest_port_be,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_src_anydest) {
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (src, ANY dest) - port ANY
    let key_src_anydest_port_any = IpPort {
        addr: source_ip_be,
        addr_dest: IP_ANY_BE,
        port: 0,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_src_anydest_port_any) {
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (ANY src, dest) - port exact
    let key_anysrc_dest = IpPort {
        addr: IP_ANY_BE,
        addr_dest: dest_ip_be,
        port: dest_port_be,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_anysrc_dest) {
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (ANY src, dest) - port ANY
    let key_anysrc_dest_port_any = IpPort {
        addr: IP_ANY_BE,
        addr_dest: dest_ip_be,
        port: 0,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_anysrc_dest_port_any) {
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (ANY src, ANY dest) - port exact
    let key_any_any = IpPort {
        addr: IP_ANY_BE,
        addr_dest: IP_ANY_BE,
        port: dest_port_be,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any) {
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (ANY src, ANY dest) - port ANY
    let key_any_any_port_any = IpPort {
        addr: IP_ANY_BE,
        addr_dest: IP_ANY_BE,
        port: 0,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any_port_any) {
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // ---------- Protocol = ANY checks (PROTO_ANY) ----------

    // (exact src, exact dest) - port exact - proto ANY
    let key_exact_anyproto = IpPort {
        addr: source_ip_be,
        addr_dest: dest_ip_be,
        port: dest_port_be,
        protocol: PROTO_ANY,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_exact_anyproto) {
        info!(&ctx, "MATCH (PROTO_ANY): {:i} -> {:i}", u32::from_be(key_exact_anyproto.addr), u32::from_be(key_exact_anyproto.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (exact src, exact dest) - port ANY - proto ANY
    let key_exact_anyproto_port_any = IpPort {
        addr: source_ip_be,
        addr_dest: dest_ip_be,
        port: 0,
        protocol: PROTO_ANY,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_exact_anyproto_port_any) {
        info!(&ctx, "MATCH (PROTO_ANY, port ANY): {:i} -> {:i}", u32::from_be(key_exact_anyproto_port_any.addr), u32::from_be(key_exact_anyproto_port_any.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (src, ANY dest) - port exact - proto ANY
    let key_src_anydest_anyproto = IpPort {
        addr: source_ip_be,
        addr_dest: IP_ANY_BE,
        port: dest_port_be,
        protocol: PROTO_ANY,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_src_anydest_anyproto) {
        info!(&ctx, "MATCH (PROTO_ANY, dest ANY): {:i} -> {:i}", u32::from_be(key_src_anydest_anyproto.addr), u32::from_be(key_src_anydest_anyproto.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (src, ANY dest) - port ANY - proto ANY
    let key_src_anydest_anyproto_port_any = IpPort {
        addr: source_ip_be,
        addr_dest: IP_ANY_BE,
        port: 0,
        protocol: PROTO_ANY,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_src_anydest_anyproto_port_any) {
        info!(&ctx, "MATCH (PROTO_ANY, dest ANY, port ANY): {:i} -> {:i}", u32::from_be(key_src_anydest_anyproto_port_any.addr), u32::from_be(key_src_anydest_anyproto_port_any.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (ANY src, dest) - port exact - proto ANY
    let key_anysrc_dest_anyproto = IpPort {
        addr: IP_ANY_BE,
        addr_dest: dest_ip_be,
        port: dest_port_be,
        protocol: PROTO_ANY,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_anysrc_dest_anyproto) {
        info!(&ctx, "MATCH (PROTO_ANY, src ANY): {:i} -> {:i}", u32::from_be(key_anysrc_dest_anyproto.addr), u32::from_be(key_anysrc_dest_anyproto.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (ANY src, dest) - port ANY - proto ANY
    let key_anysrc_dest_anyproto_port_any = IpPort {
        addr: IP_ANY_BE,
        addr_dest: dest_ip_be,
        port: 0,
        protocol: PROTO_ANY,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_anysrc_dest_anyproto_port_any) {
        info!(&ctx, "MATCH (PROTO_ANY, src ANY, port ANY): {:i} -> {:i}", u32::from_be(key_anysrc_dest_anyproto_port_any.addr), u32::from_be(key_anysrc_dest_anyproto_port_any.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (ANY src, ANY dest) - port exact - proto ANY
    let key_any_any_anyproto = IpPort {
        addr: IP_ANY_BE,
        addr_dest: IP_ANY_BE,
        port: dest_port_be,
        protocol: PROTO_ANY,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any_anyproto) {
        info!(&ctx, "MATCH (PROTO_ANY, src ANY, dest ANY): {:i} -> {:i}", u32::from_be(key_any_any_anyproto.addr), u32::from_be(key_any_any_anyproto.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }

    // (ANY src, ANY dest) - port ANY - proto ANY
    let key_any_any_anyproto_port_any = IpPort {
        addr: IP_ANY_BE,
        addr_dest: IP_ANY_BE,
        port: 0,
        protocol: PROTO_ANY,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any_anyproto_port_any) {
        info!(&ctx, "MATCH (PROTO_ANY, all ANY): {:i} -> {:i}", u32::from_be(key_any_any_anyproto_port_any.addr), u32::from_be(key_any_any_anyproto_port_any.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        });
    }
    // Si aucune règle ne correspond après toutes ces vérifications, on passe.
    Ok(xdp_action::XDP_PASS)
}