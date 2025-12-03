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
    let source_ip_be = unsafe { (*ipv4_hdr).src_addr };
    let dest_ip_be = unsafe { (*ipv4_hdr).dst_addr };
    let protocol = unsafe { (*ipv4_hdr).proto };

    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4_hdr).ihl() } as usize * 4);

    // 3. Parse Transport Header & Extract Ports
    let (source_port_be, dest_port_be) = match protocol {
        IpProto::Tcp => unsafe { 
            let hdr = ptr_at::<TcpHdr>(&ctx, transport_offset)?;
            ((*hdr).source, (*hdr).dest)
        },
        IpProto::Udp => unsafe { 
            let hdr = ptr_at::<UdpHdr>(&ctx, transport_offset)?;
            ((*hdr).source, (*hdr).dest)
        },
        _ => (0, 0),
    };

    // --- LOGIQUE DE FILTRAGE ---

    // 1. (exact src, exact dest) - port exact
    let key_exact = IpPort {
        addr: source_ip_be,
        addr_dest: dest_ip_be,
        port: dest_port_be,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_exact) {
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // 2. (exact src, exact dest) - port ANY
    let key_exact_port_any = IpPort {
        addr: source_ip_be,
        addr_dest: dest_ip_be,
        port: 0,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_exact_port_any) {
        info!(&ctx, "MATCH IP exact / Port ANY");
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // 3. (src, ANY dest) - port exact
    let key_src_anydest = IpPort {
        addr: source_ip_be,
        addr_dest: IP_ANY_BE,
        port: dest_port_be,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_src_anydest) {
        info!(&ctx, "MATCH Src exact / Dest ANY / Port exact");
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // 4. (src, ANY dest) - port ANY
    let key_src_anydest_port_any = IpPort {
        addr: source_ip_be,
        addr_dest: IP_ANY_BE,
        port: 0,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_src_anydest_port_any) {
        info!(&ctx, "MATCH Src exact / Dest ANY / Port ANY");
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // 5. (ANY src, dest) - port exact
    let key_anysrc_dest = IpPort {
        addr: IP_ANY_BE,
        addr_dest: dest_ip_be,
        port: dest_port_be,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_anysrc_dest) {
        info!(&ctx, "MATCH Src ANY / Dest exact / Port exact");
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }
    
    // On regarde si le PORT SOURCE est autorisé dans la map (via une règle Any->Any Port X Allow)
    let key_check_source_port = IpPort {
        addr: IP_ANY_BE,
        addr_dest: IP_ANY_BE,
        port: source_port_be, // On utilise le port SOURCE
        protocol: protocol as u8,
        _pad: 0,
    };

    if let Some(action) = check_firewall_rule(&key_check_source_port) {
        // IMPORTANT : On n'accepte le retour QUE si l'action est ALLOW.
        // Si c'est DENY, on laisse couler vers les règles suivantes (ou on bloque direct).
        if action == ACTION_ALLOW_FROM_MAP {
             info!(&ctx, "✅ TRAFIC RETOUR AUTORISÉ (Port Source: {})", u16::from_be(source_port_be));
             return Ok(xdp_action::XDP_PASS);
        }
    }
    // =========================================================================


    // 6. (ANY src, dest) - port ANY
    let key_anysrc_dest_port_any = IpPort {
        addr: IP_ANY_BE,
        addr_dest: dest_ip_be,
        port: 0,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_anysrc_dest_port_any) {
        info!(&ctx, "MATCH Src ANY / Dest exact / Port ANY");
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // 7. (ANY src, ANY dest) - port exact
    let key_any_any = IpPort {
        addr: IP_ANY_BE,
        addr_dest: IP_ANY_BE,
        port: dest_port_be,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any) {
        info!(&ctx, "MATCH Global Port: Port {}", u16::from_be(dest_port_be));
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // 8. (ANY src, ANY dest) - port ANY (Proto exact)
    let key_any_any_port_any = IpPort {
        addr: IP_ANY_BE,
        addr_dest: IP_ANY_BE,
        port: 0,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any_port_any) {
        info!(&ctx, "MATCH BLOCK ALL (Proto exact)");
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // ---------- Protocol = ANY checks (PROTO_ANY) ----------
    
    // ... Tes autres checks PROTO_ANY ...

    // (ANY src, ANY dest) - port ANY - proto ANY
    // C'EST CETTE RÈGLE QUI BLOQUAIT TOUT (ID 20)
    let key_any_any_anyproto_port_any = IpPort {
        addr: IP_ANY_BE,
        addr_dest: IP_ANY_BE,
        port: 0,
        protocol: PROTO_ANY,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any_anyproto_port_any) {
        info!(&ctx, "MATCH (PROTO_ANY, all ANY) - BLOCK ALL");
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // Default PASS if no rule matched
    Ok(xdp_action::XDP_PASS)
}