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

    // 4. Construct the key for the firewall map lookup
    let key = IpPort {
        addr: source_ip_be,    // Source IP (already network byte order)
        addr_dest: dest_ip_be, // Destination IP (already network byte order)
        port: dest_port_be,    // Destination Port (already network byte order)
        protocol: protocol as u8,
        _pad: 0,               // Padding
    };

    // 5. Logique du pare-feu en 2 temps
     if let Some(action) = check_firewall_rule(&key) {
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }
    
    // 5.2: (Spécifique, Any)
    key.addr_dest = IP_ANY_BE;
    if let Some(action) = check_firewall_rule(&key) {
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }
    
    // 5.3: (Any, Spécifique)
    key.addr = IP_ANY_BE;
    key.addr_dest = dest_ip_be; // Remettre l'IP de destination originale
    if let Some(action) = check_firewall_rule(&key) {
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // 5.4: (Any, Any)
    key.addr_dest = IP_ANY_BE;
    if let Some(action) = check_firewall_rule(&key) {
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // 6. Si aucune règle spécifique au protocole n'est trouvée,
    // on recommence la même séquence avec le protocole "ANY" (0).
    key.protocol = PROTO_ANY;
    key.addr = source_ip_be;      // Réinitialiser à l'IP source originale
    key.addr_dest = dest_ip_be; // Réinitialiser à l'IP dest originale
    
    // 6.1: (Spécifique, Spécifique) - Proto ANY
    if let Some(action) = check_firewall_rule(&key) {
        info!(&ctx, "MATCH (ANY Proto): {:i} -> {:i}", u32::from_be(key.addr), u32::from_be(key.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // 6.2: (Spécifique, Any) - Proto ANY
    key.addr_dest = IP_ANY_BE;
    if let Some(action) = check_firewall_rule(&key) {
        info!(&ctx, "MATCH (ANY Proto, ANY Dest): {:i} -> {:i}", u32::from_be(key.addr), u32::from_be(key.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // 6.3: (Any, Spécifique) - Proto ANY
    key.addr = IP_ANY_BE;
    key.addr_dest = dest_ip_be;
    if let Some(action) = check_firewall_rule(&key) {
        info!(&ctx, "MATCH (ANY Proto, ANY Source): {:i} -> {:i}", u32::from_be(key.addr), u32::from_be(key.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }
    
    // 6.4: (Any, Any) - Proto ANY
    key.addr_dest = IP_ANY_BE;
    if let Some(action) = check_firewall_rule(&key) {
        info!(&ctx, "MATCH (ANY Proto, ANY Source, ANY Dest): {:i} -> {:i}", u32::from_be(key.addr), u32::from_be(key.addr_dest));
        return Ok(if action == ACTION_DENY_FROM_MAP { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    // Si aucune règle ne correspond après toutes ces vérifications, on passe.
    Ok(xdp_action::XDP_PASS)
}