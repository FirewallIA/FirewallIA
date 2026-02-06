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
use xdp_drop_common::{IpPort, PROTO_ANY}; // Import your shared struct
use aya_ebpf::maps::PerCpuArray;
use xdp_drop_common::{STAT_INBOUND, STAT_OUTBOUND, STAT_BLOCKED, STAT_TOTAL_TYPES};
use xdp_drop_common::PacketLog;
use aya_ebpf::maps::PerfEventArray;

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

#[map]
static TRAFFIC_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_TOTAL_TYPES, 0);


#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);
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


#[inline(always)]
fn log_event(ctx: &XdpContext, src: u32, dst: u32, p_src: u16, p_dst: u16, proto: u32, action: u32) {
    let log_entry = PacketLog {
        ipv4_src: src,
        ipv4_dst: dst,
        port_src: p_src,
        port_dst: p_dst,
        protocol: proto,
        action: action,
    };
    // On envoie l'événement au Userspace
    unsafe { EVENTS.output(ctx, &log_entry, 0) };
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
        // Optionnel : logger aussi les correspondances exactes si besoin, 
        // mais souvent on évite pour ne pas spammer si le trafic est légitime et dense.
        return Ok(verdict(action, source_ip_be, dest_ip_be));
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
        info!(&ctx, "MATCH RULE | Type: IP Exact/Port ANY | Action: {} | SRC: {:i} -> DST: {:i}", 
            action, source_ip_be, dest_ip_be);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
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
        info!(&ctx, "MATCH RULE | Type: Src Exact/Port Exact | Action: {} | SRC: {:i} -> DST: *:{}", 
            action, source_ip_be, u16::from_be(dest_port_be));
        return Ok(verdict(action, source_ip_be, dest_ip_be));
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
        info!(&ctx, "MATCH RULE | Type: Src Exact/Port ANY | Action: {} | SRC: {:i} -> DST: *:*", 
            action, source_ip_be);
       return Ok(verdict(action, source_ip_be, dest_ip_be));
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
        info!(&ctx, "MATCH RULE | Type: Dst Exact/Port Exact | Action: {} | SRC: * -> DST: {:i}:{}", 
            action, dest_ip_be, u16::from_be(dest_port_be));
        return Ok(verdict(action, source_ip_be, dest_ip_be));
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
        if action == ACTION_ALLOW_FROM_MAP {
             // LOG MODIFIÉ ICI
             log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
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
        info!(&ctx, "MATCH RULE | Type: Dst Exact/Port ANY | Action: {} | SRC: * -> DST: {:i}:*", 
            action, dest_ip_be);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
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
        info!(&ctx, "MATCH RULE | Type: Global Port | Action: {} | Port: {}", 
            action, u16::from_be(dest_port_be));
        return Ok(verdict(action, source_ip_be, dest_ip_be));
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
        info!(&ctx, "MATCH RULE | Type: Block All Proto | Action: {} | Proto: {}", 
            action, protocol as u8); 
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    // ---------- Protocol = ANY checks (PROTO_ANY) ----------

    // (ANY src, ANY dest) - port ANY - proto ANY
    let key_any_any_anyproto_port_any = IpPort {
        addr: IP_ANY_BE,
        addr_dest: IP_ANY_BE,
        port: 0,
        protocol: PROTO_ANY,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any_anyproto_port_any) {
        info!(&ctx, "MATCH RULE | Type: Default (All) | Action: {}", action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    // Default PASS if no rule matched
    let src_is_priv = is_private_ip(source_ip_be);
    let dst_is_priv = is_private_ip(dest_ip_be);
    if !src_is_priv && dst_is_priv { increment_stat(STAT_INBOUND); }
    else if src_is_priv && !dst_is_priv { increment_stat(STAT_OUTBOUND); }
    
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn is_private_ip(ip: u32) -> bool {
    // 10.0.0.0/8     -> 0x0A...
    // 172.16.0.0/12  -> 0xAC10... - 0xAC1F...
    // 192.168.0.0/16 -> 0xC0A8...
    
    let ip_host = u32::from_be(ip);

    if (ip_host & 0xFF000000) == 0x0A000000 { return true; } // 10.x.x.x
    if (ip_host & 0xFFF00000) == 0xAC100000 { return true; } // 172.16.x.x - 172.31.x.x
    if (ip_host & 0xFFFF0000) == 0xC0A80000 { return true; } // 192.168.x.x
    
    false
}

#[inline(always)]
fn increment_stat(index: u32) {
    if let Some(ptr) = TRAFFIC_STATS.get_ptr_mut(index) {
        unsafe { *ptr += 1 };
    }
}

#[inline(always)]
fn verdict(action: u32, src_ip: u32, dst_ip: u32) -> u32 {
    if action == ACTION_DENY_FROM_MAP {
        increment_stat(STAT_BLOCKED);
        return xdp_action::XDP_DROP;
    } 
    
    // Si autorisé, on classifie le trafic
    let src_is_priv = is_private_ip(src_ip);
    let dst_is_priv = is_private_ip(dst_ip);

    // Public (Internet) -> Privé (Moi) = INBOUND
    if !src_is_priv && dst_is_priv {
        increment_stat(STAT_INBOUND);
    } 
    // Privé (Moi) -> Public (Internet) = OUTBOUND
    else if src_is_priv && !dst_is_priv {
        increment_stat(STAT_OUTBOUND);
    }
    
    xdp_action::XDP_PASS
}