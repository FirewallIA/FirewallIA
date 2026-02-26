#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)] 

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
    maps::PerfEventArray,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use xdp_drop_common::{IpPort, PROTO_ANY}; 
use aya_ebpf::maps::PerCpuArray;
use xdp_drop_common::{STAT_INBOUND, STAT_OUTBOUND, STAT_BLOCKED, STAT_TOTAL_TYPES};
use xdp_drop_common::PacketLog;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
static BLOCKLIST: HashMap<IpPort, u32> = HashMap::<IpPort, u32>::with_max_entries(1024, 0);

#[map]
static TRAFFIC_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_TOTAL_TYPES, 0);

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

const ACTION_DENY_FROM_MAP: u32 = 1;
const ACTION_ALLOW_FROM_MAP: u32 = 2;
const IP_ANY_BE : u32 = 0;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// Fonction helper pour envoyer les logs détaillés
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
    unsafe { EVENTS.output(ctx, &log_entry, 0) };
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

#[inline(always)]
fn check_firewall_rule(key: &IpPort) -> Option<u32> {
    unsafe { BLOCKLIST.get(key).copied() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // 1. Parsing Headers
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_ip_be = unsafe { (*ipv4_hdr).src_addr };
    let dest_ip_be = unsafe { (*ipv4_hdr).dst_addr };
    let protocol = unsafe { (*ipv4_hdr).proto };

    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4_hdr).ihl() } as usize * 4);

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
    // J'ai remplacé TOUS les info! par log_event pour que vous voyiez tout dans le gRPC.

    // 1. (exact src, exact dest) - port exact
    let key_exact = IpPort {
        addr: source_ip_be, addr_dest: dest_ip_be, port: dest_port_be, protocol: protocol as u8, _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_exact) {
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    // 2. (exact src, exact dest) - port ANY
    let key_exact_port_any = IpPort {
        addr: source_ip_be, addr_dest: dest_ip_be, port: 0, protocol: protocol as u8, _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_exact_port_any) {
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    // 3. (src, ANY dest) - port exact
    let key_src_anydest = IpPort {
        addr: source_ip_be, addr_dest: IP_ANY_BE, port: dest_port_be, protocol: protocol as u8, _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_src_anydest) {
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    // 4. (src, ANY dest) - port ANY
    let key_src_anydest_port_any = IpPort {
        addr: source_ip_be, addr_dest: IP_ANY_BE, port: 0, protocol: protocol as u8, _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_src_anydest_port_any) {
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
       return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    // 5. (ANY src, dest) - port exact
    let key_anysrc_dest = IpPort {
        addr: IP_ANY_BE, addr_dest: dest_ip_be, port: dest_port_be, protocol: protocol as u8, _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_anysrc_dest) {
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }
    
    // TRAFIC RETOUR (Port Source)
    let key_check_source_port = IpPort {
        addr: IP_ANY_BE, addr_dest: IP_ANY_BE, port: source_port_be, protocol: protocol as u8, _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_check_source_port) {
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    let key_check_source_port_any = IpPort {
        addr: IP_ANY_BE, 
        addr_dest: IP_ANY_BE, 
        port: source_port_be, 
        protocol: PROTO_ANY, // <--- On vérifie si une règle ANY autorise ce port source
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_check_source_port_any) {
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    // 6. (ANY src, dest) - port ANY
    let key_anysrc_dest_port_any = IpPort {
        addr: IP_ANY_BE, addr_dest: dest_ip_be, port: 0, protocol: protocol as u8, _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_anysrc_dest_port_any) {
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    // 7. (ANY src, ANY dest) - port exact
    let key_any_any = IpPort {
        addr: IP_ANY_BE, addr_dest: IP_ANY_BE, port: dest_port_be, protocol: protocol as u8, _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any) {
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    let key_any_any_proto_any = IpPort {
        addr: IP_ANY_BE, 
        addr_dest: IP_ANY_BE, 
        port: dest_port_be, 
        protocol: PROTO_ANY, // On force la recherche sur le proto 0
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any_proto_any) {
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }


    // 8. (ANY src, ANY dest) - port ANY (Proto exact)
    let key_any_any_port_any = IpPort {
        addr: IP_ANY_BE, addr_dest: IP_ANY_BE, port: 0, protocol: protocol as u8, _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any_port_any) {
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    // ---------- Protocol = ANY checks (PROTO_ANY) ----------

    // (ANY src, ANY dest) - port ANY - proto ANY
    // C'EST ICI QUE SE JOUE VOTRE RÈGLE "BLOCK ALL"
    let key_any_any_anyproto_port_any = IpPort {
        addr: IP_ANY_BE,
        addr_dest: IP_ANY_BE,
        port: 0,
        protocol: PROTO_ANY,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&key_any_any_anyproto_port_any) {
        // CORRECTION : Plus de info!(), on envoie les vraies IPs au userspace
        log_event(&ctx, source_ip_be, dest_ip_be, u16::from_be(source_port_be), u16::from_be(dest_port_be), protocol as u32, action);
        return Ok(verdict(action, source_ip_be, dest_ip_be));
    }

    // Default PASS (Compteur Stats uniquement, pas de log pour éviter le spam si pas de règle)
    let src_is_priv = is_private_ip(source_ip_be);
    let dst_is_priv = is_private_ip(dest_ip_be);
    if !src_is_priv && dst_is_priv { increment_stat(STAT_INBOUND); }
    else if src_is_priv && !dst_is_priv { increment_stat(STAT_OUTBOUND); }
    
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn is_private_ip(ip: u32) -> bool {
    let ip_host = u32::from_be(ip);
    if (ip_host & 0xFF000000) == 0x0A000000 { return true; } 
    if (ip_host & 0xFFF00000) == 0xAC100000 { return true; } 
    if (ip_host & 0xFFFF0000) == 0xC0A80000 { return true; } 
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
    
    let src_is_priv = is_private_ip(src_ip);
    let dst_is_priv = is_private_ip(dst_ip);

    if !src_is_priv && dst_is_priv {
        increment_stat(STAT_INBOUND);
    } 
    else if src_is_priv && !dst_is_priv {
        increment_stat(STAT_OUTBOUND);
    }
    
    xdp_action::XDP_PASS
}