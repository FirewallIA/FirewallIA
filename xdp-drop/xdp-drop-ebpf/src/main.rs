// Fichier : xdp-drop-ebpf/src/main.rs

#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
// On importe les helpers conntrack depuis aya_ebpf::ct
use aya_ebpf::ct::{
    helpers::{xdp_ct_lookup, xdp_ct_insert_entry, xdp_ct_release},
    netlink::NfCtInfo,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
};

// On importe seulement la structure pour la blocklist
use xdp_drop_common::IpPort;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
static BLOCKLIST: HashMap<IpPort, u32> = HashMap::<IpPort, u32>::with_max_entries(1024, 0);

// Les constantes pour les actions de la blocklist
const ACTION_DENY_FROM_MAP: u32 = 1;
const ACTION_ALLOW_FROM_MAP: u32 = 2;

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

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // 1. Parsage des en-têtes
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }
    let l3_offset = EthHdr::LEN;

    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, l3_offset)? };
    let source_ip_be = unsafe { (*ipv4_hdr).src_addr };
    let dest_ip_be = unsafe { (*ipv4_hdr).dst_addr };
    let protocol = unsafe { (*ipv4_hdr).proto };
    let transport_offset = l3_offset + (unsafe { (*ipv4_hdr).ihl() } as usize * 4);

    // --- LOGIQUE STATELESS (PRIORITÉ 1) ---
    let stateless_key = IpPort { addr: source_ip_be, addr_dest: dest_ip_be, port: 0, _pad: 0 };
    if let Some(action) = unsafe { BLOCKLIST.get(&stateless_key) } {
        if *action == ACTION_DENY_FROM_MAP {
            return Ok(xdp_action::XDP_DROP);
        }
        if *action == ACTION_ALLOW_FROM_MAP {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // --- LOGIQUE STATEFUL (pour TCP et UDP) AVEC CONNSYS DU NOYAU ---
    if protocol != IpProto::Tcp && protocol != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    let source_ip = u32::from_be(source_ip_be);
    const INTERNAL_NETWORK_PREFIX: u32 = 0xC0A80100; // 192.168.1.0
    const INTERNAL_NETWORK_MASK:   u32 = 0xFFFFFF00; // /24
    let is_from_internal = (source_ip & INTERNAL_NETWORK_MASK) == INTERNAL_NETWORK_PREFIX;

    // ÉTAPE 1: Consulter le système de suivi de connexion du noyau
    let ct_lookup = match unsafe { xdp_ct_lookup(&ctx, l3_offset, transport_offset, 0) } {
        Some(ptr) => ptr,
        None => return Ok(xdp_action::XDP_PASS),
    };
    
    let ct_info = unsafe { (*ct_lookup).info };

    // ÉTAPE 2: Appliquer la politique
    let action;
    match ct_info {
        NfCtInfo::REPLY | NfCtInfo::ESTABLISHED => {
            // C'est du trafic légitime pour une connexion existante, on autorise.
            action = xdp_action::XDP_PASS;
        }
        NfCtInfo::NEW => {
            if is_from_internal {
                // Nouvelle connexion sortante : on dit au noyau de la suivre et on autorise.
                if unsafe { xdp_ct_insert_entry(ct_lookup, 0) } == 0 {
                    action = xdp_action::XDP_PASS;
                } else {
                    action = xdp_action::XDP_ABORTED;
                }
            } else {
                // Nouvelle connexion entrante non sollicitée : on bloque.
                action = xdp_action::XDP_DROP;
            }
        }
        _ => {
            // Par défaut, on bloque tout autre état.
            action = xdp_action::XDP_DROP;
        }
    }
    
    // ÉTAPE 3: Libérer la ressource conntrack (OBLIGATOIRE).
    unsafe { xdp_ct_release(ct_lookup) };

    Ok(action)
}