#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_ebpf_ct::{
    helpers::{xdp_ct_lookup, xdp_ct_insert_entry, xdp_ct_release},
    netlink::NfCtInfo,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
};

// Importer seulement la structure partagée pour le stateless
use xdp_drop_common::IpPort;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Map pour les règles stateless (BLOCKLIST) - INCHANGÉ
#[map]
static BLOCKLIST: HashMap<IpPort, u32> = HashMap::<IpPort, u32>::with_max_entries(1024, 0);

// SUPPRIMÉ : La map CONNTRAK_MAP n'est plus nécessaire !

// Constantes pour les actions - INCHANGÉ
const ACTION_DENY_FROM_MAP: u32 = 1;
const ACTION_ALLOW_FROM_MAP: u32 = 2;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// La fonction ptr_at reste utile - INCHANGÉ
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
    // 1. Parsage des en-têtes Ethernet et IP
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

    // --- LOGIQUE STATELESS (PRIORITÉ 1) --- INCHANGÉ
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
    
    // On ne gère que TCP et UDP pour le suivi de connexion
    if protocol != IpProto::Tcp && protocol != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    // Définition du réseau interne (à adapter) - INCHANGÉ
    let source_ip = u32::from_be(source_ip_be);
    const INTERNAL_NETWORK_PREFIX: u32 = 0xC0A80100; // 192.168.1.0
    const INTERNAL_NETWORK_MASK:   u32 = 0xFFFFFF00; // /24
    let is_from_internal = (source_ip & INTERNAL_NETWORK_MASK) == INTERNAL_NETWORK_PREFIX;

    // ÉTAPE 1: Consulter le système de suivi de connexion du noyau
    let ct_lookup = match unsafe { xdp_ct_lookup(&ctx, l3_offset, transport_offset, 0) } {
        Some(ptr) => ptr,
        None => {
            // Ne devrait pas arriver pour TCP/UDP, mais par sécurité on laisse passer.
            return Ok(xdp_action::XDP_PASS);
        }
    };
    
    let ct_info = unsafe { (*ct_lookup).info };

    // ÉTAPE 2: Appliquer la politique en fonction de l'état de la connexion
    let action;
    match ct_info {
        // Paquet entrant appartenant à une connexion déjà établie ou en réponse.
        // C'est ici que la magie opère : le noyau a déjà fait le "de-NAT" et
        // sait que ce paquet pour PUBLIC_IP est en fait pour 192.168.1.101.
        NfCtInfo::REPLY | NfCtInfo::ESTABLISHED => {
            info!(&ctx, "STATEFUL: Allowing established/reply packet.");
            action = xdp_action::XDP_PASS;
        }

        // Nouvelle connexion. On ne l'autorise QUE si elle vient de l'intérieur.
        NfCtInfo::NEW => {
            if is_from_internal {
                info!(&ctx, "STATEFUL: New outgoing connection from internal network. Tracking and allowing.");
                // On demande au noyau de commencer à suivre cette connexion.
                if unsafe { xdp_ct_insert_entry(ct_lookup, 0) } == 0 {
                    action = xdp_action::XDP_PASS;
                } else {
                    action = xdp_action::XDP_ABORTED;
                }
            } else {
                info!(&ctx, "STATEFUL: Denying new unsolicited incoming connection.");
                action = xdp_action::XDP_DROP;
            }
        }

        // Tous les autres états (UNTRACKED, etc.) sont bloqués par défaut.
        _ => {
            info!(&ctx, "STATEFUL: Denying packet with unhandled conntrack state.");
            action = xdp_action::XDP_DROP;
        }
    }
    
    // ÉTAPE 3: Libérer la référence au "conntrack entry". C'est OBLIGATOIRE.
    unsafe { xdp_ct_release(ct_lookup) };

    Ok(action)
}