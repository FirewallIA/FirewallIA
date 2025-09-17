
#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// Importer les structures partagées pour le pare-feu stateful
use xdp_drop_common::{ConnectionKey, ConnectionValue, IpPort, TcpState};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Map pour les règles stateless (BLOCKLIST)
#[map]
static BLOCKLIST: HashMap<IpPort, u32> = HashMap::<IpPort, u32>::with_max_entries(1024, 0);

// Map pour le suivi des connexions (la "conntrack table")
#[map]
static CONNTRAK_MAP: HashMap<ConnectionKey, ConnectionValue> =
    HashMap::<ConnectionKey, ConnectionValue>::with_max_entries(65536, 0);

// Constantes pour les actions
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

#[inline(always)]
fn check_firewall_rule(key: &IpPort) -> Option<u32> {
    unsafe { BLOCKLIST.get(key).copied() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // 1. Parsage des en-têtes Ethernet et IP
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_ip_be = unsafe { (*ipv4_hdr).src_addr };
    let dest_ip_be = unsafe { (*ipv4_hdr).dst_addr };
    let protocol = unsafe { (*ipv4_hdr).proto };

    // --- LOGIQUE STATELESS (PRIORITÉ 1) ---
    let stateless_key = IpPort {
        addr: source_ip_be,
        addr_dest: dest_ip_be,
        port: 0,
        _pad: 0,
    };
    if let Some(action) = check_firewall_rule(&stateless_key) {
        if action == ACTION_DENY_FROM_MAP {
            info!(&ctx, "BLOCKLIST: Deny S_IP={:i}", u32::from_be(source_ip_be));
            return Ok(xdp_action::XDP_DROP);
        }
        if action == ACTION_ALLOW_FROM_MAP {
            info!(&ctx, "BLOCKLIST: Allow S_IP={:i}", u32::from_be(source_ip_be));
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // --- LOGIQUE STATEFUL (pour TCP) ---
    if protocol != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4_hdr).ihl() } as usize * 4);
    let tcp_hdr: *const TcpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
    let src_port_be = unsafe { (*tcp_hdr).source };
    let dst_port_be = unsafe { (*tcp_hdr).dest };
    
    let is_syn = unsafe { (*tcp_hdr).syn() } == 1;
    let is_ack = unsafe { (*tcp_hdr).ack() } == 1;

    // Définition du réseau interne (à adapter)
    let internal_network_prefix = u32::from_be(0xC0A80100); // 192.168.1.0
    let internal_network_mask = u32::from_be(0xFFFFFF00); // Masque /24
    let is_from_internal = (source_ip_be & internal_network_mask) == internal_network_prefix;

    // NOUVEAU: Préparer la clé de connexion inversée.
    // Elle est nécessaire pour rechercher dans la map les paquets de réponse (entrants).
    // La connexion originale (sortante) a été enregistrée avec (src=interne, dst=externe).
    // La réponse (entrante) aura (src=externe, dst=interne). Il faut donc inverser la clé pour la trouver.
    let reverse_conn_key = ConnectionKey {
        src_ip: dest_ip_be,
        dst_ip: source_ip_be,
        src_port: dst_port_be,
        dst_port: src_port_be,
        protocol: protocol as u8,
        _pad: [0; 3],
    };

    // ÉTAPE 2: Gérer une nouvelle connexion SORTANTE (SYN)
    if is_syn && !is_ack && is_from_internal {
        info!(&ctx, "STATEFUL (2): New outgoing SYN from {:i}:{}", u32::from_be(source_ip_be), u16::from_be(src_port_be));
        let conn_key = ConnectionKey {
            src_ip: source_ip_be,
            dst_ip: dest_ip_be,
            src_port: src_port_be,
            dst_port: dst_port_be,
            protocol: protocol as u8,
            _pad: [0; 3],
        };
        let new_value = ConnectionValue { state: TcpState::SynSent as u32 };
        unsafe { CONNTRAK_MAP.insert(&conn_key, &new_value, 0).map_err(|_| ())? };
        return Ok(xdp_action::XDP_PASS);
    }
    
    // NOUVEAU - ÉTAPE 3: Gérer la réponse entrante (SYN-ACK)
    // Si le paquet vient de l'extérieur, est un SYN et un ACK,
    // c'est la réponse à notre SYN initial.
    if is_syn && is_ack && !is_from_internal {
        // On cherche dans la map en utilisant la clé inversée.
        // On utilise `get_mut` car on veut modifier l'état de la connexion.
        if let Some(existing_conn) = unsafe { CONNTRAK_MAP.get_mut(&reverse_conn_key) } {
            // On vérifie que la connexion était bien en attente d'un SYN-ACK.
            if existing_conn.state == TcpState::SynSent as u32 {
                info!(&ctx, "STATEFUL (3): Matched incoming SYN-ACK. Establishing connection from {:i}:{}", u32::from_be(source_ip_be), u16::from_be(src_port_be));
                // La poignée de main est valide, on met à jour l'état à "Established".
                existing_conn.state = TcpState::Established as u32;
                // On laisse passer le paquet pour que le client local le reçoive.
                return Ok(xdp_action::XDP_PASS);
            }
        }
        // Si on ne trouve pas de correspondance ou si l'état n'est pas SynSent,
        // le paquet sera bloqué par la règle par défaut plus bas.
    }
    
    // Action par défaut pour cette étape
    if !is_from_internal {
        info!(&ctx, "STATEFUL (Default): Drop unsolicited incoming packet from {:i}", u32::from_be(source_ip_be));
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}