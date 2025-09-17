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
    let stateless_key = IpPort { addr: source_ip_be, addr_dest: dest_ip_be, port: 0, _pad: 0 };
    if let Some(action) = check_firewall_rule(&stateless_key) {
        if action == ACTION_DENY_FROM_MAP { return Ok(xdp_action::XDP_DROP); }
        if action == ACTION_ALLOW_FROM_MAP { return Ok(xdp_action::XDP_PASS); }
    }

    // --- LOGIQUE STATEFUL (pour TCP) ---
    if protocol != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4_hdr).ihl() } as usize * 4);
    let tcp_hdr: *const TcpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
    let src_port_be = unsafe { (*tcp_hdr).source };
    let dst_port_be = unsafe { (*tcp_hdr).dest };
    
    // NOUVEAU: extraire tous les drapeaux nécessaires
    let is_syn = unsafe { (*tcp_hdr).syn() } == 1;
    let is_ack = unsafe { (*tcp_hdr).ack() } == 1;
    let is_fin = unsafe { (*tcp_hdr).fin() } == 1;
    let is_rst = unsafe { (*tcp_hdr).rst() } == 1;

    let source_ip = u32::from_be(source_ip_be);
    let dest_ip   = u32::from_be(dest_ip_be);
    // Définition du réseau interne (à adapter)
    const INTERNAL_NETWORK_PREFIX: u32 = 0xC0A80100;
    const INTERNAL_NETWORK_MASK:   u32 = 0xFFFFFF00;
    let is_from_internal = (source_ip & INTERNAL_NETWORK_MASK) == INTERNAL_NETWORK_PREFIX;

   
    
    // Définition des clés de connexion (directe et inversée)
    let conn_key = ConnectionKey { src_ip: source_ip_be, dst_ip: dest_ip_be, src_port: src_port_be, dst_port: dst_port_be, protocol: protocol as u8, _pad: [0; 3] };
    let reverse_conn_key = ConnectionKey { src_ip: dest_ip_be, dst_ip: source_ip_be, src_port: dst_port_be, dst_port: src_port_be, protocol: protocol as u8, _pad: [0; 3] };

    // ÉTAPE 2: Gérer une nouvelle connexion SORTANTE (SYN)
    if is_syn && !is_ack && is_from_internal {
        let new_value = ConnectionValue { state: TcpState::SynSent as u32 };
        unsafe { CONNTRAK_MAP.insert(&conn_key, &new_value, 0).map_err(|_| ())? };
        return Ok(xdp_action::XDP_PASS);
    }
    
    // ÉTAPE 3: Gérer la réponse entrante (SYN-ACK)
    if is_syn && is_ack && !is_from_internal {
        if let Some(existing_conn) = unsafe { CONNTRAK_MAP.get_mut(&reverse_conn_key) } {
            if existing_conn.state == TcpState::SynSent as u32 {
                existing_conn.state = TcpState::Established as u32;
                return Ok(xdp_action::XDP_PASS);
            }
        }
    }
    
    //  ÉTAPE 4: Gérer le trafic d'une connexion établie et sa fermeture
    // On vérifie si le paquet (quelle que soit sa direction) correspond à une connexion connue.
    let lookup_key = if is_from_internal { &conn_key } else { &reverse_conn_key };
    if let Some(conn_value) = unsafe { CONNTRAK_MAP.get(lookup_key) } {
        // Si la connexion est dans l'état "Established", on autorise le paquet.
        if conn_value.state == TcpState::Established as u32 {
            // Si c'est un paquet de fin de connexion (FIN ou RST), on nettoie l'entrée.
            if is_fin || is_rst {
                info!(&ctx, "STATEFUL (4): Connection closing from {:i}", u32::from_be(source_ip_be));
                // Supprimer l'entrée de la map
                unsafe { let _ = CONNTRAK_MAP.remove(lookup_key); }
            }
            // Laisser passer le paquet de données (ACK) ou de fermeture (FIN/RST).
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // NOUVEAU - ÉTAPE 4 (fin): Actions par défaut renforcées
    // Si on arrive ici, c'est que le paquet TCP n'appartient à aucune phase de connexion valide.
    
    // Bloquer tout paquet ENTRANT qui n'a pas été validé par les règles ci-dessus.
    if !is_from_internal {
        // info!(&ctx, "STATEFUL (Default): Drop unsolicited incoming packet from {:i}", u32::from_be(source_ip_be));
        info!(&ctx, "DBG src_be=0x{:x} src_host=0x{:x} mask=0x{:x} pref=0x{:x}",
        source_ip_be, source_ip, INTERNAL_NETWORK_MASK, INTERNAL_NETWORK_PREFIX);

        return Ok(xdp_action::XDP_DROP);
    }
    
    // Bloquer tout paquet SORTANT qui n'est pas un SYN initial (et n'appartient pas
    // à une connexion établie). Cela prévient des comportements anormaux.
    if is_from_internal && !is_syn {
         info!(&ctx, "STATEFUL (Default): Drop unexpected outgoing packet from {:i}", u32::from_be(source_ip_be));
         return Ok(xdp_action::XDP_DROP);
    }

    // Cette ligne est une sécurité mais ne devrait pas être atteinte pour les paquets TCP.
    Ok(x        dp_action::XDP_PASS)
}