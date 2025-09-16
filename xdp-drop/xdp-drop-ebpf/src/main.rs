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

// NOUVEAU: Importer les structures partagées pour le pare-feu stateful
use xdp_drop_common::{ConnectionKey, ConnectionValue, IpPort, TcpState};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Map pour les règles stateless (votre BLOCKLIST existante)
#[map]
static BLOCKLIST: HashMap<IpPort, u32> = HashMap::<IpPort, u32>::with_max_entries(1024, 0);

// NOUVEAU: La map pour le suivi des connexions (la "conntrack table")
// Clé: 5-tuple (IP/ports source/dest, protocole)
// Valeur: État de la connexion (ex: SynSent, Established)
#[map]
static CONNTRAK_MAP: HashMap<ConnectionKey, ConnectionValue> =
    HashMap::<ConnectionKey, ConnectionValue>::with_max_entries(65536, 0);

// Constantes pour les actions, comme avant
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

// La fonction pour la BLOCKLIST reste utile pour les règles stateless prioritaires
#[inline(always)]
fn check_firewall_rule(key: &IpPort) -> Option<u32> {
    unsafe { BLOCKLIST.get(key).copied() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // 1. Parsage des en-têtes Ethernet et IP
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS); // On ne traite que l'IPv4
    }

    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_ip_be = unsafe { (*ipv4_hdr).src_addr };
    let dest_ip_be = unsafe { (*ipv4_hdr).dst_addr };
    let protocol = unsafe { (*ipv4_hdr).proto };

    // --- LOGIQUE STATELESS (PRIORITÉ 1) ---
    // On vérifie d'abord la blocklist. Ces règles priment sur la logique stateful.
    // NOTE: On utilise un port 0 pour matcher "n'importe quel port", ce qui est une
    // simplification. Vous pourriez rendre cela plus sophistiqué.
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

    // --- NOUVELLE LOGIQUE STATEFUL (pour TCP) ---
    // Pour l'instant, on se concentre sur TCP. On laisse passer les autres protocoles.
    if protocol != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parsage de l'en-tête TCP
    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4_hdr).ihl() } as usize * 4);
    let tcp_hdr: *const TcpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
    let src_port_be = unsafe { (*tcp_hdr).source };
    let dst_port_be = unsafe { (*tcp_hdr).dest };
    
    // Extraction des drapeaux TCP importants
    let is_syn = unsafe { (*tcp_hdr).syn() } == 1;
    let is_ack = unsafe { (*tcp_hdr).ack() } == 1;
    // let is_fin = unsafe { (*tcp_hdr).fin() } == 1;
    // let is_rst = unsafe { (*tcp_hdr).rst() } == 1;

    // NOUVEAU: Définir ce qui est "interne" vs "externe".
    // À ADAPTER à votre réseau. Ici, on prend l'exemple de 10.0.2.0/24.
    // Les IPs sont lues en big-endian (ordre réseau), donc on utilise des constantes
    // en big-endian pour la comparaison.
    let internal_network_prefix = u32::from_be(0x0A000200); // 10.0.2.0
    let internal_network_mask = u32::from_be(0xFFFFFF00); // Masque /24

    let is_from_internal = (source_ip_be & internal_network_mask) == internal_network_prefix;

    // ÉTAPE 2: Gérer une nouvelle connexion SORTANTE (paquet SYN pur)
    // Si le paquet vient de notre réseau interne, est un SYN et n'est pas un ACK,
    // c'est une nouvelle tentative de connexion vers l'extérieur.
    if is_syn && !is_ack && is_from_internal {
        info!(
            &ctx,
            "STATEFUL: New outgoing SYN from {:i}:{} to {:i}:{}",
            u32::from_be(source_ip_be),
            u16::from_be(src_port_be),
            u32::from_be(dest_ip_be),
            u16::from_be(dst_port_be)
        );

        // On construit la clé de connexion
        let conn_key = ConnectionKey {
            src_ip: source_ip_be,
            dst_ip: dest_ip_be,
            src_port: src_port_be,
            dst_port: dst_port_be,
            protocol: protocol as u8,
            _pad: [0; 3],
        };
        
        // On enregistre cette tentative dans notre map avec l'état "SynSent"
        let new_value = ConnectionValue {
            state: TcpState::SynSent as u32,
        };
        unsafe { CONNTRAK_MAP.insert(&conn_key, &new_value, 0).map_err(|_| ())? };

        // On laisse passer ce paquet pour qu'il puisse initier la connexion.
        return Ok(xdp_action::XDP_PASS);
    }
    
    // Action par défaut pour cette étape de développement :
    // - Bloquer le trafic entrant non sollicité pour la sécurité de base.
    // - Laisser passer le reste du trafic sortant pour ne pas bloquer les
    //   réponses des connexions que nous ne suivons pas encore.
    
    if !is_from_internal {
        info!(&ctx, "STATEFUL: Drop unsolicited incoming packet from {:i}", u32::from_be(source_ip_be));
        return Ok(xdp_action::XDP_DROP);
    }

    // On laisse passer les autres paquets sortants pour le moment.
    // Ceci sera affiné dans les étapes suivantes.
    Ok(xdp_action::XDP_PASS)
}