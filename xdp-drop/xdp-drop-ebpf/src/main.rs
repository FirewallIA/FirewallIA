// Dans xdp-drop-ebpf/src/main.rs

#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code, unused_imports)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
    helpers::bpf_ktime_get_ns,
};
use aya_log_ebpf::info;

// MODIFIÉ: Importation des constantes de flags TCP
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::{self, TcpHdr}, // Importer le module tcp et TcpHdr
    udp::UdpHdr,
};

// Vos structures partagées
use xdp_drop_common::{IpPort, ConnectionKey, ConnectionValue, TcpState, UdpState, ConnStateVariant};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
static BLOCKLIST: HashMap<IpPort, u32> = HashMap::<IpPort, u32>::with_max_entries(1024, 0);

#[map]
static CONN_TRACK_TABLE: HashMap<ConnectionKey, ConnectionValue> =
    HashMap::<ConnectionKey, ConnectionValue>::with_max_entries(10240, 0);

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
    if start + offset + len > end { Err(()) } else { Ok((start + offset) as *const T) }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let current_time_ns = unsafe { bpf_ktime_get_ns() };

    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_ip = unsafe { (*ipv4_hdr).src_addr };
    let dest_ip = unsafe { (*ipv4_hdr).dst_addr };
    let protocol = unsafe { (*ipv4_hdr).proto };
    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4_hdr).ihl() } as usize * 4);

    // CORRIGÉ: Accès aux flags TCP
    let (source_port, dest_port, tcp_flags_byte) = match protocol {
        IpProto::Tcp => {
            let tcp_hdr: *const TcpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            // network-types::TcpHdr a un champ `_bitflags` (privé par convention, mais accessible en unsafe)
            // ou des méthodes individuelles. Pour obtenir le byte de flags, on accède au champ.
            // Ce champ est souvent le 13ème byte (offset 12) du header TCP (après les ports, seq, ack).
            // La structure TcpHdr de network-types (0.0.7) stocke les flags dans un champ interne.
            // Le plus simple est d'utiliser les méthodes booléennes pour reconstruire le byte si besoin,
            // ou si vous avez accès à la valeur brute (par exemple, `(*tcp_hdr).flags_raw()` si elle existe).
            // Pour l'instant, construisons-le à partir des méthodes individuelles si besoin.
            // TcpHdr de network_types a un champ 'inner' qui contient les champs bruts.
            // On peut aussi utiliser les méthodes .syn(), .ack(), etc.
            // Pour cet exemple, nous allons supposer que nous avons besoin du byte de flags.
            // `(*tcp_hdr).flags()` n'existe pas. On va utiliser les constantes importées
            // et les méthodes `tcp_hdr.syn()`, `tcp_hdr.ack()` etc.

            let mut flags: u8 = 0;
            if unsafe { (*tcp_hdr).syn() } { flags |= tcp::SYN_FLAG; } // Utiliser les constantes du module tcp
            if unsafe { (*tcp_hdr).ack() } { flags |= tcp::ACK_FLAG; }
            if unsafe { (*tcp_hdr).fin() } { flags |= tcp::FIN_FLAG; }
            if unsafe { (*tcp_hdr).rst() } { flags |= tcp::RST_FLAG; }
            // Ajoutez PSH, URG si nécessaire
            (unsafe { (*tcp_hdr).source() }, unsafe { (*tcp_hdr).dest() }, flags)
        }
        IpProto::Udp => {
            let udp_hdr: *const UdpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            (unsafe { (*udp_hdr).source() }, unsafe { (*udp_hdr).dest() }, 0)
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let conn_key = ConnectionKey {
        src_ip: source_ip,
        src_port: source_port,
        dst_ip: dest_ip,
        dst_port: dest_port,
        protocol: protocol as u8,
        _pad1: 0, _pad2: 0,
    };
    let reverse_conn_key = ConnectionKey {
        src_ip: dest_ip,
        src_port: dest_port,
        dst_ip: source_ip,
        dst_port: source_port,
        protocol: protocol as u8,
        _pad1: 0, _pad2: 0,
    };

    if let Some(conn_val_ptr) = unsafe { CONN_TRACK_TABLE.get_ptr_mut(&conn_key) } {
        let mut current_state_val = unsafe { (*conn_val_ptr).clone() };
        current_state_val.last_seen_ns = current_time_ns;

        match current_state_val.state {
            ConnStateVariant::Tcp(ref mut tcp_s) => {
                // Utiliser les constantes de flags du module tcp
                if tcp_flags_byte & tcp::RST_FLAG != 0 { // CORRIGÉ
                    unsafe { CONN_TRACK_TABLE.remove(&conn_key).map_err(|_| ())? };
                    info!(&ctx, "CTT: TCP RST (fwd), dropping & removing. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
                    return Ok(xdp_action::XDP_DROP);
                }
                if tcp_flags_byte & tcp::FIN_FLAG != 0 && *tcp_s == TcpState::Established { // CORRIGÉ
                    *tcp_s = TcpState::FinWait1;
                    info!(&ctx, "CTT: TCP FIN (fwd) on established. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
                }
                else if *tcp_s == TcpState::SynReceived && (tcp_flags_byte & tcp::ACK_FLAG != 0) && !(tcp_flags_byte & tcp::SYN_FLAG != 0) { // CORRIGÉ
                    *tcp_s = TcpState::Established;
                    info!(&ctx, "CTT: TCP ACK for SYN-ACK (fwd). ESTABLISHED. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
                }
            }
            ConnStateVariant::Udp(ref mut udp_s) => {
                 if *udp_s == UdpState::New { *udp_s = UdpState::Established; }
            }
        }
        // CORRIGÉ: Remplacer ¤t_state_val par current_state_val
        unsafe { CONN_TRACK_TABLE.insert(&conn_key, ¤t_state_val, 0).map_err(|_| ())? };
        return Ok(xdp_action::XDP_PASS);

    } else if let Some(conn_val_ptr) = unsafe { CONN_TRACK_TABLE.get_ptr_mut(&reverse_conn_key) } {
        let mut current_state_val = unsafe { (*conn_val_ptr).clone() };
        current_state_val.last_seen_ns = current_time_ns;

        match current_state_val.state {
            ConnStateVariant::Tcp(ref mut tcp_s) => {
                // Utiliser les constantes de flags du module tcp
                if tcp_flags_byte & tcp::RST_FLAG != 0 { // CORRIGÉ
                    unsafe { CONN_TRACK_TABLE.remove(&reverse_conn_key).map_err(|_| ())? };
                    info!(&ctx, "CTT: TCP RST (rev), dropping & removing. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
                    return Ok(xdp_action::XDP_DROP);
                }
                if *tcp_s == TcpState::SynSent && (tcp_flags_byte & (tcp::SYN_FLAG | tcp::ACK_FLAG) == (tcp::SYN_FLAG | tcp::ACK_FLAG)) { // CORRIGÉ
                    *tcp_s = TcpState::SynReceived;
                    info!(&ctx, "CTT: TCP SYN-ACK for SYN (rev). SynReceived. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
                }
                else if tcp_flags_byte & tcp::FIN_FLAG != 0 && *tcp_s == TcpState::Established { // CORRIGÉ
                    info!(&ctx, "CTT: TCP FIN (rev) on established. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
                }
            }
            ConnStateVariant::Udp(ref mut udp_s) => {
                if *udp_s == UdpState::New {
                    *udp_s = UdpState::Established;
                    info!(&ctx, "CTT: UDP Reply. Established. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
                }
            }
        }
        // CORRIGÉ: Remplacer ¤t_state_val par current_state_val
        unsafe { CONN_TRACK_TABLE.insert(&reverse_conn_key, ¤t_state_val, 0).map_err(|_| ())? };
        return Ok(xdp_action::XDP_PASS);
    }

    let blocklist_key = IpPort {
        addr: source_ip,
        addr_dest: dest_ip,
        port: dest_port,
        _pad: 0,
    };

    let action_from_blocklist = unsafe { BLOCKLIST.get(&blocklist_key).copied() };

    match action_from_blocklist {
        Some(ACTION_DENY_FROM_MAP) => {
            info!(&ctx, "BLOCKLIST: DENY. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
            return Ok(xdp_action::XDP_DROP);
        }
        Some(ACTION_ALLOW_FROM_MAP) => {
            let new_conn_state_opt: Option<ConnStateVariant> = match protocol {
                // Utiliser les constantes de flags du module tcp
                IpProto::Tcp if (tcp_flags_byte & tcp::SYN_FLAG != 0) && !(tcp_flags_byte & tcp::ACK_FLAG != 0) => { // CORRIGÉ
                    info!(&ctx, "BLOCKLIST: ALLOW new TCP SYN. Creating CTT entry. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
                    Some(ConnStateVariant::Tcp(TcpState::SynSent))
                }
                IpProto::Udp => {
                    info!(&ctx, "BLOCKLIST: ALLOW new UDP. Creating CTT entry. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
                    Some(ConnStateVariant::Udp(UdpState::New))
                }
                _ => {
                    info!(&ctx, "BLOCKLIST: ALLOW rule, but not valid init packet (e.g. TCP not SYN). Dropping. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
                    None
                }
            };

            if let Some(new_state) = new_conn_state_opt {
                let new_conn_val = ConnectionValue {
                    state: new_state,
                    last_seen_ns: current_time_ns,
                };
                unsafe { CONN_TRACK_TABLE.insert(&conn_key, &new_conn_val, 0).map_err(|_| ())? };
                return Ok(xdp_action::XDP_PASS);
            } else {
                return Ok(xdp_action::XDP_DROP);
            }
        }
        None => {
            info!(&ctx, "DEFAULT DROP (no CTT, no BLOCKLIST allow): {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
            return Ok(xdp_action::XDP_DROP);
        }
        _ => {
             info!(&ctx, "BLOCKLIST: Unknown action value. Dropping. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port), u32::from_be(dest_ip), u16::from_be(dest_port));
            return Ok(xdp_action::XDP_DROP);
        }
    }
}