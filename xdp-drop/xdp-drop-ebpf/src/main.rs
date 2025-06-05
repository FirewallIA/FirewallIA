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

    let (source_port_be, dest_port_be, tcp_flags_byte) = match protocol {
        IpProto::Tcp => {
            let tcp_hdr: *const TcpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            let mut flags: u8 = 0;
            if unsafe { (*tcp_hdr).syn() } != 0 { flags |= TCP_FLAG_SYN; }
            if unsafe { (*tcp_hdr).ack() } != 0 { flags |= TCP_FLAG_ACK; }
            if unsafe { (*tcp_hdr).fin() } != 0 { flags |= TCP_FLAG_FIN; }
            if unsafe { (*tcp_hdr).rst() } != 0 { flags |= TCP_FLAG_RST; }
            (unsafe { (*tcp_hdr).source }, unsafe { (*tcp_hdr).dest }, flags)
        }
        IpProto::Udp => {
            let udp_hdr: *const UdpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            (unsafe { (*udp_hdr).source }, unsafe { (*udp_hdr).dest }, 0)
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let conn_key = ConnectionKey {
        src_ip: source_ip,
        src_port: source_port_be,
        dst_ip: dest_ip,
        dst_port: dest_port_be,
        protocol: protocol as u8,
        _pad1: 0, _pad2: 0,
    };
    let reverse_conn_key = ConnectionKey {
        src_ip: dest_ip,
        src_port: dest_port_be,
        dst_ip: source_ip,
        dst_port: source_port_be,
        protocol: protocol as u8,
        _pad1: 0, _pad2: 0,
    };

    if let Some(conn_val_ptr) = unsafe { CONN_TRACK_TABLE.get_ptr_mut(&conn_key) } {
        let mut current_state_val = unsafe { (*conn_val_ptr).clone() }; // current_state_val est défini ici
        current_state_val.last_seen_ns = current_time_ns;

        match current_state_val.state {
            ConnStateVariant::Tcp(ref mut tcp_s) => {
                if tcp_flags_byte & TCP_FLAG_RST != 0 {
                    unsafe { CONN_TRACK_TABLE.remove(&conn_key).map_err(|_| ())? };
                    info!(&ctx, "CTT: TCP RST (fwd), dropping & removing. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
                    return Ok(xdp_action::XDP_DROP);
                }
                if tcp_flags_byte & TCP_FLAG_FIN != 0 && *tcp_s == TcpState::Established {
                    *tcp_s = TcpState::FinWait1;
                    info!(&ctx, "CTT: TCP FIN (fwd) on established. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
                }
                else if *tcp_s == TcpState::SynReceived && (tcp_flags_byte & TCP_FLAG_ACK != 0) && !(tcp_flags_byte & TCP_FLAG_SYN != 0) {
                    *tcp_s = TcpState::Established;
                    info!(&ctx, "CTT: TCP ACK for SYN-ACK (fwd). ESTABLISHED. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
                }
            }
            ConnStateVariant::Udp(ref mut udp_s) => {
                 if *udp_s == UdpState::New { *udp_s = UdpState::Established; }
            }
        }
        // Utiliser current_state_val et passer par référence
        unsafe { CONN_TRACK_TABLE.insert(&conn_key, ¤t_state_val, 0).map_err(|_| ())? }; // CORRIGÉ ICI
        return Ok(xdp_action::XDP_PASS);

    } else if let Some(conn_val_ptr) = unsafe { CONN_TRACK_TABLE.get_ptr_mut(&reverse_conn_key) } {
        let mut current_state_val = unsafe { (*conn_val_ptr).clone() }; // current_state_val est défini ici
        current_state_val.last_seen_ns = current_time_ns;

        match current_state_val.state {
            ConnStateVariant::Tcp(ref mut tcp_s) => {
                if tcp_flags_byte & TCP_FLAG_RST != 0 {
                    unsafe { CONN_TRACK_TABLE.remove(&reverse_conn_key).map_err(|_| ())? };
                    info!(&ctx, "CTT: TCP RST (rev), dropping & removing. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
                    return Ok(xdp_action::XDP_DROP);
                }
                if *tcp_s == TcpState::SynSent && (tcp_flags_byte & (TCP_FLAG_SYN | TCP_FLAG_ACK) == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
                    *tcp_s = TcpState::SynReceived;
                    info!(&ctx, "CTT: TCP SYN-ACK for SYN (rev). SynReceived. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
                }
                else if tcp_flags_byte & TCP_FLAG_FIN != 0 && *tcp_s == TcpState::Established {
                    info!(&ctx, "CTT: TCP FIN (rev) on established. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
                }
            }
            ConnStateVariant::Udp(ref mut udp_s) => {
                if *udp_s == UdpState::New {
                    *udp_s = UdpState::Established;
                    info!(&ctx, "CTT: UDP Reply. Established. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
                }
            }
        }
        // Utiliser current_state_val et passer par référence
        unsafe { CONN_TRACK_TABLE.insert(&reverse_conn_key, ¤t_state_val, 0).map_err(|_| ())? }; // CORRIGÉ ICI
        return Ok(xdp_action::XDP_PASS);
    }

    let blocklist_key = IpPort {
        addr: source_ip,
        addr_dest: dest_ip,
        port: dest_port_be,
        _pad: 0,
    };

    let action_from_blocklist = unsafe { BLOCKLIST.get(&blocklist_key).copied() };

    match action_from_blocklist {
        Some(ACTION_DENY_FROM_MAP) => {
            info!(&ctx, "BLOCKLIST: DENY. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
            return Ok(xdp_action::XDP_DROP);
        }
        Some(ACTION_ALLOW_FROM_MAP) => {
            let new_conn_state_opt: Option<ConnStateVariant> = match protocol {
                IpProto::Tcp if (tcp_flags_byte & TCP_FLAG_SYN != 0) && !(tcp_flags_byte & TCP_FLAG_ACK != 0) => {
                    info!(&ctx, "BLOCKLIST: ALLOW new TCP SYN. Creating CTT entry. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
                    Some(ConnStateVariant::Tcp(TcpState::SynSent))
                }
                IpProto::Udp => {
                    info!(&ctx, "BLOCKLIST: ALLOW new UDP. Creating CTT entry. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
                    Some(ConnStateVariant::Udp(UdpState::New))
                }
                _ => {
                    info!(&ctx, "BLOCKLIST: ALLOW rule, but not valid init packet (e.g. TCP not SYN). Dropping. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
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
            info!(&ctx, "DEFAULT DROP (no CTT, no BLOCKLIST allow): {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
            return Ok(xdp_action::XDP_DROP);
        }
        _ => {
             info!(&ctx, "BLOCKLIST: Unknown action value. Dropping. {:i}:{} -> {:i}:{}", u32::from_be(source_ip), u16::from_be(source_port_be), u32::from_be(dest_ip), u16::from_be(dest_port_be));
            return Ok(xdp_action::XDP_DROP);
        }
    }
}