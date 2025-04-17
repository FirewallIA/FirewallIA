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

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    ip::IpProto,
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ... (imports et setup inchangés)

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

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

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

pub fn decimal_to_hex(ctx: &XdpContext, byte: u8) -> [u8; 2] {
    const HEX: [u8; 16] = *b"0123456789ABCDEF";

    let low = byte % 16;
    let high = byte / 16;
    info!(
        ctx,
        "{} -> {}={}, {}={}",
        byte,
        high,
        HEX[high as usize],
        low,
        HEX[low as usize],
    );

    [HEX[high as usize], HEX[low as usize]]
}

// ✅ NOUVELLE FONCTION pour formater et afficher l'adresse MAC
pub fn format_mac(ctx: &XdpContext, mac: &[u8; 6]) {
    let mut out = [0u8; 17]; // "XX:XX:XX:XX:XX:XX"
    let mut j = 0;
    for (i, &byte) in mac.iter().enumerate() {
        let hex = decimal_to_hex(ctx, byte);
        out[j] = hex[0];
        out[j + 1] = hex[1];
        if i < 5 {
            out[j + 2] = b':';
        }
        j += 3;
    }

    // Solution simple : log le tableau complet en tant que &[u8; 17]
    info!(ctx, "MAC = {:?}", out);
    info!(ctx, "SRC MAC RAW: {:?}", mac);
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    let src_mac: [u8; 6] = unsafe { (*ethhdr).src_addr };
    let dst_mac: [u8; 6] = unsafe { (*ethhdr).dst_addr };

    // ✅ Utilisation de la nouvelle fonction
    format_mac(&ctx, &src_mac);
    format_mac(&ctx, &dst_mac);

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

    let protocol = unsafe { (*ipv4hdr).proto };
    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4hdr).ihl() } as usize * 4);

    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let (src_port, dst_port) = match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
            )
        }
        _ => (0, 0),
    };

    let action = if block_ip(src_addr) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    let action_str = match action {
        1 => "Block",
        2 => "Pass",
        _ => "Unknown",
    };

    info!(
        &ctx,
        "IP SRC: {:i}:{} => DST: {:i}:{}, ACTION: {}",
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        action_str
    );

    Ok(action)
}
