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
    // Using .get() directly is safe in eBPF.
    // The unsafe block is not strictly needed here for the get call itself,
    // but might be kept if BLOCKLIST access requires it in other contexts.
    // However, for clarity, let's assume HashMap::get is safe.
    unsafe {
        BLOCKLIST.get(&address).is_some()
    }
}

// REMOVED: decimal_to_hex function
// REMOVED: format_mac function

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let mut mac_str = [0u8; 17]; // "XX:XX:XX:XX:XX:XX"
    let mut j = 0;
    for (i, &byte) in mac.iter().enumerate() {
        let hex = decimal_to_hex(ctx, byte);
        mac_str[j] = hex[0];
        mac_str[j + 1] = hex[1];
        if i < 5 {
            mac_str[j + 2] = b':';
        }
        j += 3;
    }

    // Affichage des octets hexadécimaux sans utilisation de formatage complexe
    info!(
        &ctx,
        "MAC = {}{}:{}{}:{}{}:{}{}:{}{}:{}{}",
        mac[0] >> 4,
        mac[0] & 0x0F,
        mac[1] >> 4,
        mac[1] & 0x0F,
        mac[2] >> 4,
        mac[2] & 0x0F,
        mac[3] >> 4,
        mac[3] & 0x0F,
        mac[4] >> 4,
        mac[4] & 0x0F,
        mac[5] >> 4,
        mac[5] & 0x0F
    );
    // --- End Log MAC Addresses ---

    match ether_type {
        EtherType::Ipv4 => {} // Continue processing
        _ => return Ok(xdp_action::XDP_PASS), // Pass non-IPv4
    }

    // IP Header
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let protocol = unsafe { (*ipv4hdr).proto };
    // Calculate transport header offset using IHL (Internet Header Length)
    // IHL is the number of 32-bit words, so multiply by 4 for bytes.
    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4hdr).ihl() } as usize * 4);

    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    // Transport Header (TCP/UDP Ports)
    let (src_port, dst_port) = match protocol {
        IpProto::Tcp => {
            // Ensure TCP header is within bounds before accessing
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            // Ensure UDP header is within bounds before accessing
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
            )
        }
        _ => (0, 0), // No ports for other protocols like ICMP
    };

    // Firewall Logic
    let action = if block_ip(src_addr) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    // Log Decision
    // Avoid passing strings directly to info! if possible, use constants or simple types.
    // However, aya_log_ebpf might handle small static strings okay. Let's try.
    // If this causes issues, log the action code (1 or 2) instead.
    let action_str = if action == xdp_action::XDP_DROP {
        "DROP"
    } else {
        "PASS"
    };

    info!(
        &ctx,
        "IP SRC: {:i}:{} => DST: {:i}:{}, Proto: {}, Action: {}", // Added Proto
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        protocol as u8, // Log protocol number
        action_str
    );

    Ok(action)
}