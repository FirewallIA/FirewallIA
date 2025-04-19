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

#[map] // (1)
static BLOCKLIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);

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
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}


fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}


// pub fn decimal_to_hex(ctx: &XdpContext, byte: u8) -> [u8; 2] {
//     let ascii_table: [u8; 16] = [
//         48, 49, 50, 51, 52, 53, 54, 55, 56, 57, // '0' à '9'
//         65, 66, 67, 68, 69, 70,               // 'A' à 'F'
//     ];


//     let low = byte % 16;
//     let high = byte / 16;
//     info!(
//         ctx,
//         "{} -> {}={}, {}={}",
//         byte,
//         high,
//         ascii_table[high as usize],
//         low,
//         ascii_table[low as usize], 
//     );

//     [ascii_table[high as usize], ascii_table[low as usize]]
// }

pub fn decimal_to_hex(ctx: &XdpContext, byte: u8) -> [u8; 2] {
    const HEX: [u8; 16] = *b"0123456789ABCDEF";

    let low = byte % 16;
    let high = byte / 16;
    info!(
        &ctx,
        "{} -> {}={}, {}={}",
        byte,
        high,
        HEX[high as usize],
        low,
        HEX[low as usize], 
    );

    [HEX[high as usize], HEX[low as usize]]
}



pub fn dump_mac_address(ctx: &XdpContext, _is_src: bool, mac: &[u8; 6]) {
    for (_, &byte) in mac.iter().enumerate() {
        let _hex_chars = decimal_to_hex(ctx, byte);

        // Affichage sans utiliser as char, directement les valeurs hexadécimales
        // info!(
        //     ctx,
        //     "Byte {}: {} => {}{}",
        //     i,
        //     byte,
        //     hex_chars[0],  // Affichage du premier caractère hexadécimal
        //     hex_chars[1]   // Affichage du second caractère hexadécimal
        // );
    }
}


fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    let src_mac: [u8; 6] = unsafe { (*ethhdr).src_addr };
    dump_mac_address(&ctx, true, &src_mac);
    let dst_mac: [u8; 6] = unsafe { (*ethhdr).dst_addr };
    dump_mac_address(&ctx, false, &dst_mac);

    // let src_mac_val = mac_to_u64(&src_mac);
    // let dst_mac_val = mac_to_u64(&dst_mac);
    

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    
    let protocol = unsafe { (*ipv4hdr).proto };
    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4hdr).ihl() } as usize * 4);

    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let src_port;
    let dst_port;

    match protocol {
        IpProto::Tcp  => { // TCP
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            src_port = u16::from_be(unsafe { (*tcphdr).source });
            dst_port = u16::from_be(unsafe { (*tcphdr).dest });
        }
        IpProto::Udp => { // UDP
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            src_port = u16::from_be(unsafe { (*udphdr).source });
            dst_port = u16::from_be(unsafe { (*udphdr).dest });
        }
        _ => {
            src_port = 0;
            dst_port = 0;
        }
    }

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
        "MAC SRC: X, IP SRC: {:i}:{} => MAC DST: X, DST: {:i}:{}, ACTION: {}",
        // "MAC SRC: {}, IP SRC: {:i}:{} => MAC DST: {}, DST: {:i}:{}, ACTION: {}",
        // src_mac_val,
        src_addr,
        src_port,
        // dst_mac_val,
        dst_addr,
        dst_port,
        action_str
    );
   

    Ok(action)
}