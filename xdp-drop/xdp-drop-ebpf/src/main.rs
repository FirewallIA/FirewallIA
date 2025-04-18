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

//#[map] // (1)
//static BLOCKLIST: HashMap<u32, u32> =
//    HashMap::<u32, u32>::with_max_entries(1024, 0);

// Hashmap pour ip et port 
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IpPort {
    pub addr: u32,
    pub addr_dest : u32,
    pub port: u16,
    pub _pad: u16,
}



#[map]
static BLOCKLIST: HashMap<IpPort, u32> = HashMap::<IpPort, u32>::with_max_entries(1024, 0);

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

// (2)
fn block_ip_port(ctx: &XdpContext, addr: u32, addr_dest : u32, port: u16) -> bool {
    let key = IpPort { addr, addr_dest, port, _pad: 0 };
    let is_blocked = unsafe { BLOCKLIST.get(&key).is_some() };

    let ip_be = addr.to_le_bytes(); // pour affichage plus clair
    let ip_dest_be = addr_dest.to_le_bytes(); // pour affichage plus clair
    let status = if is_blocked { "BLOCKED" } else { "ALLOWED" };

    info!(ctx, "Checking IP src : {}.{}.{}.{}, IP dest : {}.{}.{}.{} Port: {} Status : {}", ip_be[0], ip_be[1], ip_be[2], ip_be[3],ip_dest_be[0], ip_dest_be[1], ip_dest_be[2], ip_dest_be[3],  port, status);

    is_blocked
}


fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    
    let protocol = unsafe { (*ipv4hdr).proto };
    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4hdr).ihl() } as usize * 4);

    let source = unsafe { (*ipv4hdr).src_addr };
    let destination = unsafe { (*ipv4hdr).dst_addr };

    let source_port;
let dest_port;

    match protocol {
        IpProto::Tcp  => { // TCP
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            source_port = u16::from_be(unsafe { (*tcphdr).source });
            dest_port = u16::from_be(unsafe { (*tcphdr).dest });
        }
        IpProto::Udp => { // UDP
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            source_port = u16::from_be(unsafe { (*udphdr).source });
            dest_port = u16::from_be(unsafe { (*udphdr).dest });
        }
        _ => {
            source_port = 0;
            dest_port = 0;
        }
    }
 
    // (3)
    let action = if block_ip_port(&ctx, source, destination, dest_port) {
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
        "IP SRC: {:i}:{}, DST: {:i}:{}, ACTION: {}",
        u32::from_be(source),
        source_port,
        u32::from_be(destination),
        dest_port,
        action_str
    );

   

    Ok(action)
}