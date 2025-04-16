#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]
#[derive(Clone, Copy)]
#[repr(C)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use std::net::Ipv4Addr;

use core::{mem, hash::{Hash, Hasher}};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// Struct clé IP + Port (Doit être `Pod + Eq + Hash`)

pub struct IpPortKey {
    pub ip: u32,
    pub port: u16,
}

// Implémenter Eq et Hash manuellement car pas de std
impl PartialEq for IpPortKey {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip && self.port == other.port
    }
}
impl Eq for IpPortKey {}
impl core::hash::Hash for IpPortKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip.hash(state);
        self.port.hash(state);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
static BLOCKLIST: HashMap<IpPortKey, u32> = HashMap::<IpPortKey, u32>::with_max_entries(1024, 0);

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

fn block_ip_port(ip: u32, port: u16) -> bool {
    let key = IpPortKey { ip, port };
    unsafe { BLOCKLIST.get(&key).is_some() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let destination = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto };
    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4hdr).ihl() } as usize * 4);

    let source_port;
    let dest_port;

    match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            source_port = u16::from_be(unsafe { (*tcphdr).source });
            dest_port = u16::from_be(unsafe { (*tcphdr).dest });
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            source_port = u16::from_be(unsafe { (*udphdr).source });
            dest_port = u16::from_be(unsafe { (*udphdr).dest });
        }
        _ => {
            source_port = 0;
            dest_port = 0;
        }
    }

    let action = if block_ip_port(source, source_port) {
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
        "SRC: {:i}:{}, DST: {:i}:{}, ACTION: {}",
        source,
        source_port,
        destination,
        dest_port,
        action_str
    );

    Ok(action)
}
