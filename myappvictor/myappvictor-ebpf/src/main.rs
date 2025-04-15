#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;

#[xdp]
pub fn xdp_hello(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_hello(&ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_xdp_hello(ctx: &XdpContext) -> Result<u32, u32> {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    // Check bounds for Ethernet header (14 bytes)
    if data.add(14) > data_end {
        return Err(1);
    }

    // Get ethertype (bytes 12-13)
    let eth_proto_ptr = data.add(12) as *const u16;
    if eth_proto_ptr.add(1) as *const u8 > data_end {
        return Err(1);
    }
    let eth_proto = u16::from_be(*eth_proto_ptr);

    if eth_proto == 0x0800 {
        // IPv4: check bounds for IP header protocol (byte 23)
        if data.add(23 + 1) > data_end {
            return Err(1);
        }
        let ip_proto = *data.add(23);

        match ip_proto {
            1 => info!(ctx, "IPv4: ICMP packet"),
            6 => info!(ctx, "IPv4: TCP packet"),
            17 => info!(ctx, "IPv4: UDP packet"),
            _ => info!(ctx, "IPv4: other protocol {}", ip_proto),
        }
    } else {
        info!(ctx, "Non-IPv4 packet, ethertype: {}", eth_proto);
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
