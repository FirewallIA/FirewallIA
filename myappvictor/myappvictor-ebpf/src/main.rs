#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;

#[xdp]
pub fn xdp_hello(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_hello(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_xdp_hello(ctx: XdpContext) -> Result<u32, u32> {
    // On récupère les données du paquet
    let data = ctx.data();
    let data_end = ctx.data_end();
    let len = data_end.offset_from(data);

    // Vérifie qu'on a assez de données pour un header Ethernet + IP (approximatif)
    if len < 34 {
        return Err(1);
    }

    // Interprète la mémoire comme un header Ethernet (14 octets)
    let eth_proto_ptr = data.add(12) as *const u16;
    let eth_proto = u16::from_be(*eth_proto_ptr);

    // Si c'est un paquet IPv4 (0x0800), lis le protocole IP (byte 23 du header IP)
    if eth_proto == 0x0800 {
        let ip_proto_ptr = data.add(23) as *const u8;
        let ip_proto = *ip_proto_ptr;

        match ip_proto {
            1 => info!(&ctx, "IPv4: ICMP packet"),
            6 => info!(&ctx, "IPv4: TCP packet"),
            17 => info!(&ctx, "IPv4: UDP packet"),
            _ => info!(&ctx, "IPv4: other protocol {}", ip_proto),
        }
    } else {
        info!(&ctx, "Non-IPv4 packet, ethertype: {:#x}", eth_proto);
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
