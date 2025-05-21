// In xdp-drop-ebpf/src/main.rs
#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)] // dead_code for unused parts during dev

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info; // For logging from eBPF
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use xdp_drop_common::IpPort; // Import your shared struct

// Panic handler (required for no_std)
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The eBPF map for storing firewall rules.
// Key: IpPort (source IP, dest IP, dest port)
// Value: u32 (action code, e.g., 1 for DENY, 2 for ALLOW)
#[map]
static BLOCKLIST: HashMap<IpPort, u32> = HashMap::<IpPort, u32>::with_max_entries(1024, 0);

// Action constants (must match userspace definitions)
const ACTION_DENY_FROM_MAP: u32 = 1;
const ACTION_ALLOW_FROM_MAP: u32 = 2;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED, // Abort on error (e.g., out-of-bounds access)
    }
}

// Helper to safely get a pointer to data in the packet.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(()); // Offset + size is out of bounds
    }

    Ok((start + offset) as *const T)
}

// Checks the BLOCKLIST map for a matching rule.
// Returns Some(action_value) if a rule is found, None otherwise.
#[inline(always)]
fn check_firewall_rule(key: &IpPort) -> Option<u32> {
    unsafe { BLOCKLIST.get(key).copied() }
}

// Main XDP processing logic
fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // 1. Parse Ethernet Header
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    // let src_mac = unsafe { (*eth_hdr).src_addr }; // Example: if you need MACs
    // let dst_mac = unsafe { (*eth_hdr).dst_addr };

    // Check if it's an IPv4 packet, pass others
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {} // Continue processing
        _ => {
            // info!(&ctx, "Passing non-IPv4 packet");
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // 2. Parse IPv4 Header
    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_ip_be = unsafe { (*ipv4_hdr).src_addr }; // Big-endian (network order)
    let dest_ip_be = unsafe { (*ipv4_hdr).dst_addr };   // Big-endian (network order)
    let protocol = unsafe { (*ipv4_hdr).proto };

    // Calculate offset to the transport layer header
    // IHL (Internet Header Length) is in 32-bit words, so multiply by 4 for bytes.
    let transport_offset = EthHdr::LEN + (unsafe { (*ipv4_hdr).ihl() } as usize * 4);

    // 3. Parse Transport Header (TCP/UDP to get destination port)
    // We are primarily interested in the destination port for firewall rules.
    let dest_port_be: u16 = match protocol {
        IpProto::Tcp => {
            let tcp_hdr: *const TcpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            unsafe { (*tcp_hdr).dest } // Big-endian (network order)
        }
        IpProto::Udp => {
            let udp_hdr: *const UdpHdr = unsafe { ptr_at(&ctx, transport_offset)? };
            unsafe { (*udp_hdr).dest } // Big-endian (network order)
        }
        _ => {
            // For ICMP or other protocols, we might not have a port, or we can use 0.
            // For simplicity, if it's not TCP/UDP, we'll treat dest_port as 0.
            // A rule with port 0 could then act as a wildcard for "any port" for that protocol.
            0 // Represent "any" or "no port"
        }
    };

    // 4. Construct the key for the firewall map lookup
    let rule_key = IpPort {
        addr: source_ip_be,    // Source IP (already network byte order)
        addr_dest: dest_ip_be, // Destination IP (already network byte order)
        port: dest_port_be,    // Destination Port (already network byte order)
        _pad: 0,               // Padding
    };

    // 5. Perform Firewall Logic: Check the map
    let final_action = match check_firewall_rule(&rule_key) {
        Some(action_value_from_map) => {
            // A rule was found in the map
            if action_value_from_map == ACTION_DENY_FROM_MAP {
                info!(
                    &ctx,
                    "DENY rule match: S_IP={:i}, D_IP={:i}, D_PORT={}, Proto={}",
                    u32::from_be(source_ip_be), // Log in host byte order for readability
                    u32::from_be(dest_ip_be),   // Log in host byte order
                    u16::from_be(dest_port_be), // Log in host byte order
                    protocol as u8
                );
                xdp_action::XDP_DROP
            } else if action_value_from_map == ACTION_ALLOW_FROM_MAP {
                info!(
                    &ctx,
                    "ALLOW rule match: S_IP={:i}, D_IP={:i}, D_PORT={}, Proto={}",
                    u32::from_be(source_ip_be),
                    u32::from_be(dest_ip_be),
                    u16::from_be(dest_port_be),
                    protocol as u8
                );
                xdp_action::XDP_PASS
            } else {
                // Unknown action value from map, default to pass (or your chosen default)
                info!(
                    &ctx,
                    "WARN: Unknown action {} from map for S_IP={:i}, D_IP={:i}, D_PORT={}. Passing.",
                    action_value_from_map,
                    u32::from_be(source_ip_be),
                    u32::from_be(dest_ip_be),
                    u16::from_be(dest_port_be)
                );
                xdp_action::XDP_PASS
            }
        }
        None => {
            // No specific rule found in the map. Default action is PASS.
            // You could log this if needed for debugging, but it can be very verbose.
            // info!(&ctx, "No rule match for S_IP={:i}, D_IP={:i}, D_PORT={}. Passing by default.",
            //     u32::from_be(source_ip_be), u32::from_be(dest_ip_be), u16::from_be(dest_port_be));
            xdp_action::XDP_PASS
        }
    };

    Ok(final_action)
}