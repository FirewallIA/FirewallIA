// Dans xdp-drop-common/src/lib.rs
#![no_std]
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
#[cfg(feature = "user")]
use aya::Pod; // Nécessaire pour implémenter le TRAIT Pod

// --- Structure PacketLog ---
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}
#[cfg(feature = "user")]
unsafe impl Pod for PacketLog {}

// --- Structure IpPort ---
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct IpPort {
    pub addr: u32,
    pub addr_dest: u32,
    pub port: u16,
    pub _pad: u16,
}
#[cfg(feature = "user")]
unsafe impl Pod for IpPort {}

// --- NOUVELLES STRUCTURES POUR LE SUIVI DE CONNEXION (STATEFUL) ---
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad1: u8,
    pub _pad2: u16,
}
#[cfg(feature = "user")]
unsafe impl Pod for ConnectionKey {}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    SynSent = 1,
    SynReceived = 2,
    Established = 3,
    FinWait1 = 4,
}
#[cfg(feature = "user")]
unsafe impl Pod for TcpState {}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpState {
    New = 1,
    Established = 2,
}
#[cfg(feature = "user")]
unsafe impl Pod for UdpState {}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnStateVariant {
    Tcp(TcpState),
    Udp(UdpState),
}
#[cfg(feature = "user")]
unsafe impl Pod for ConnStateVariant {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectionValue {
    pub state: ConnStateVariant,
    pub last_seen_ns: u64,
}
#[cfg(feature = "user")]
unsafe impl Pod for ConnectionValue {}