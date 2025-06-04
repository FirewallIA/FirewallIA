// Dans xdp-drop-common/src/lib.rs

#![no_std]

// Cet import est nécessaire pour l'implémentation manuelle du TRAIT Pod.
#[cfg(feature = "user")]
use aya::Pod;

// --- Structure PacketLog ---
#[repr(C)]
#[derive(Clone, Copy)] // Gardez les autres derives utiles
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}
// Implémentation manuelle de Pod pour PacketLog
#[cfg(feature = "user")]
unsafe impl Pod for PacketLog {}


// --- Structure IpPort ---
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)] // Gardez les autres derives utiles
pub struct IpPort {
    pub addr: u32,
    pub addr_dest: u32,
    pub port: u16,
    pub _pad: u16,
}
// Implémentation manuelle de Pod pour IpPort
#[cfg(feature = "user")]
unsafe impl Pod for IpPort {}


// --- NOUVELLES STRUCTURES POUR LE SUIVI DE CONNEXION (STATEFUL) ---

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] // Gardez les autres derives utiles
pub struct ConnectionKey {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad1: u8,
    pub _pad2: u16,
}
// Implémentation manuelle de Pod pour ConnectionKey
#[cfg(feature = "user")]
unsafe impl Pod for ConnectionKey {}


#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)] // Gardez les autres derives utiles
pub enum TcpState {
    SynSent = 1,
    SynReceived = 2,
    Established = 3,
    FinWait1 = 4,
}
// Implémentation manuelle de Pod pour TcpState
#[cfg(feature = "user")]
unsafe impl Pod for TcpState {}


#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)] // Gardez les autres derives utiles
pub enum UdpState {
    New = 1,
    Established = 2,
}
// Implémentation manuelle de Pod pour UdpState
#[cfg(feature = "user")]
unsafe impl Pod for UdpState {}


#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)] // Gardez les autres derives utiles
pub enum ConnStateVariant {
    Tcp(TcpState),
    Udp(UdpState),
}
// Implémentation manuelle de Pod pour ConnStateVariant
#[cfg(feature = "user")]
unsafe impl Pod for ConnStateVariant {}


#[repr(C)]
#[derive(Clone, Copy, Debug)] // Gardez les autres derives utiles
pub struct ConnectionValue {
    pub state: ConnStateVariant,
    pub last_seen_ns: u64,
}
// Implémentation manuelle de Pod pour ConnectionValue
#[cfg(feature = "user")]
unsafe impl Pod for ConnectionValue {}