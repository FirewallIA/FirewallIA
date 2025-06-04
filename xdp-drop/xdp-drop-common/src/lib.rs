// Dans xdp-drop-common/src/lib.rs

#![no_std]

// Vous pouvez garder cet import pour le trait si vous l'utilisez ailleurs,
// ou le supprimer si derive(Pod) est la seule utilisation.
#[cfg(feature = "user")]
use aya::Pod as AyaPodTrait;

// --- Structure PacketLog ---
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Pod))] // Modifié : juste Pod
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}

// --- Structure IpPort ---
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "user", derive(Pod))] // Modifié : juste Pod
pub struct IpPort {
    pub addr: u32,
    pub addr_dest: u32,
    pub port: u16,
    pub _pad: u16,
}

// --- NOUVELLES STRUCTURES POUR LE SUIVI DE CONNEXION (STATEFUL) ---

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "user", derive(Pod))] // Modifié : juste Pod
pub struct ConnectionKey {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad1: u8,
    pub _pad2: u16,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Pod))] // Modifié : juste Pod
pub enum TcpState {
    SynSent = 1,
    SynReceived = 2,
    Established = 3,
    FinWait1 = 4,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Pod))] // Modifié : juste Pod
pub enum UdpState {
    New = 1,
    Established = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Pod))] // Modifié : juste Pod
pub enum ConnStateVariant {
    Tcp(TcpState),
    Udp(UdpState),
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Pod))] // Modifié : juste Pod
pub struct ConnectionValue {
    pub state: ConnStateVariant,
    pub last_seen_ns: u64,
}