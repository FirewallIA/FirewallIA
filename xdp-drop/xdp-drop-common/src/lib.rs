// Dans xdp-drop-common/src/lib.rs

#![no_std]

#[cfg(feature = "user")]
use aya::Pod as AyaPodTrait; // Importez le TRAIT Pod, vous pouvez le renommer si nécessaire pour éviter la confusion

// --- Structure PacketLog ---
#[repr(C)]
#[derive(Clone, Copy)]
// Si vous voulez utiliser derive pour PacketLog (et que vous avez supprimé l'impl manuelle)
#[cfg_attr(feature = "user", derive(aya::Pod))] // Modifié ici
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}
// Si vous utilisez derive, supprimez :
// #[cfg(feature = "user")]
// unsafe impl AyaPodTrait for PacketLog {}


// --- Structure IpPort ---
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "user", derive(aya::Pod))] // Modifié ici
pub struct IpPort {
    pub addr: u32,
    pub addr_dest: u32,
    pub port: u16,
    pub _pad: u16,
}
// Si vous utilisez derive, supprimez :
// #[cfg(feature = "user")]
// unsafe impl AyaPodTrait for IpPort {}


// --- NOUVELLES STRUCTURES POUR LE SUIVI DE CONNEXION (STATEFUL) ---

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "user", derive(aya::Pod))] // Modifié ici
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
#[cfg_attr(feature = "user", derive(aya::Pod))] // Modifié ici
pub enum TcpState {
    SynSent = 1,
    SynReceived = 2,
    Established = 3,
    FinWait1 = 4,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(aya::Pod))] // Modifié ici
pub enum UdpState {
    New = 1,
    Established = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(aya::Pod))] // Modifié ici
pub enum ConnStateVariant {
    Tcp(TcpState),
    Udp(UdpState),
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(aya::Pod))] // Modifié ici
pub struct ConnectionValue {
    pub state: ConnStateVariant,
    pub last_seen_ns: u64,
}