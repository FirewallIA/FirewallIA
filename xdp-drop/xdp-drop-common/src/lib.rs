#![no_std]

// Structure partagée entre eBPF (Kernel) et Userspace
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketLog {
    pub ipv4_src: u32,
    pub ipv4_dst: u32,
    pub port_src: u16,
    pub port_dst: u16,
    pub protocol: u32,
    pub action: u32, // 1 = BLOCK (DENY), 2 = ALLOW
}

// Constantes pour les protocoles
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_ANY: u8 = 0;

// Constantes pour les stats
pub const STAT_INBOUND: u32 = 0;
pub const STAT_OUTBOUND: u32 = 1;
pub const STAT_BLOCKED: u32 = 2;
pub const STAT_TOTAL_TYPES: u32 = 3;

// Clé pour la Map de règles
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IpPort {
    pub addr: u32,      // IP Source
    pub addr_dest: u32, // IP Dest
    pub port: u16,      // Port Dest
    pub protocol: u8,   // Protocole
    pub _pad: u8,       // Padding pour alignement mémoire
}

// Nécessaire pour que Aya puisse lire la struct depuis le Userspace
#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpPort {}  