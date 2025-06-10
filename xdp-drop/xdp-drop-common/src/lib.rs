// Fichier : /root/FirewallIA/xdp-drop/xdp-drop-common/src/lib.rs

#![no_std]

// Tu auras besoin de bytemuck pour dériver Pod.
use bytemuck::{Pod, Zeroable};

// --- Structure PacketLog ---
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)] // Utilise les dérives de bytemuck
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}

// --- Structure IpPort ---
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Pod, Zeroable)]
pub struct IpPort {
    pub addr: u32,
    pub addr_dest: u32,
    pub port: u16,
    pub _pad: u16,
}

// --- NOUVELLES STRUCTURES POUR LE SUIVI DE CONNEXION (STATEFUL) ---
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Pod, Zeroable)]
pub struct ConnectionKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3], // Remplacer _pad1 et _pad2 par un seul padding explicite de 3 octets
}


#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    SynSent = 1,
    SynReceived = 2,
    Established = 3,
    FinWait1 = 4,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpState {
    New = 1,
    Established = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union State {
    pub tcp: TcpState,
    pub udp: UdpState,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Protocol {
    Tcp,
    Udp
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct ConnectionValue {
    pub last_seen_ns: u64,
    pub state: u8,
    pub protocol: u8,
    pub _pad: [u8; 6],
}
// Bytemuck ne peut pas dériver Pod pour les enums avec des données ou les unions complexes
// On doit l'implémenter manuellement si nécessaire ou simplifier la structure.
// Pour l'instant, simplifions en ne dérivant Pod que sur les structures simples.
// NOTE: Ta structure ConnectionValue avec une union peut poser problème à `Pod`.
// Je l'ai simplifiée ci-dessus pour la rendre compatible.
// Il faudra peut-être adapter ton code eBPF.
// La structure que tu avais avec `ConnStateVariant` est aussi difficilement compatible Pod.
// C'est un problème connu. On va le régler après la compilation.