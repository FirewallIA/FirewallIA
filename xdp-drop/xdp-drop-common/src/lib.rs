#![no_std]

// L'importation de `aya::Pod` est pour le *trait*.
// La *macro* `derive(Pod)` est généralement rendue disponible via la feature "macros" de la crate `aya`.
#[cfg(feature = "user")]
use aya::Pod; // C'est pour le TRAIT Pod.

// Si vous avez besoin d'importer explicitement la macro pour `derive`
// (normalement ce n'est pas nécessaire si les features sont bien configurées
// dans Cargo.toml pour la crate `aya` elle-même)
// #[cfg(feature = "user")]
// use aya::macros::Pod; // Cela importerait la MACRO Pod. Essayons sans d'abord.


// --- Structure PacketLog (EXISTANTE) ---
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}

#[cfg(feature = "user")]
unsafe impl Pod for PacketLog {} // Implémentation manuelle du TRAIT


// --- Structure IpPort (EXISTANTE, avec potentiels ajouts de traits) ---
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct IpPort {
    pub addr: u32,
    pub addr_dest: u32,
    pub port: u16,
    pub _pad: u16,
}

#[cfg(feature = "user")]
unsafe impl Pod for IpPort {} // Implémentation manuelle du TRAIT


// --- NOUVELLES STRUCTURES POUR LE SUIVI DE CONNEXION (STATEFUL) ---

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "user", derive(aya::macros::Pod))] // UTILISEZ LE CHEMIN COMPLET VERS LA MACRO
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
#[cfg_attr(feature = "user", derive(aya::macros::Pod))] // UTILISEZ LE CHEMIN COMPLET VERS LA MACRO
pub enum TcpState {
    SynSent = 1,
    SynReceived = 2,
    Established = 3,
    FinWait1 = 4,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(aya::macros::Pod))] // UTILISEZ LE CHEMIN COMPLET VERS LA MACRO
pub enum UdpState {
    New = 1,
    Established = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(aya::macros::Pod))] // UTILISEZ LE CHEMIN COMPLET VERS LA MACRO
pub enum ConnStateVariant {
    Tcp(TcpState),
    Udp(UdpState),
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(aya::macros::Pod))] // UTILISEZ LE CHEMIN COMPLET VERS LA MACRO
pub struct ConnectionValue {
    pub state: ConnStateVariant,
    pub last_seen_ns: u64,
}

// Les implémentations `unsafe impl Pod for ... {}` que vous aviez pour PacketLog et IpPort
// sont des implémentations manuelles du *trait* Pod.
// Si vous voulez utiliser `#[derive(Pod)]`, vous devez vous assurer que la *macro* `Pod`
// est accessible.

// NOTE IMPORTANTE:
// Si vous utilisez `#[derive(Pod)]`, vous n'avez PAS besoin de l'implémentation manuelle
// `unsafe impl Pod for VotreType {}` pour le même type. L'un ou l'autre.
// La macro `derive` génère cette implémentation pour vous.
// J'ai changé vos nouvelles structures pour utiliser `derive(aya::macros::Pod)`.
// Vous devriez faire de même pour `PacketLog` et `IpPort` si vous préférez `derive`
// ou garder l'implémentation manuelle. Pour la cohérence, utilisons `derive` partout
// où c'est possible.

// Donc, pour PacketLog et IpPort, si vous voulez utiliser derive :
/*
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(aya::macros::Pod))] // Chemin complet
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}
// Plus besoin de : #[cfg(feature = "user")] unsafe impl Pod for PacketLog {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "user", derive(aya::macros::Pod))] // Chemin complet
pub struct IpPort {
    pub addr: u32,
    pub addr_dest: u32,
    pub port: u16,
    pub _pad: u16,
}
// Plus besoin de : #[cfg(feature = "user")] unsafe impl Pod for IpPort {}
*/