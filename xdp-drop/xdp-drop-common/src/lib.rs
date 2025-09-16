// Dans: xdp-drop-common/src/lib.rs (ou votre crate commune équivalente)

#![no_std] // Assurez-vous que ceci est bien au début du fichier

// Définition existante (gardez-la)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}

// Implémentation Pod existante (gardez-la)
#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}


// --- Nouvelle structure IpPort ---

/// Représente une combinaison d'adresse IPv4 et de port.
/// Conçue pour être partagée entre l'espace utilisateur et les programmes eBPF.
#[repr(C)] // Assure une disposition mémoire compatible C, essentielle pour eBPF.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)] // Clone/Copy sont essentiels pour les maps. Debug est utile.
                              // Ajoutez PartialEq, Eq, Hash si utilisé comme clé dans std::collections::HashMap (user-space)
pub struct IpPort {
    /// Adresse IPv4, généralement stockée en network byte order (big-endian).
    pub addr: u32,
    pub addr_dest : u32,
    /// Numéro de port, généralement stocké en network byte order (big-endian).
    pub port: u16,
    pub _pad: u16,
    // Deux octets de padding seront probablement insérés ici par le compilateur
    // à cause de #[repr(C)] pour aligner la structure sur 4 octets (alignement de addr).
    // Taille totale : 4 (addr) + 2 (port) + 2 (padding) = 8 octets.
}

/// Marque IpPort comme sûr pour être utilisé comme Plain Old Data (POD) dans les maps eBPF
/// lorsque la feature "user" est activée (c'est-à-dire lors de la compilation pour l'espace utilisateur).
#[cfg(feature = "user")]
unsafe impl aya::Pod for IpPort {} // Ajoutez ceci pour IpPort, comme pour PacketLog

// --- Autres définitions partagées si nécessaire ---
// Clé pour le suivi de connexion (5-tuple)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct ConnectionKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3], // Alignement
}

// États possibles pour une connexion TCP
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    SynSent = 1,      // Un SYN a été envoyé, en attente de SYN-ACK
    Established = 2,  // La connexion est établie (SYN-ACK reçu)
    Closing = 3,      // Un FIN a été vu
}

// NOUVEAU: Valeur pour la map de suivi
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConnectionValue {
    pub state: u32,
    // On pourrait ajouter un timestamp pour le nettoyage, mais gardons simple pour l'instant
}