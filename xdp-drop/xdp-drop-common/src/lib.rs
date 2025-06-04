// xdp-drop-common/src/lib.rs
#![no_std] 

#[cfg(feature = "user")]
use aya::Pod; // Pour la dérivation de Pod en userspace, seulement si la feature "user" est active

// --- Structure PacketLog (EXISTANTE) ---
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}

#[cfg(feature = "user")]
unsafe impl Pod for PacketLog {}


// --- Structure IpPort (EXISTANTE, avec potentiels ajouts de traits) ---
/// Représente une combinaison d'adresse IPv4 source, destination et de port destination.
/// Utilisée comme clé pour la BLOCKLIST (règles statiques).
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct IpPort {
    /// Adresse IPv4 source, en network byte order (big-endian).
    pub addr: u32,
    /// Adresse IPv4 destination, en network byte order (big-endian).
    pub addr_dest: u32,
    /// Numéro de port destination, en network byte order (big-endian).
    /// Une valeur de 0 peut signifier "any port" pour cette règle.
    pub port: u16,
    /// Padding pour aligner la structure sur 8 octets si nécessaire (total 4+4+2+2 = 12 octets).
    /// Si vous visez un alignement de 8 octets avec 2 u32 et 1 u16,
    /// vous avez besoin de 2 octets de padding.
    pub _pad: u16,
}

#[cfg(feature = "user")]
unsafe impl Pod for IpPort {}


// --- NOUVELLES STRUCTURES POUR LE SUIVI DE CONNEXION (STATEFUL) ---

/// Clé unique identifiant une connexion réseau (5-tuple).
/// Utilisée comme clé pour la CONN_TRACK_TABLE (table de suivi des états).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "user", derive(Pod))] // Dérive Pod si feature "user" active
pub struct ConnectionKey {
    pub src_ip: u32,   // IP source (Network byte order)
    pub src_port: u16, // Port source (Network byte order)
    pub dst_ip: u32,   // IP destination (Network byte order)
    pub dst_port: u16, // Port destination (Network byte order)
    pub protocol: u8,  // Protocole IP (ex: 6 pour TCP, 17 pour UDP)
    pub _pad1: u8,     // Padding pour alignement
    pub _pad2: u16,    // Padding pour alignement (total 4+2+4+2+1+1+2 = 16 octets)
}

/// États possibles pour une connexion TCP suivie.
#[repr(u8)] // Représente l'enum comme un u8 pour une taille compacte
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Pod))]
pub enum TcpState {
    // Closed = 0, // Généralement, on supprime l'entrée au lieu d'un état "Closed"
    SynSent = 1,     // SYN envoyé par nous (client), attendant SYN-ACK
    SynReceived = 2, // SYN reçu du pair, SYN-ACK envoyé par nous, attendant ACK final du client
    Established = 3, // Connexion établie
    FinWait1 = 4,    // Notre FIN a été envoyé
    // Vous pouvez ajouter d'autres états (FinWait2, CloseWait, LastAck, TimeWait)
    // mais gardez à l'esprit la complexité en eBPF.
    // Pour XDP, une machine d'état simplifiée est souvent préférable.
}

/// États possibles pour un flux UDP "suivi".
#[repr(u8)] // Représente l'enum comme un u8
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Pod))]
pub enum UdpState {
    New = 1,         // Premier paquet vu
    Established = 2, // Paquet de "réponse" vu (flux bidirectionnel simple)
}

/// Variante pour encapsuler l'état spécifique au protocole (TCP ou UDP).
/// C'est une manière de stocker différents types d'états dans ConnectionValue.
/// Attention à la taille et à l'alignement pour eBPF.
#[repr(C)] // Pour contrôler la disposition
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Pod))]
pub enum ConnStateVariant {
    Tcp(TcpState),   // Occupera la taille de TcpState (1 octet) + discriminant (si nécessaire, mais repr(C) peut l'optimiser)
    Udp(UdpState),   // Occupera la taille de UdpState (1 octet) + discriminant
    // Vous pourriez aussi utiliser un type `None` ou `Unused` si nécessaire.
    // Si la taille devient un problème, envisagez une union ou des champs séparés.
}

// Si la taille de ConnStateVariant pose problème avec Pod ou pour la map eBPF
// (par exemple si l'enum devient trop grande ou complexe à cause des discriminants),
// une alternative est d'utiliser des entiers bruts et de les interpréter :
// pub state_type: u8; // 0 pour TCP, 1 pour UDP
// pub specific_state: u8; // Valeur de TcpState ou UdpState


/// Valeur stockée dans la CONN_TRACK_TABLE.
/// Contient l'état actuel de la connexion et quand elle a été vue pour la dernière fois.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Pod))]
pub struct ConnectionValue {
    /// L'état actuel de la connexion (TCP ou UDP).
    /// Pour que `Pod` fonctionne bien avec des enums contenant des données,
    /// il est parfois plus simple de stocker l'état sous forme d'entiers.
    /// Cependant, avec `repr(C)` sur l'enum et `repr(u8)` sur les états internes,
    /// `ConnStateVariant` devrait bien fonctionner.
    pub state: ConnStateVariant,

    /// Timestamp de la dernière fois que cette connexion a vu un paquet,
    /// en nanosecondes depuis le démarrage du système (valeur de `bpf_ktime_get_ns()`).
    pub last_seen_ns: u64,

    // Optionnel : vous pourriez ajouter des flags ici
    // pub flags: u8; // ex: initié depuis l'intérieur, etc.
    // pub _pad_cv: [u8; X]; // Padding pour aligner ConnectionValue si nécessaire
}

// Note sur `aya::Pod` et les enums contenant des données (comme ConnStateVariant):
// La dérivation de `Pod` pour les enums avec des données peut parfois être délicate
// car la représentation mémoire doit être sans padding et prédictible.
// L'utilisation de `#[repr(C)]` sur ConnStateVariant et `#[repr(u8)]` sur TcpState/UdpState
// aide grandement à contrôler cette représentation. Si vous rencontrez des problèmes
// avec `Pod` pour `ConnectionValue` à cause de `ConnStateVariant`, la solution
// serait de "désaplatir" `ConnStateVariant` dans `ConnectionValue`:
/*
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Pod))]
pub struct ConnectionValueAlternative {
    pub protocol_type: u8, // 0=TCP, 1=UDP
    pub current_state: u8, // Valeur de TcpState ou UdpState castée en u8
    pub last_seen_ns: u64,
    // ... padding ...
}
*/
// Mais essayons d'abord avec ConnStateVariant comme défini.


// --- Assurez-vous que les features sont correctement configurées ---
// Dans le Cargo.toml de cette crate (xdp-drop-common):
// [dependencies]
// aya = { version = "...", optional = true } # Utilisez votre version d'Aya
//
// [features]
// default = []
// user = ["aya"] # La feature "user" active la dépendance "aya"

// Et dans les Cargo.toml des crates qui utilisent xdp-drop-common :
// Pour xdp-drop (userspace):
// xdp-drop-common = { path = "../xdp-drop-common", features = ["user"] }
//
// Pour xdp-drop-ebpf (kernelspace):
// xdp-drop-common = { path = "../xdp-drop-common", default-features = false }
// (default-features = false désactive la feature "user" et donc la dépendance aya)