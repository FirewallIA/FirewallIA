use aya::{Ebpf, programs::Xdp};
use aya::programs::XdpAttachType;
use std::path::Path;

fn main() {
    // Charger un programme eBPF depuis un fichier (un fichier pré-compilé .o)
    let ebpf = Ebpf::load_file("my_program.o").expect("Failed to load eBPF program");

    // Attacher le programme XDP à une interface réseau via un fichier "pin"
    let interface = "enp0s8"; // Remplace avec l'interface que tu souhaites surveiller
    let xdp_program = Xdp::from_pin(Path::new(&interface), XdpAttachType::XdpDrop).expect("Failed to convert to XDP");

    // Attacher le programme XDP à l'interface
    xdp_program.attach().expect("Failed to attach XDP program");

    // Boucle pour surveiller les paquets
    loop {
        // Si tu veux bloquer certains paquets, fais ici des vérifications
        // Exemple : Bloquer les paquets ICMP (protocole 1)
        if xdp_program.process_packet(|packet| {
            if packet.ip_protocol() == 1 {
                // Bloquer le paquet ICMP
                return XdpAction::Drop;
            }
            // Laisser passer les autres paquets
            XdpAction::Pass
        }).is_err() {
            println!("Error while processing packet");
        }
    }
}


