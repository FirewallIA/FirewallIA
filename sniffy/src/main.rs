use aya::{Ebpf, programs::{CgroupSkb, CgroupSkbAttachType, CgroupAttachMode}};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Charger le programme BPF à partir du fichier binaire
    let mut ebpf = Ebpf::load_file("ebpf.o")?;

    // Obtenir le programme `ingress_filter` du fichier binaire
    let ingress: &mut CgroupSkb = ebpf.program_mut("ingress_filter")?.try_into()?;

    // Charger le programme dans le noyau
    ingress.load()?;

    // Attacher le programme au cgroup racine pour qu'il soit exécuté sur tous les paquets entrants
    let cgroup = File::open("/sys/fs/cgroup/unified")?;
    ingress.attach(cgroup, CgroupSkbAttachType::Ingress, CgroupAttachMode::AllowOverride)?;

    println!("Program loaded and attached!");

    Ok(())
}
