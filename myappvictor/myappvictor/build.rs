use std::{
    env,
    fs,
    path::PathBuf,
};

fn main() {
    // Chemin vers le .o généré par le projet eBPF
    let src = PathBuf::from("../myappvictor-ebpf/target/bpfel-unknown-none/release/myappvictor-ebpf");

    // Dossier OUT_DIR de ce crate
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Chemin de destination du binaire eBPF
    let dst = out_dir.join("myappvictor");

    fs::copy(&src, &dst).expect("Failed to copy eBPF program");
}
