use std::fs::File;
use aya::Ebpf;
use aya::programs::{CgroupSkb, CgroupSkbAttachType, CgroupAttachMode};

// load the BPF code
let mut ebpf = Ebpf::load_file("ebpf.o")?;

// get the `ingress_filter` program compiled into `ebpf.o`.
let ingress: &mut CgroupSkb = ebpf.program_mut("ingress_filter")?.try_into()?;

// load the program into the kernel
ingress.load()?;

// attach the program to the root cgroup. `ingress_filter` will be called for all
// incoming packets.
let cgroup = File::open("/sys/fs/cgroup/unified")?;
ingress.attach(cgroup, CgroupSkbAttachType::Ingress, CgroupAttachMode::AllowOverride)?;