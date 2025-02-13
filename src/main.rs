use std::thread::{self, sleep};
use std::{env, mem::MaybeUninit};

mod strace {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/strace.skel.rs"
    ));
}
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags};
use strace::*;
use sysnames::Syscalls;

fn get_syscall_name(syscall: u64) -> &'static str {
    let syscalls = Syscalls::name(syscall as u64);
    match syscalls {
        Some(name) => name,
        None => "Unknown",
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <pid>", args[0]);
        return;
    }

    let value: &[u8] = &args[1].parse::<u32>().unwrap().to_ne_bytes();
    let key: &[u8] = &0u32.to_ne_bytes();
    // eBPF loading happens here
    let skel_builder = StraceSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object);
    if open_skel.is_err() {
        eprintln!("Failed to open BPF skeleton: {:?}", open_skel.err());
        return;
    }

    // Load into kernel
    let skel = open_skel.unwrap().load().unwrap();

    skel.maps
        .input_map
        .update(key, value, MapFlags::empty())
        .expect("Failed to insert pid into input map");

    //enable program
    let link = skel
        .progs
        .syscall_tracker
        .attach()
        .expect("Failed to attach syscall_tracker program");

    loop {
        // read output map
        let mut key: u32 = 0;
        let key: &[u8] = &key.to_ne_bytes();

        let value = skel
            .maps
            .syscall_map
            .lookup(value, MapFlags::empty())
            .expect("Failed to lookup output map");
        if let Some(value) = value {
            let syscall = u64::from_ne_bytes(value[0..8].try_into().unwrap());
            let syscall_name = get_syscall_name(syscall);
            println!("Syscall: {}({})", syscall_name, syscall);
        } else {
            println!("No syscalls recorded yet.");
        }
    }
}
