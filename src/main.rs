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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <command> <args>", args[0]);
        return;
    }
    let mut command = std::process::Command::new(&args[1]);
    command.args(&args[2..]);
    let child = command.spawn().expect("failed to execute process");
    let pid = child.id();
    let key: u32 = 0;
    let key: &[u8] = &key.to_ne_bytes();
    let value: &[u8] = &pid.to_ne_bytes();
    let output = child
        .wait_with_output()
        .expect("failed to wait on child process");

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



}
