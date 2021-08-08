use std::{
    convert::{TryFrom, TryInto},
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Bpf, Btf,
};

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
        process::exit(1);
    }
}

fn try_main() -> Result<(), anyhow::Error> {
    // load the eBPF code
    let code = include_bytes!("../../target/bpfel-unknown-none/debug/{{ project-name }}").to_vec();
    let mut bpf = Bpf::load(&code, Btf::from_sys_fs().ok().as_ref())?;

    // insert port 8080 in the list of ports to be blocked
    let mut map = HashMap::<_, u16, u16>::try_from(bpf.map_mut("BLOCK_PORTS")?)?;
    map.insert(8080, 1, 0)?;

    // load the XDP program
    let prog: &mut Xdp = bpf.program_mut("xdp_fw")?.try_into()?;
    prog.load()?;
    prog.attach("eth0", XdpFlags::SKB_MODE)?;

    // wait for SIGINT or SIGTERM
    Ok(loop_until_terminated())
}

fn loop_until_terminated() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting signal handler");

    while running.load(Ordering::SeqCst) {}
    println!("Exiting...");
}
