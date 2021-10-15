use aya::Bpf;
{% case program_type -%}
{%- when "kprobe", "kretprobe" -%}
use aya::programs::KProbe;
{%- when "uprobe", "uretprobe" -%}
use aya::programs::UProbe;
{%- when "sock_ops" -%}
use aya::programs::SockOps;
{%- when "sk_msg" -%}
use aya::maps::{MapRefMut,SockHash};
use aya::programs::SkMsg;
use {{crate_name}}_common::SockKey;
{%- when "xdp" -%}
use aya::programs::{Xdp, XdpFlags};
{%- when "classifier" -%}
use aya::programs::{tc, SchedClassifier, TcAttachType};
{%- when "cgroup_skb" -%}
use aya::programs::{CgroupSkb, CgroupSkbAttachType};
{%- when "tracepoint" -%}
use aya::programs::TracePoint;
{%- endcase %}
use std::{
    convert::{TryFrom,TryInto},
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};
use structopt::StructOpt;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    path: String,
    {% if program_type == "xdp" or program_type == "classifier" -%}
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
    {%- elsif program_type == "sock_ops" or program_type == "cgroup_skb" -%}
    #[structopt(short, long, default_value = "/sys/fs/cgroup/unified")]
    cgroup_path: String,
    {%- elsif program_type == "uprobe" or program_type == "uretprobe" -%}
    #[structopt(short, long)]
    pid: Option<i32>
    {%- endif %}
}

fn try_main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    let mut bpf = Bpf::load_file(&opt.path)?;
    {% case program_type -%}
    {%- when "kprobe", "kretprobe" -%}
    let program: &mut KProbe = bpf.program_mut("{{crate_name}}")?.try_into()?;
    program.load()?;
    program.attach("{{probe}}", 0)?;
    {%- when "uprobe", "uretprobe" -%}
    let program: &mut UProbe = bpf.program_mut("{{crate_name}}")?.try_into()?;
    program.load()?;
    program.attach(Some("{{uprobe_fn_name}}"), 0, "{{uprobe_target}}", opt.pid.try_into()?)?;
    {%- when "sock_ops" -%}
    let program: &mut SockOps = bpf.program_mut("{{crate_name}}")?.try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup)?;
    {%- when "sk_msg" -%}
    let sock_map = SockHash::<MapRefMut, SockKey>::try_from(bpf.map_mut("{{sock_map}}")?)?;
    let prog: &mut SkMsg = bpf.program_mut("{{crate_name}}")?.try_into()?;
    prog.load()?;
    prog.attach(&sock_map)?;
    // insert sockets to the map using sock_map.insert here, or from a sock_ops program
    {%- when "xdp" -%}
    let program: &mut Xdp = bpf.program_mut("{{crate_name}}")?.try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;
    {%- when "classifier" -%}
    tc::qdisc_add_clsact(&opt.iface)?;
    let program: &mut SchedClassifier = bpf.program_mut("{{crate_name}}")?.try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::{{direction}})?;
    {%- when "cgroup_skb" -%}
    let program: &mut CgroupSkb = bpf.program_mut("{{crate_name}}")?.try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup, CgroupSkbAttachType::{{direction}})?;
    {%- when "tracepoint" -%}
    let program: &mut TracePoint = bpf.program_mut("{{crate_name}}")?.try_into()?;
    program.load()?;
    program.attach("{{tracepoint_category}}", "{{tracepoint_name}}")?;
    {%- endcase %}
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    println!("Waiting for Ctrl-C...");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(500))
    }
    println!("Exiting...");

    Ok(())
}