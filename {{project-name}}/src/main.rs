use aya::{include_bytes_aligned, Bpf};
{% case program_type -%}
{%- when "kprobe", "kretprobe" -%}
use aya::programs::KProbe;
{%- when "fentry" -%}
use aya::{programs::FEntry, Btf};
{%- when "fexit" -%}
use aya::{programs::FExit, Btf};
{%- when "uprobe", "uretprobe" -%}
use aya::programs::UProbe;
{%- when "sock_ops" -%}
use aya::programs::SockOps;
{%- when "sk_msg" -%}
use aya::maps::{MapRefMut,SockHash};
use aya::programs::SkMsg;
use {{crate_name}}_common::SockKey;
{%- when "xdp" -%}
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
{%- when "classifier" -%}
use aya::programs::{tc, SchedClassifier, TcAttachType};
{%- when "cgroup_skb" -%}
use aya::programs::{CgroupSkb, CgroupSkbAttachType};
{%- when "tracepoint" -%}
use aya::programs::TracePoint;
{%- when "lsm" -%}
use aya::{programs::Lsm, Btf};
{%- when "tp_btf" -%}
use aya::{programs::BtfTracePoint, Btf};
{%- endcase %}
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use structopt::StructOpt;
use tokio::signal;

#[derive(Debug, StructOpt)]
struct Opt {
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

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/{{project-name}}"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/{{project-name}}"
    ))?;
    {% case program_type -%}
    {%- when "kprobe", "kretprobe" -%}
    let program: &mut KProbe = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach("{{kprobe}}", 0)?;
    {%- when "fentry" -%}
    let btf = Btf::from_sys_fs()?;
    let program: &mut FEntry = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load("{{fn_name}}", &btf)?;
    program.attach()?;
    {%- when "fexit" -%}
    let btf = Btf::from_sys_fs()?;
    let program: &mut FExit = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load("{{fn_name}}", &btf)?;
    program.attach()?;
    {%- when "uprobe", "uretprobe" -%}
    let program: &mut UProbe = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("{{uprobe_fn_name}}"), 0, "{{uprobe_target}}", opt.pid.try_into()?)?;
    {%- when "sock_ops" -%}
    let program: &mut SockOps = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup)?;
    {%- when "sk_msg" -%}
    let sock_map = SockHash::<MapRefMut, SockKey>::try_from(bpf.map_mut("{{sock_map}}")?)?;
    let prog: &mut SkMsg = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    prog.load()?;
    prog.attach(&sock_map)?;
    // insert sockets to the map using sock_map.insert here, or from a sock_ops program
    {%- when "xdp" -%}
    let program: &mut Xdp = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    {%- when "classifier" -%}
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::{{direction}})?;
    {%- when "cgroup_skb" -%}
    let program: &mut CgroupSkb = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup, CgroupSkbAttachType::{{direction}})?;
    {%- when "tracepoint" -%}
    let program: &mut TracePoint = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach("{{tracepoint_category}}", "{{tracepoint_name}}")?;
    {%- when "lsm" -%}
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("{{lsm_hook}}").unwrap().try_into()?;
    program.load("{{lsm_hook}}", &btf)?;
    program.attach()?;
    {%- when "tp_btf" -%}
    let btf = Btf::from_sys_fs()?;
    let program: &mut BtfTracePoint = bpf.program_mut("{{tracepoint_name}}").unwrap().try_into()?;
    program.load("{{tracepoint_name}}", &btf)?;
    program.attach()?;
    {%- endcase %}

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
