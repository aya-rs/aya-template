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
{%- when "cgroup_sysctl" -%}
use aya::programs::CgroupSysctl;
{%- when "cgroup_sockopt" -%}
use aya::programs::CgroupSockopt;
{%- when "tracepoint" -%}
use aya::programs::TracePoint;
{%- when "lsm" -%}
use aya::{programs::Lsm, Btf};
{%- when "perf_event" -%}
use aya::programs::{perf_event, PerfEvent};
use aya::util::online_cpus;
{%- when "tp_btf" -%}
use aya::{programs::BtfTracePoint, Btf};
{%- when "socket_filter" -%}
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use aya::programs::SocketFilter;
{%- when "raw_tracepoint" -%}
use aya::programs::RawTracePoint;
{%- endcase %}
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
{% if program_types_with_opts contains program_type -%}
use clap::Parser;
{% endif -%}
use log::{info, warn};
use tokio::signal;

{% if program_types_with_opts contains program_type -%}
#[derive(Debug, Parser)]
struct Opt {
{%- if program_type == "xdp" or program_type == "classifier" %}
    #[clap(short, long, default_value = "eth0")]
    iface: String,
{% elsif program_type == "sock_ops" or program_type == "cgroup_skb" or program_type == "cgroup_sysctl" or program_type == "cgroup_sockopt" %}
    #[clap(short, long, default_value = "/sys/fs/cgroup/unified")]
    cgroup_path: String,
{% elsif program_type == "uprobe" or program_type == "uretprobe" %}
    #[clap(short, long)]
    pid: Option<i32>
{% endif -%}
}

{% endif -%}
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
{%- if program_types_with_opts contains program_type %}
    let opt = Opt::parse();
{% endif %}
    env_logger::init();

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
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
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
    {%- when "socket_filter" -%}
    let client = TcpStream::connect("127.0.0.1:1234")?;
    let prog: &mut SocketFilter = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    prog.load()?;
    prog.attach(client.as_raw_fd())?;
    {%- when "cgroup_sysctl" -%}
    let program: &mut CgroupSysctl = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup)?;
    {%- when "cgroup_sockopt" -%}
    let program: &mut CgroupSockopt = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup)?;
    {%- when "perf_event" -%}
    // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // on clock ticks.
    let program: &mut PerfEvent = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    for cpu in online_cpus()? {
        program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Frequency(1),
        )?;
    }
    {%- when "raw_tracepoint" -%}
    let program: &mut RawTracePoint = bpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach("{{tracepoint_name}}")?;
    {%- endcase %}

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
