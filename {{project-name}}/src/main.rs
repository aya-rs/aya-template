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
use aya::programs::{SockOps, links::CgroupAttachMode};
{%- when "sk_msg" -%}
use aya::maps::SockHash;
use aya::programs::SkMsg;
use {{crate_name}}_common::SockKey;
{%- when "xdp" -%}
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
{%- when "classifier" -%}
use aya::programs::{tc, SchedClassifier, TcAttachType};
{%- when "cgroup_skb" -%}
use aya::programs::{CgroupSkb, CgroupSkbAttachType, links::CgroupAttachMode};
{%- when "cgroup_sysctl" -%}
use aya::programs::{CgroupSysctl, links::CgroupAttachMode};
{%- when "cgroup_sockopt" -%}
use aya::programs::{CgroupSockopt, links::CgroupAttachMode};
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
use aya::programs::SocketFilter;
{%- when "raw_tracepoint" -%}
use aya::programs::RawTracePoint;
{%- endcase %}
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
{% if program_types_with_opts contains program_type -%}
use clap::Parser;
{% endif -%}
use log::{info, warn, debug};
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
    pid: Option<i32>,
{% endif -%}
}

{% endif -%}
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
{%- if program_types_with_opts contains program_type %}
    let opt = Opt::parse();
{% endif %}
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/{{project-name}}"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/{{project-name}}"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    {% case program_type -%}
    {%- when "kprobe", "kretprobe" -%}
    let program: &mut KProbe = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach("{{kprobe}}", 0)?;
    {%- when "fentry" -%}
    let btf = Btf::from_sys_fs()?;
    let program: &mut FEntry = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load("{{fn_name}}", &btf)?;
    program.attach()?;
    {%- when "fexit" -%}
    let btf = Btf::from_sys_fs()?;
    let program: &mut FExit = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load("{{fn_name}}", &btf)?;
    program.attach()?;
    {%- when "uprobe", "uretprobe" -%}
    let program: &mut UProbe = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("{{uprobe_fn_name}}"), 0, "{{uprobe_target}}", opt.pid)?;
    {%- when "sock_ops" -%}
    let program: &mut SockOps = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup, CgroupAttachMode::default())?;
    {%- when "sk_msg" -%}
    let sock_map: SockHash::<_, SockKey> = ebpf.map("{{sock_map}}").unwrap().try_into()?;
    let map_fd = sock_map.fd().try_clone()?;

    let prog: &mut SkMsg = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    prog.load()?;
    prog.attach(&map_fd)?;
    // insert sockets to the map using sock_map.insert here, or from a sock_ops program
    {%- when "xdp" -%}
    let program: &mut Xdp = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    {%- when "classifier" -%}
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::{{direction}})?;
    {%- when "cgroup_skb" -%}
    let program: &mut CgroupSkb = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup, CgroupSkbAttachType::{{direction}}, CgroupAttachMode::default())?;
    {%- when "tracepoint" -%}
    let program: &mut TracePoint = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach("{{tracepoint_category}}", "{{tracepoint_name}}")?;
    {%- when "lsm" -%}
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = ebpf.program_mut("{{lsm_hook}}").unwrap().try_into()?;
    program.load("{{lsm_hook}}", &btf)?;
    program.attach()?;
    {%- when "tp_btf" -%}
    let btf = Btf::from_sys_fs()?;
    let program: &mut BtfTracePoint = ebpf.program_mut("{{tracepoint_name}}").unwrap().try_into()?;
    program.load("{{tracepoint_name}}", &btf)?;
    program.attach()?;
    {%- when "socket_filter" -%}
    let client = TcpStream::connect("127.0.0.1:1234")?;
    let prog: &mut SocketFilter = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    prog.load()?;
    prog.attach(client)?;
    {%- when "cgroup_sysctl" -%}
    let program: &mut CgroupSysctl = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup, CgroupAttachMode::default())?;
    {%- when "cgroup_sockopt" -%}
    let program: &mut CgroupSockopt = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup, CgroupAttachMode::default())?;
    {%- when "perf_event" -%}
    // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // on clock ticks.
    let program: &mut PerfEvent = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    for cpu in online_cpus().map_err(|(_, error)| error)? {
        program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Frequency(1),
            true,
        )?;
    }
    {%- when "raw_tracepoint" -%}
    let program: &mut RawTracePoint = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach("{{tracepoint_name}}")?;
    {%- endcase %}

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
