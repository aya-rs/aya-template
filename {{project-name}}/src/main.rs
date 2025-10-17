{%- case program_type -%}
{%- when "kprobe", "kretprobe" -%}
use aya::programs::KProbe;
{%- when "fentry" -%}
use anyhow::Context as _;
use aya::{Btf, programs::FEntry};
{%- when "fexit" -%}
use anyhow::Context as _;
use aya::{Btf, programs::FExit};
{%- when "uprobe", "uretprobe" -%}
use aya::programs::UProbe;
{%- when "sock_ops" -%}
use anyhow::Context as _;
use aya::programs::{SockOps, links::CgroupAttachMode};
{%- when "sk_msg" -%}
use aya::{maps::SockHash, programs::SkMsg};
use {{crate_name}}_common::SockKey;
{%- when "xdp" -%}
use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
{%- when "classifier" -%}
use aya::programs::{SchedClassifier, TcAttachType, tc};
{%- when "cgroup_skb" -%}
use anyhow::Context as _;
use aya::programs::{CgroupSkb, CgroupSkbAttachType, links::CgroupAttachMode};
{%- when "cgroup_sysctl" -%}
use anyhow::Context as _;
use aya::programs::{CgroupSysctl, links::CgroupAttachMode};
{%- when "cgroup_sockopt" -%}
use anyhow::Context as _;
use aya::programs::{CgroupSockopt, links::CgroupAttachMode};
{%- when "tracepoint" -%}
use aya::programs::TracePoint;
{%- when "lsm" -%}
use aya::{Btf, programs::Lsm};
{%- when "perf_event" -%}
use aya::{
    programs::{PerfEvent, perf_event},
    util::online_cpus,
};
{%- when "tp_btf" -%}
use aya::{Btf, programs::BtfTracePoint};
{%- when "socket_filter" -%}
use aya::programs::SocketFilter;
{%- when "raw_tracepoint" -%}
use aya::programs::RawTracePoint;
{%- endcase %}
{% if program_types_with_opts contains program_type -%}
use clap::Parser;
{% endif -%}

#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

{% if program_types_with_opts contains program_type -%}
#[derive(Debug, Parser)]
struct Opt {
{%- case program_type -%}
{%- when "xdp", "classifier" %}
    #[clap(short, long, default_value = "{{default_iface}}")]
    iface: String,
{%- when "sock_ops", "cgroup_skb", "cgroup_sysctl", "cgroup_sockopt" %}
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: std::path::PathBuf,
{%- when "uprobe", "uretprobe" %}
    #[clap(short, long)]
    pid: Option<i32>,
{%- endcase %}
}

{% endif -%}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/{{project-name}}"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    {%- case program_type -%}
    {%- when "kprobe", "kretprobe" %}
    let program: &mut KProbe = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach("{{kprobe}}", 0)?;
    {%- when "fentry" %}
    let btf = Btf::from_sys_fs().context("BTF from sysfs")?;
    let program: &mut FEntry = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load("{{fn_name}}", &btf)?;
    program.attach()?;
    {%- when "fexit" %}
    let btf = Btf::from_sys_fs().context("BTF from sysfs")?;
    let program: &mut FExit = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load("{{fn_name}}", &btf)?;
    program.attach()?;
    {%- when "uprobe", "uretprobe" %}
    let Opt { pid } = opt;
    let program: &mut UProbe = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach("{{uprobe_fn_name}}", "{{uprobe_target}}", pid, None /* cookie */)?;
    {%- when "sock_ops", "cgroup_skb", "cgroup_sysctl", "cgroup_sockopt" %}
    let Opt { cgroup_path } = opt;
    let cgroup =
        std::fs::File::open(&cgroup_path).with_context(|| format!("{}", cgroup_path.display()))?;
    {%- if program_type == "sock_ops" %}
    let program: &mut SockOps = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(cgroup, CgroupAttachMode::default())?;
    {%- elsif program_type == "cgroup_skb" %}
    let program: &mut CgroupSkb = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(
        cgroup,
        CgroupSkbAttachType::{{direction}},
        CgroupAttachMode::default(),
    )?;
    {%- elsif program_type == "cgroup_sysctl" %}
    let program: &mut CgroupSysctl = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(cgroup, CgroupAttachMode::default())?;
    {%- elsif program_type == "cgroup_sockopt" %}
    let program: &mut CgroupSockopt = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(cgroup, CgroupAttachMode::default())?;
    {%- endif -%}
    {%- when "sk_msg" %}
    let sock_map: SockHash<_, SockKey> = ebpf.map("{{sock_map}}").unwrap().try_into()?;
    let map_fd = sock_map.fd().try_clone()?;
    let prog: &mut SkMsg = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    prog.load()?;
    prog.attach(&map_fd)?;
    // insert sockets to the map using sock_map.insert here, or from a sock_ops program
    {%- when "xdp" %}
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    {%- when "classifier" %}
    let Opt { iface } = opt;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::{{direction}})?;
    {%- when "tracepoint" %}
    let program: &mut TracePoint = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach("{{tracepoint_category}}", "{{tracepoint_name}}")?;
    {%- when "lsm" %}
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = ebpf.program_mut("{{lsm_hook}}").unwrap().try_into()?;
    program.load("{{lsm_hook}}", &btf)?;
    program.attach()?;
    {%- when "tp_btf" %}
    let btf = Btf::from_sys_fs()?;
    let program: &mut BtfTracePoint = ebpf.program_mut("{{tracepoint_name}}").unwrap().try_into()?;
    program.load("{{tracepoint_name}}", &btf)?;
    program.attach()?;
    {%- when "socket_filter" %}
    let listener = std::net::TcpListener::bind("localhost:0")?;
    let prog: &mut SocketFilter = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    prog.load()?;
    prog.attach(&listener)?;
    {%- when "perf_event" %}
    // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // on clock ticks.
    let program: &mut PerfEvent = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    for cpu in online_cpus().map_err(|(_, error)| error)? {
        program.attach(
            perf_event::PerfEventConfig::Software(perf_event::SoftwareEvent::CpuClock),
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Frequency(1),
            true,
        )?;
    }
    {%- when "raw_tracepoint" %}
    let program: &mut RawTracePoint = ebpf.program_mut("{{crate_name}}").unwrap().try_into()?;
    program.load()?;
    program.attach("{{tracepoint_name}}")?;
    {%- endcase %}

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
