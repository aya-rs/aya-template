#![no_std]
#![no_main]
{% case program_type -%}
{%- when "kprobe" %}
use aya_bpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function {{kprobe}} called");
    Ok(0)
}
{%- when "kretprobe" %}
use aya_bpf::{macros::kretprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kretprobe(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function {{kprobe}} called");
    Ok(0)
}
{%- when "fentry" %}
use aya_bpf::{
    macros::fentry,
    programs::FEntryContext,
};
use aya_log_ebpf::info;

#[fentry(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: FEntryContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: FEntryContext) -> Result<u32, u32> {
    info!(&ctx, "function {{fn_name}} called");
    Ok(0)
}
{%- when "fexit" %}
use aya_bpf::{
    macros::fexit,
    programs::FExitContext,
};
use aya_log_ebpf::info;

#[fexit(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: FExitContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: FExitContext) -> Result<u32, u32> {
    info!(&ctx, "function {{fn_name}} called");
    Ok(0)
}
{%- when "uprobe" %}
use aya_bpf::{
    macros::uprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[uprobe(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function {{uprobe_fn_name}} called by {{uprobe_target}}");
    Ok(0)
}
{%- when "uretprobe" %}
use aya_bpf::{
    macros::uretprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[uretprobe(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function {{uprobe_fn_name}} called by {{uprobe_target}}");
    Ok(0)
}
{%- when "sock_ops" %}
use aya_bpf::{
    macros::sock_ops,
    programs::SockOpsContext,
};
use aya_log_ebpf::info;

#[sock_ops(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: SockOpsContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: SockOpsContext) -> Result<u32, u32> {
    info!(&ctx, "received TCP connection");
    Ok(0)
}
{%- when "sk_msg" %}
use aya_bpf::{
    macros::{map, sk_msg},
    maps::SockHash,
    programs::SkMsgContext,
};
use aya_log_ebpf::info;

use {{crate_name}}_common::SockKey;

#[map(name="{{sock_map}}")]
static {{sock_map}}: SockHash<SockKey> = SockHash::<SockKey>::with_max_entries(1024, 0);

#[sk_msg(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: SkMsgContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: SkMsgContext) -> Result<u32, u32> {
    info!(&ctx, "received a message on the socket");
    Ok(0)
}
{%- when "xdp" %}
use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

#[xdp(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: XdpContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_{{crate_name}}(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}
{%- when "classifier" %}
use aya_bpf::{macros::classifier, programs::TcContext};
use aya_log_ebpf::info;

#[classifier(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: TcContext) -> i32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(0)
}
{%- when "cgroup_skb" %}
use aya_bpf::{
    macros::cgroup_skb,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;

#[cgroup_skb(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: SkBuffContext) -> i32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: SkBuffContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(0)
}
{%- when "tracepoint" %}
use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: TracePointContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint {{tracepoint_name}} called");
    Ok(0)
}
{%- when "lsm" %}
use aya_bpf::{
    macros::lsm,
    programs::LsmContext,
};
use aya_log_ebpf::info;

#[lsm(name = "{{lsm_hook}}")]
pub fn {{lsm_hook}}(ctx: LsmContext) -> i32 {
    match try_{{lsm_hook}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{lsm_hook}}(ctx: LsmContext) -> Result<i32, i32> {
    info!(&ctx, "lsm hook {{lsm_hook}} called");
    Ok(0)
}
{%- when "tp_btf" %}
use aya_bpf::{
    macros::btf_tracepoint,
    programs::BtfTracePointContext,
};
use aya_log_ebpf::info;

#[btf_tracepoint(name = "{{tracepoint_name}}")]
pub fn {{tracepoint_name}}(ctx: BtfTracePointContext) -> i32 {
    match try_{{tracepoint_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{tracepoint_name}}(ctx: BtfTracePointContext) -> Result<i32, i32> {
    info!(&ctx, "tracepoint {{tracepoint_name}} called");
    Ok(0)
}
{%- when "socket_filter" %}
use aya_bpf::{
    macros::socket_filter,
    programs::SkBuffContext,
};

#[socket_filter(name = "{{crate_name}}")]
pub fn {{crate_name}}(_ctx: SkBuffContext) -> i64 {
    return 0
}
{%- when "cgroup_sysctl" %}
use aya_bpf::{
    macros::cgroup_sysctl,
    programs::SysctlContext,
};
use aya_log_ebpf::info;

#[cgroup_sysctl(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: SysctlContext) -> i32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: SysctlContext) -> Result<i32, i32> {
    info!(&ctx, "sysctl operation called");
    Ok(0)
}
{%- when "cgroup_sockopt" %}
use aya_bpf::{macros::cgroup_sockopt, programs::SockoptContext};
use aya_log_ebpf::info;

#[cgroup_sockopt({{sockopt_target}}, name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: SockoptContext) -> i32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: SockoptContext) -> Result<i32, i32> {
    info!(&ctx, "{{sockopt_target}} called");
    Ok(0)
}
{%- when "raw_tracepoint" %}
use aya_bpf::{macros::raw_tracepoint, programs::RawTracePointContext};
use aya_log_ebpf::info;

#[raw_tracepoint(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: RawTracePointContext) -> i32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: RawTracePointContext) -> Result<i32, i32> {
    info!(&ctx, "tracepoint {{tracepoint_name}} called");
    Ok(0)
}
{%- when "perf_event" %}
use aya_bpf::{
    helpers::bpf_get_smp_processor_id, macros::perf_event, programs::PerfEventContext, BpfContext,
};
use aya_log_ebpf::info;

#[perf_event]
pub fn {{crate_name}}(ctx: PerfEventContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_{{crate_name}}(ctx: PerfEventContext) -> Result<u32, u32> {
    let cpu = unsafe { bpf_get_smp_processor_id() };
    match ctx.pid() {
        0 => info!(
            &ctx,
            "perf_event 'perftest' triggered on CPU {}, running a kernel task", cpu
        ),
        pid => info!(
            &ctx,
            "perf_event 'perftest' triggered on CPU {}, running PID {}", cpu, pid
        ),
    }

    Ok(0)
}
{%- endcase %}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
