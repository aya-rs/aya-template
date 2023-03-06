#![no_std]
#![no_main]

{% case program_type -%}
{%- when "kprobe" %}
use aya_bpf::{
    cty::c_long,
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[kprobe(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) {
    let _ = try_{{crate_name}}(ctx);
}

fn try_{{crate_name}}(ctx: ProbeContext) -> Result<(), c_long> {
    info!(&ctx, "function {{kprobe}} called");
    Ok(())
}
{%- when "kretprobe" %}
use aya_bpf::{
    cty::c_long,
    macros::kretprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[kretprobe(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) {
    let _ = try_{{crate_name}}(ctx);
}

fn try_{{crate_name}}(ctx: ProbeContext) -> Result<(), c_long> {
    info!(&ctx, "function {{kprobe}} called");
    Ok(())
}
{%- when "fentry" %}
use aya_bpf::{
    cty::c_long,
    macros::fentry,
    programs::FEntryContext,
};
use aya_log_ebpf::info;

#[fentry(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: FEntryContext) {
    let _ = try_{{crate_name}}(ctx);
}

fn try_{{crate_name}}(ctx: FEntryContext) -> Result<(), c_long> {
    info!(&ctx, "function {{fn_name}} called");
    Ok(())
}
{%- when "fexit" %}
use aya_bpf::{
    cty::c_long,
    macros::fexit,
    programs::FExitContext,
};
use aya_log_ebpf::info;

#[fexit(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: FExitContext) {
    let _ = try_{{crate_name}}(ctx);
}

fn try_{{crate_name}}(ctx: FExitContext) -> Result<(), c_long> {
    info!(&ctx, "function {{fn_name}} called");
    Ok(())
}
{%- when "uprobe" %}
use aya_bpf::{
    cty::c_long,
    macros::uprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[uprobe(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) {
    let _ = try_{{crate_name}}(ctx);
}

fn try_{{crate_name}}(ctx: ProbeContext) -> Result<(), c_long> {
    info!(&ctx, "function {{uprobe_fn_name}} called by {{uprobe_target}}");
    Ok(())
}
{%- when "uretprobe" %}
use aya_bpf::{
    cty::c_long,
    macros::uretprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[uretprobe(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) {
    let _ = try_{{crate_name}}(ctx);
}

fn try_{{crate_name}}(ctx: ProbeContext) -> Result<(), c_long> {
    info!(&ctx, "function {{uprobe_fn_name}} called by {{uprobe_target}}");
    Ok(())
}
{%- when "sock_ops" %}
use aya_bpf::{
    cty::c_long,
    macros::sock_ops,
    programs::SockOpsContext,
};
use aya_log_ebpf::info;

#[sock_ops(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: SockOpsContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_{{crate_name}}(ctx: SockOpsContext) -> Result<u32, c_long> {
    info!(&ctx, "received TCP connection");
    Ok(0)
}
{%- when "sk_msg" %}
use aya_bpf::{
    cty::c_long,
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
        Err(_) => 1,
    }
}

fn try_{{crate_name}}(ctx: SkMsgContext) -> Result<u32, c_long> {
    info!(&ctx, "received a message on the socket");
    Ok(0)
}
{%- when "xdp" %}
use aya_bpf::{
    bindings::xdp_action,
    cty::c_long,
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;

#[xdp(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: XdpContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_{{crate_name}}(ctx: XdpContext) -> Result<u32, c_long> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}
{%- when "classifier" %}
use aya_bpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    cty::c_long,
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::info;

#[classifier(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: TcContext) -> i32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_{{crate_name}}(ctx: TcContext) -> Result<i32, c_long> {
    info!(&ctx, "received a packet");
    Ok(TC_ACT_PIPE)
}
{%- when "cgroup_skb" %}
use aya_bpf::{
    cty::c_long,
    macros::cgroup_skb,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;

#[cgroup_skb(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: SkBuffContext) -> i32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_{{crate_name}}(ctx: SkBuffContext) -> Result<i32, c_long> {
    info!(&ctx, "received a packet");
    Ok(1)
}
{%- when "tracepoint" %}
use aya_bpf::{
    cty::c_long,
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: TracePointContext) {
    let _ = try_{{crate_name}}(ctx);
}

fn try_{{crate_name}}(ctx: TracePointContext) -> Result<(), c_long> {
    info!(&ctx, "tracepoint {{tracepoint_name}} called");
    Ok(())
}
{%- when "lsm" %}
use aya_bpf::{
    cty::c_long,
    macros::lsm,
    programs::LsmContext,
};
use aya_log_ebpf::info;

#[lsm(name = "{{lsm_hook}}")]
pub fn {{lsm_hook}}(ctx: LsmContext) -> i32 {
    match try_{{lsm_hook}}(ctx) {
        Ok(ret) => ret,
        Err(ret) => 1,
    }
}

fn try_{{lsm_hook}}(ctx: LsmContext) -> Result<i32, c_long> {
    info!(&ctx, "lsm hook {{lsm_hook}} called");
    Ok(0)
}
{%- when "tp_btf" %}
use aya_bpf::{
    cty::c_long,
    macros::btf_tracepoint,
    programs::BtfTracePointContext,
};
use aya_log_ebpf::info;

#[btf_tracepoint(name = "{{tracepoint_name}}")]
pub fn {{tracepoint_name}}(ctx: BtfTracePointContext) {
    let _ = try_{{tracepoint_name}}(ctx);
}

fn try_{{tracepoint_name}}(ctx: BtfTracePointContext) -> Result<(), c_long> {
    info!(&ctx, "tracepoint {{tracepoint_name}} called");
    Ok(())
}
{%- when "socket_filter" %}
use aya_bpf::{
    cty::c_long,
    macros::socket_filter,
    programs::SkBuffContext,
};

#[socket_filter(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: SkBuffContext) -> i64 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_{{crate_name}}(ctx: SkBuffContext) -> Result<i64, c_long> {
    Ok(0)
}
{%- when "cgroup_sysctl" %}
use aya_bpf::{
    cty::c_long,
    macros::cgroup_sysctl,
    programs::SysctlContext,
};
use aya_log_ebpf::info;

#[cgroup_sysctl(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: SysctlContext) -> i32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_{{crate_name}}(ctx: SysctlContext) -> Result<i32, c_long> {
    info!(&ctx, "sysctl operation called");
    Ok(1)
}
{%- when "cgroup_sockopt" %}
use aya_bpf::{
    cty::c_long,
    macros::cgroup_sockopt,
    programs::SockoptContext,
};
use aya_log_ebpf::info;

#[cgroup_sockopt({{sockopt_target}}, name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: SockoptContext) -> i32 {
    match try_{{crate_name}}(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_{{crate_name}}(ctx: SockoptContext) -> Result<i32, c_long> {
    info!(&ctx, "{{sockopt_target}} called");
    Ok(1)
}
{%- when "raw_tracepoint" %}
use aya_bpf::{
    cty::c_long,
    macros::raw_tracepoint,
    programs::RawTracePointContext,
};
use aya_log_ebpf::info;

#[raw_tracepoint(name = "{{crate_name}}")]
pub fn {{crate_name}}(ctx: RawTracePointContext) {
    let _ = try_{{crate_name}}(ctx);
}

fn try_{{crate_name}}(ctx: RawTracePointContext) -> Result<(), c_long> {
    info!(&ctx, "tracepoint {{tracepoint_name}} called");
    Ok(())
}
{%- when "perf_event" %}
use aya_bpf::{
    cty::c_long,
    helpers::bpf_get_smp_processor_id,
    macros::perf_event,
    programs::PerfEventContext,
    BpfContext,
};
use aya_log_ebpf::info;

#[perf_event]
pub fn {{crate_name}}(ctx: PerfEventContext) -> u32 {
    match try_{{crate_name}}(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_{{crate_name}}(ctx: PerfEventContext) -> Result<(), c_long> {
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

    Ok(())
}
{%- endcase %}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
