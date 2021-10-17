#![no_std]
#![no_main]
{% case program_type -%}
{%- when "kprobe" %}
use aya_bpf::{
    macros::kprobe,
    programs::ProbeContext,
};

#[kprobe(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) -> u32 {
    match unsafe { try_{{crate_name}}(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_{{crate_name}}(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}
{%- when "kretprobe" %}
use aya_bpf::{
    macros::kretprobe,
    programs::ProbeContext,
};

#[kretprobe(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) -> u32 {
    match unsafe { try_{{crate_name}}(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_{{crate_name}}(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}
{%- when "uprobe" %}
use aya_bpf::{
    macros::uprobe,
    programs::ProbeContext,
};

#[uprobe(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) -> u32 {
    match unsafe { try_{{crate_name}}(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_{{crate_name}}(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}
{%- when "uretprobe" %}
use aya_bpf::{
    macros::uretprobe,
    programs::ProbeContext,
};

#[uretprobe(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: ProbeContext) -> u32 {
    match unsafe { try_{{crate_name}}(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_{{crate_name}}(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}
{%- when "sock_ops" %}
use aya_bpf::{
    macros::sock_ops,
    programs::SockOpsContext,
};

#[sock_ops(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: SockOpsContext) -> u32 {
    match unsafe { try_{{crate_name}}(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_{{crate_name}}(_ctx: SockOpsContext) -> Result<u32, u32> {
    Ok(0)
}
{%- when "sk_msg" %}
use aya_bpf::{
    macros::{map, sk_msg},
    maps::SockHash,
    programs::SkMsgContext,
};
use {{crate_name}}_common::SockKey;

#[map(name="{{sock_map}}")]
static mut {{sock_map}}: SockHash<SockKey> = SockHash::<SockKey>::with_max_entries(1024, 0);

#[sk_msg(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: SkMsgContext) -> u32 {
    match unsafe { try_{{crate_name}}(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_{{crate_name}}(_ctx: SkMsgContext) -> Result<u32, u32> {
    Ok(0)
}
{%- when "xdp" %}
use aya_bpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};

#[xdp(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: XdpContext) -> u32 {
    match unsafe { try_{{crate_name}}(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_{{crate_name}}(_ctx: XdpContext) -> Result<u32, u32> {
    Ok(xdp_action::XDP_PASS)
}
{%- when "classifier" %}
use aya_bpf::{
    macros::classifier,
    programs::SkSkbContext,
};

#[classifier(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: SkSkbContext) -> i32 {
    match unsafe { try_{{crate_name}}(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_{{crate_name}}(_ctx: SkSkbContext) -> Result<i32, i32> {
    Ok(0)
}
{%- when "cgroup_skb" %}
use aya_bpf::{
    macros::cgroup_skb,
    programs::SkSkbContext,
};

#[cgroup_skb(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: SkSkbContext) -> i32 {
    match unsafe { try_{{crate_name}}(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_{{crate_name}}(_ctx: SkSkbContext) -> Result<i32, i32> {
    Ok(0)
}
{%- when "tracepoint" %}
use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext,
};

#[tracepoint(name="{{crate_name}}")]
pub fn {{crate_name}}(ctx: TracePointContext) -> u32 {
    match unsafe { try_{{crate_name}}(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_{{crate_name}}(_ctx: TracePointContext) -> Result<u32, u32> {
    Ok(0)
}
{%- endcase %}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}