#![no_std]
#![no_main]

use core::mem;
use memoffset::offset_of;

use aya_bpf::{
    bindings::xdp_action::{XDP_DROP, XDP_PASS},
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

mod net;
use net::{iphdr, tcphdr};

use crate::net::ethhdr;

#[map]
static mut BLOCK_PORTS: HashMap<u16, u16> = HashMap::with_max_entries(1024, 0);

#[xdp(name = "xdp_fw")]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => XDP_PASS,
    }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    if let Some(port) = tcp_dest_port(&ctx)? {
        if block_port(port) {
            return Ok(XDP_DROP);
        }
    }

    Ok(XDP_PASS)
}

fn tcp_dest_port(ctx: &XdpContext) -> Result<Option<u16>, ()> {
    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    let ip_proto: u8 = unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? };

    if h_proto != ETH_P_IP || ip_proto != IPPROTO_TCP {
        return Ok(None);
    }

    let dest = u16::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?
    });

    Ok(Some(dest))
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn block_port(port: u16) -> bool {
    unsafe { BLOCK_PORTS.get(&port).is_some() }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
