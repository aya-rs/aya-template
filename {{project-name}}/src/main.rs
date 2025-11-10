#[rustfmt::skip]
use log::debug;
use std::fs;

fn main() -> anyhow::Result<()> {
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

    let src = concat!(env!("OUT_DIR"), "/{{project-name}}");
    let dst = "{{project-name}}-go/.ebpf/{{project-name}}";

    fs::copy(src, dst)?;
    Ok(())
}
