use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
}

/// Build our ebpf program and the userspace program.
pub fn build(opts: Options) -> Result<(), anyhow::Error> {
    let Options {
        bpf_target,
        release,
    } = opts;

    // Build our ebpf program.
    build_ebpf(BuildOptions {
        target: bpf_target,
        release,
    })?;

    // Build our userspace program.
    let mut cmd = Command::new("cargo");
    cmd.arg("build");
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().context("failed to build userspace")?;
    anyhow::ensure!(status.success(), "failed to build userspace program: {}", status);

    Ok(())
}
