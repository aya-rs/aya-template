use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

#[derive(Debug, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl Architecture {
    pub fn as_str(&self) -> &'static str {
        match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        }
    }
}

impl std::str::FromStr for Architecture {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target"),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,
    /// Build the release target
    #[clap(long)]
    pub release: bool,
}

pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    let Options { target, release } = opts;

    let mut cmd = Command::new("cargo");
    cmd.current_dir("{{project-name}}-ebpf")
        // Command::new creates a child process which inherits all env variables. This means env
        // vars set by the cargo xtask command are also inherited. RUSTUP_TOOLCHAIN is removed so
        // the rust-toolchain.toml file in the -ebpf folder is honored.
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(["build", "--target", target.as_str()]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to build bpf program")?;
    anyhow::ensure!(status.success(), "failed to build bpf program: {}", status);

    Ok(())
}
