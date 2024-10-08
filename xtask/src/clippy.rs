use clap::Parser;
use std::{path::PathBuf, process::Command};

#[derive(Debug, Parser)]
pub struct Options {
    /// Clippy will fix as much as it can
    #[clap(long)]
    pub fix: bool,
    /// Clippy will ignore if the directory has uncommitted changes
    #[clap(long)]
    pub allow_dirty: bool,
    /// Clippy will fix staged files
    #[clap(long)]
    pub allow_staged: bool,
}

/// Run Clippy on the project
pub fn run_clippy(opts: Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["clippy"];

    if opts.fix {
        args.push("--fix")
    }
    if opts.allow_dirty {
        args.push("--allow-dirty")
    }
    if opts.allow_staged {
        args.push("--allow-staged")
    }
    let status = Command::new("cargo")
        .current_dir(PathBuf::from("{{project-name}}-ebpf"))
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}
