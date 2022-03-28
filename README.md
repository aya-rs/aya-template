# {{project-name}}

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

You may change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo xtask run
```
