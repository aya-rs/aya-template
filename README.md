# {{project-name}}

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
pushd {{project-name}}-ebpf
cargo +nightly build
popd
```

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo run --package {{project-name}} -bin {{project-name}}
```