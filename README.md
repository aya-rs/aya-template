# {{project-name}}

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with `xtask run`.

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program. When not using `xtask run`, eBPF code generation is skipped for a faster developer
experience; this compromise necessitates the use of `xtask` to actually build the eBPF.
