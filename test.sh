#!/usr/bin/env bash

set -eux

TEMPLATE_DIR=$1
if [ -z "${TEMPLATE_DIR}" ]; then
  echo "template dir required"
  exit 1
fi
PROG_TYPE=$2
if [ -z "${PROG_TYPE}" ]; then
  echo "program type required"
  exit 1
fi
CRATE_NAME=aya-test-crate

case ${PROG_TYPE} in
"cgroup_sockopt")
  ADDITIONAL_ARGS=(-d sockopt_target=getsockopt)
  ;;
"classifier" | "cgroup_skb")
  ADDITIONAL_ARGS=(-d direction=Ingress)
  ;;
"fentry" | "fexit")
  ADDITIONAL_ARGS=(-d fn_name=try_to_wake_up)
  ;;
"kprobe" | "kretprobe")
  ADDITIONAL_ARGS=(-d kprobe=do_unlinkat)
  ;;
"lsm")
  ADDITIONAL_ARGS=(-d lsm_hook=file_open)
  ;;
"raw_tracepoint")
  ADDITIONAL_ARGS=(-d tracepoint_name=sys_enter)
  ;;
"sk_msg")
  ADDITIONAL_ARGS=(-d sock_map=SOCK_MAP)
  ;;
"tp_btf")
  ADDITIONAL_ARGS=(-d tracepoint_name=net_dev_queue)
  ;;
"tracepoint")
  ADDITIONAL_ARGS=(-d tracepoint_category=net -d tracepoint_name=net_dev_queue)
  ;;
"uprobe" | "uretprobe")
  ADDITIONAL_ARGS=(-d uprobe_target=/proc/self/exe -d uprobe_fn_name=main)
  ;;
*)
  ADDITIONAL_ARGS=()
  ;;
esac

TMP_DIR=$(mktemp -d)
clean_up() {
  # shellcheck disable=SC2317
  rm -rf "${TMP_DIR}"
}
trap clean_up EXIT

pushd "${TMP_DIR}"
cargo generate --path "${TEMPLATE_DIR}" -n "${CRATE_NAME}" -d program_type="${PROG_TYPE}" "${ADDITIONAL_ARGS[@]}"
pushd "${CRATE_NAME}"

OS=$(uname)
case $OS in
"Darwin")
  ARCH=$(uname -m)
  if [[ "$ARCH" == "arm64" ]]; then
    ARCH="aarch64"
  fi
  TARGET=${ARCH}-unknown-linux-musl
  CC=${ARCH}-linux-musl-gcc cargo build --package "${CRATE_NAME}" --release \
    --target="${TARGET}" \
    --config=target."${TARGET}".linker=\""${ARCH}"-linux-musl-gcc\"
  ;;
"Linux")
  cargo +nightly fmt --all -- --check
  cargo build --package "${CRATE_NAME}"
  cargo build --package "${CRATE_NAME}" --release
  # We cannot run clippy over the whole workspace at once due to feature unification. Since both
  # ${CRATE_NAME} and ${CRATE_NAME}-ebpf depend on ${CRATE_NAME}-common and ${CRATE_NAME} activates
  # ${CRATE_NAME}-common's aya dependency, we end up trying to compile the panic handler twice: once
  # from the bpf program, and again from std via aya.
  #
  # `-C panic=abort` because "unwinding panics are not supported without std";
  # integration-ebpf contains `#[no_std]` binaries.
  #
  # `-Zpanic_abort_tests` because "building tests with panic=abort is not supported without
  # `-Zpanic_abort_tests`"; Cargo does this automatically when panic=abort is set via profile
  # but we want to preserve unwinding at runtime - here we are just running clippy so we don't
  # care about unwinding behavior.
  #
  # `+nightly` because "the option `Z` is only accepted on the nightly compiler".
  cargo +nightly clippy --exclude "${CRATE_NAME}-ebpf" --all-targets --workspace -- --deny warnings
  cargo +nightly clippy --package "${CRATE_NAME}-ebpf" --all-targets -- --deny warnings -C panic=abort -Zpanic_abort_tests

  expect <<EOF
    set timeout 30        ;# Increase timeout if necessary
    spawn cargo run --release --config "target.\"cfg(all())\".runner=\"sudo -E\""
    expect {
      -re "Waiting for Ctrl-C.*" {
        send -- \003      ;# Send Ctrl-C
      }
      timeout {
        puts "Error: Timed out waiting for 'Waiting for Ctrl-C...'"
        exit 1
      }
      eof {
        puts "Error: Process exited prematurely"
        exit 1
      }
    }

    expect {
      -re "Exiting.*" { }
      eof { }
    }
EOF
  ;;
*)
  echo "Unsupported OS: ${OS}"
  exit 1
  ;;
esac
