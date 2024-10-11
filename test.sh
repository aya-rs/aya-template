#!/bin/bash

set -ex

TEMPLATE_DIR=$1
if [ -z "${TEMPLATE_DIR}" ]; then echo "template dir required"; exit 1; fi
PROG_TYPE=$2
if [ -z "${PROG_TYPE}" ]; then echo "program type required"; exit 1; fi

TMP_DIR=$(mktemp -d)
clean_up() {
    # shellcheck disable=SC2317
    rm -rf "${TMP_DIR}"
}
trap clean_up EXIT

pushd "${TMP_DIR}"
case "${PROG_TYPE}" in
    "cgroup_sockopt")
	    ADDITIONAL_ARGS=(-d sockopt_target=getsockopt)
        ;;
    "classifier"|"cgroup_skb")
        ADDITIONAL_ARGS=(-d direction=Ingress)
        ;;
    "fentry"|"fexit")
        ADDITIONAL_ARGS=(-d fn_name=try_to_wake_up)
        ;;
    "kprobe"|"kretprobe")
        ADDITIONAL_ARGS=(-d kprobe=test)
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
    "uprobe"|"uretprobe")
        ADDITIONAL_ARGS=(-d uprobe_target=testlib -d uprobe_fn_name=testfn)
        ;;
    *)
        ADDITIONAL_ARGS=()
esac

cargo generate --path "${TEMPLATE_DIR}" -n test -d program_type="${PROG_TYPE}" "${ADDITIONAL_ARGS[@]}"
pushd test
cargo +nightly fmt --all -- --check
cargo build --package test
cargo build --package test --release
# We cannot run clippy over the whole workspace at once due to feature unification. Since both test
# and test-ebpf depend on test-common and test activates test-common's aya dependency, we end up
# trying to compile the panic handler twice: once from the bpf program, and again from std via aya.
cargo clippy --exclude test-ebpf --all-targets --workspace -- --deny warnings
cargo clippy --package test-ebpf --all-targets -- --deny warnings
popd
exit 0
