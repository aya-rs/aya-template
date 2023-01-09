#!/bin/bash

set -ex

TEMPLATE_DIR=$1
if [ -z "$TEMPLATE_DIR" ]; then echo "template dir required"; exit 1; fi
PROG_TYPE=$2
if [ -z "$PROG_TYPE" ]; then echo "program type required"; exit 1; fi

TMP_DIR=$(mktemp -d)
clean_up() {
    rm -rf "${TMP_DIR}"
}
trap clean_up EXIT

pushd $TMP_DIR
case "$PROG_TYPE" in
    "kprobe"|"kretprobe")
        ADDITIONAL_ARGS="-d kprobe=test"
        ;;
    "fentry"|"fexit")
        ADDITIONAL_ARGS="-d fn_name=try_to_wake_up"
        ;;
    "uprobe"|"uretprobe")
        ADDITIONAL_ARGS="-d uprobe_target=testlib -d uprobe_fn_name=testfn"
        ;;
    "tracepoint")
	    ADDITIONAL_ARGS="-d tracepoint_category=net -d tracepoint_name=net_dev_queue"
        ;;
    "classifier"|"cgroup_skb")
        ADDITIONAL_ARGS="-d direction=Ingress"
        ;;
    "sk_msg")
        ADDITIONAL_ARGS="-d sock_map=TEST"
        ;;
    "lsm")
        ADDITIONAL_ARGS="-d lsm_hook=file_open"
        ;;
    "tp_btf")
	    ADDITIONAL_ARGS="-d tracepoint_name=net_dev_queue"
        ;;
    "cgroup_sockopt")
	    ADDITIONAL_ARGS="-d sockopt_target=getsockopt"
        ;;
    "raw_tracepoint")
        ADDITIONAL_ARGS="-d tracepoint_name=sys_enter"
        ;;
    *)
        ADDITIONAL_ARGS=''
esac

cargo generate -v --path "${TEMPLATE_DIR}" -n test -d program_type="${PROG_TYPE}" ${ADDITIONAL_ARGS}
pushd test
cargo xtask build-ebpf
cargo build
popd
exit 0
