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
    "cgroup_sockopt")
	    ADDITIONAL_ARGS="-d sockopt_target=getsockopt"
        ;;
    "classifier"|"cgroup_skb")
        ADDITIONAL_ARGS="-d direction=Ingress"
        ;;
    "fentry"|"fexit")
        ADDITIONAL_ARGS="-d fn_name=try_to_wake_up"
        ;;
    "kprobe"|"kretprobe")
        ADDITIONAL_ARGS="-d kprobe=test"
        ;;
    "lsm")
        ADDITIONAL_ARGS="-d lsm_hook=file_open"
        ;;
    "raw_tracepoint")
        ADDITIONAL_ARGS="-d tracepoint_name=sys_enter"
        ;;
    "sk_msg")
        ADDITIONAL_ARGS="-d sock_map=TEST"
        ;;
    "tp_btf")
	    ADDITIONAL_ARGS="-d tracepoint_name=net_dev_queue"
        ;;
    "tracepoint")
	    ADDITIONAL_ARGS="-d tracepoint_category=net -d tracepoint_name=net_dev_queue"
        ;;
    "uprobe"|"uretprobe")
        ADDITIONAL_ARGS="-d uprobe_target=testlib -d uprobe_fn_name=testfn"
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
