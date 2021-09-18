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
    *)
        ADDITIONAL_ARGS=''
esac

cargo generate -v --path "${TEMPLATE_DIR}" -n test -d program_type="${PROG_TYPE}" ${ADDITIONAL_ARGS}
pushd test
cargo build
cargo xtask build-ebpf
popd
exit 0
