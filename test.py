#!/usr/bin/env python3

import argparse
import os
import platform
import signal
import subprocess
import sys
import tempfile
from typing import TypedDict

if platform.system() == "Linux":
    import asyncio


class SubprocessArgs(TypedDict, total=False):
    cwd: str
    env: dict[str, str]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate and build a Rust project using cargo."
    )
    parser.add_argument("template_dir", help="Template directory")
    parser.add_argument("program_type", help="Program type")
    args = parser.parse_args()

    match args.program_type:
        case "cgroup_sockopt":
            additional_args = ["-d", "sockopt_target=getsockopt"]
        case "classifier", "cgroup_skb":
            additional_args = ["-d", "direction=Ingress"]
        case "fentry", "fexit":
            additional_args = ["-d", "fn_name=try_to_wake_up"]
        case "kprobe", "kretprobe":
            additional_args = ["-d", "kprobe=do_unlinkat"]
        case "lsm":
            additional_args = ["-d", "lsm_hook=file_open"]
        case "raw_tracepoint":
            additional_args = ["-d", "tracepoint_name=sys_enter"]
        case "sk_msg":
            additional_args = ["-d", "sock_map=SOCK_MAP"]
        case "tp_btf":
            additional_args = ["-d", "tracepoint_name=net_dev_queue"]
        case "tracepoint":
            additional_args = [
                "-d",
                "tracepoint_category=net",
                "-d",
                "tracepoint_name=net_dev_queue",
            ]
        case "uprobe", "uretprobe":
            additional_args = [
                "-d",
                "uprobe_target=/proc/self/exe",
                "-d",
                "uprobe_fn_name=main",
            ]
        case _:
            additional_args = []

    CRATE_NAME = "aya-test-crate"
    with tempfile.TemporaryDirectory() as tmp_dir:
        cmds: list[tuple[list[str], SubprocessArgs]] = [
            (
                [
                    "cargo",
                    "generate",
                    "--path",
                    args.template_dir,
                    "-n",
                    CRATE_NAME,
                    "-d",
                    f"program_type={args.program_type}",
                ]
                + additional_args,
                {"cwd": tmp_dir},
            ),
        ]
        project_dir = os.path.join(tmp_dir, CRATE_NAME)
        match platform.system():
            case "Linux":
                cmds.extend(
                    (cmd, {"cwd": project_dir})
                    for cmd in (
                        ["cargo", "+nightly", "fmt", "--all", "--", "--check"],
                        ["cargo", "build", "--package", CRATE_NAME],
                        ["cargo", "build", "--package", CRATE_NAME, "--release"],
                        # We cannot run clippy over the whole workspace at once due to feature unification.
                        # Since both ${CRATE_NAME} and ${CRATE_NAME}-ebpf depend on ${CRATE_NAME}-common and
                        # ${CRATE_NAME} activates ${CRATE_NAME}-common's aya dependency, we end up trying to
                        # compile the panic handler twice: once from the bpf program, and again from std via
                        # aya.
                        [
                            "cargo",
                            "--exclude",
                            f"{CRATE_NAME}-ebpf",
                            "--all-targets",
                            "--workspace",
                            "--",
                            "--deny",
                            "warnings",
                        ],
                        [
                            "cargo",
                            "--package",
                            f"{CRATE_NAME}-ebpf",
                            "--all-targets",
                            "--",
                            "--deny",
                            "warnings",
                        ],
                    )
                )
            case "Darwin":
                arch = platform.machine()
                if arch == "arm64":
                    arch = "aarch64"
                target = f"{arch}-unknown-linux-musl"
                cmds.append(
                    (
                        [
                            "cargo",
                            "build",
                            "--package",
                            CRATE_NAME,
                            "--release",
                            "--target",
                            target,
                            "--config",
                            f'target.{target}.linker = "rust-lld"',
                        ],
                        {
                            "cwd": project_dir,
                            "env": os.environ
                            | {
                                "AYA_BUILD_EBPF": "true",
                                "CC": f"{arch}-linux-musl-gcc",
                            },
                        },
                    )
                )

        for cmd, kwargs in cmds:
            print(f"Running command: {' '.join(cmd)} with kwargs: {kwargs}")
            subprocess.check_call(cmd, **kwargs)

        if platform.system() == "Linux":

            async def run():
                async with asyncio.create_subprocess_exec(
                    "cargo",
                    "xtask",
                    "run",
                    cwd=project_dir,
                    stdin=subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    text=True,
                ) as process:
                    async with asyncio.timeout(30):
                        for line in process.stdout:
                            sys.stdout.write(line)
                            if "Waiting for Ctrl-C" in line:
                                process.send_signal(signal.SIGINT)
                        retcode = await process.wait()
                        if retcode != 0:
                            raise subprocess.CalledProcessError(retcode, process.args)

            asyncio.run(run())


if __name__ == "__main__":
    main()
