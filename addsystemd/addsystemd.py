#!/usr/bin/env python3
"""Utility to create and enable a systemd service for an arbitrary program."""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from shutil import which

UNIT_DIR = Path("/etc/systemd/system")
DEFAULT_RESTART = "on-failure"
DEFAULT_RESTART_SEC = 5
SYSTEMCTL_BIN = which("systemctl")


class AddSystemdError(Exception):
    """Base error for addsystemd failures."""


@dataclass
class ServiceSpec:
    name: str
    description: str
    exec_start: str
    user: str
    working_dir: str | None


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a systemd unit file for a program, enable it, and start it.",
    )
    parser.add_argument(
        "--prog",
        required=True,
        help="Absolute path to the program binary or script to manage via systemd",
    )
    parser.add_argument(
        "--progargs",
        default="",
        help="Arguments passed to the program (use quotes if providing multiple arguments)",
    )
    parser.add_argument(
        "--service-name",
        help="Explicit name for the systemd service (without .service extension)",
    )
    parser.add_argument(
        "--description",
        help="Unit description shown by systemctl",
    )
    parser.add_argument(
        "--working-dir",
        help="Working directory for the service (defaults to the program's directory)",
    )
    parser.add_argument(
        "--user",
        default="root",
        help="User account the service should run as (default: root)",
    )
    parser.add_argument(
        "--restart",
        default=DEFAULT_RESTART,
        help=f"Value for Restart= in the service unit (default: {DEFAULT_RESTART})",
    )
    parser.add_argument(
        "--restart-sec",
        type=int,
        default=DEFAULT_RESTART_SEC,
        help=f"Seconds before restarting the service (default: {DEFAULT_RESTART_SEC})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing unit file if one already exists",
    )
    parser.add_argument(
        "--no-enable",
        action="store_true",
        help="Create the unit file but skip enabling it",
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Create (and optionally enable) the unit file but skip starting it",
    )

    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        parser.error("addsystemd must be run as root to write to /etc/systemd/system and call systemctl")

    if SYSTEMCTL_BIN is None:
        parser.error("systemctl binary not found in PATH")

    return args


def validate_program(path_str: str) -> Path:
    path = Path(path_str).expanduser()
    if not path.is_absolute():
        raise AddSystemdError("--prog must be an absolute path")
    if not path.exists():
        raise AddSystemdError(f"Program '{path}' does not exist")
    if path.is_dir():
        raise AddSystemdError(f"Program path '{path}' is a directory")
    if not os.access(path, os.X_OK):
        raise AddSystemdError(f"Program '{path}' is not executable")
    return path.resolve()


def normalise_service_name(explicit: str | None, program: Path) -> str:
    name = explicit or program.stem
    sanitized = "".join(ch for ch in name if ch.isalnum() or ch in ("-", "_"))
    if not sanitized:
        raise AddSystemdError("Service name becomes empty after sanitisation; provide a valid --service-name")
    return sanitized


def build_exec_start(prog: Path, prog_args: str) -> str:
    parts = [str(prog)]
    if prog_args:
        parts.extend(shlex.split(prog_args))
    return shlex.join(parts)


def build_description(description: str | None, prog: Path) -> str:
    if description:
        return description
    return f"Custom service for {prog.name}"


def build_spec(args: argparse.Namespace) -> ServiceSpec:
    prog_path = validate_program(args.prog)
    service_name = normalise_service_name(args.service_name, prog_path)
    exec_start = build_exec_start(prog_path, args.progargs)
    description = build_description(args.description, prog_path)
    working_dir = args.working_dir or str(prog_path.parent)

    if args.working_dir:
        wd_path = Path(args.working_dir).expanduser()
        if not wd_path.exists():
            raise AddSystemdError(f"Working directory '{wd_path}' does not exist")
        if not wd_path.is_dir():
            raise AddSystemdError(f"Working directory '{wd_path}' is not a directory")
        working_dir = str(wd_path.resolve())

    return ServiceSpec(
        name=service_name,
        description=description,
        exec_start=exec_start,
        user=args.user,
        working_dir=working_dir,
    )


def unit_file_content(spec: ServiceSpec, restart: str, restart_sec: int) -> str:
    lines = [
        "[Unit]",
        f"Description={spec.description}",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"User={spec.user}",
        f"WorkingDirectory={spec.working_dir}",
        f"ExecStart={spec.exec_start}",
        f"Restart={restart}",
        f"RestartSec={restart_sec}",
        "StandardOutput=journal",
        "StandardError=journal",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ]
    return "\n".join(lines)


def write_unit_file(spec: ServiceSpec, content: str, force: bool) -> Path:
    UNIT_DIR.mkdir(parents=True, exist_ok=True)
    unit_path = UNIT_DIR / f"{spec.name}.service"
    if unit_path.exists() and not force:
        raise AddSystemdError(
            f"Unit file '{unit_path}' already exists. Use --force to overwrite or choose a different --service-name."
        )
    unit_path.write_text(content)
    unit_path.chmod(0o644)
    return unit_path


def run_systemctl(args: list[str]) -> None:
    assert SYSTEMCTL_BIN is not None
    result = subprocess.run([SYSTEMCTL_BIN, *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise AddSystemdError(
            f"systemctl {' '.join(args)} failed with code {result.returncode}: {result.stderr.strip()}"
        )


def enable_and_start(service_name: str, skip_enable: bool, skip_start: bool) -> None:
    run_systemctl(["daemon-reload"])
    if not skip_enable:
        run_systemctl(["enable", f"{service_name}.service"])
    if not skip_start:
        run_systemctl(["start", f"{service_name}.service"])


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    try:
        args = parse_arguments(argv)
        spec = build_spec(args)
        content = unit_file_content(spec, args.restart, args.restart_sec)
        unit_path = write_unit_file(spec, content, args.force)
        enable_and_start(spec.name, args.no_enable, args.no_start)
        print(f"Created {unit_path}")
        if args.no_enable:
            print("Skipped enabling the service (--no-enable)")
        if args.no_start:
            print("Skipped starting the service (--no-start)")
        if not args.no_enable:
            print(f"Service {spec.name}.service enabled")
        if not args.no_start:
            print(f"Service {spec.name}.service started")
        return 0
    except AddSystemdError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"systemctl command failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
