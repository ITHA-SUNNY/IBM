"""Threshold — environment / platform detection (M5).

Judges verify that the demo actually runs on IBM Z (LinuxONE, s390x). This
module reads the *real* host at runtime so the console can prove it — no
hard-coded claims. On the mainframe it reports s390x; on a dev laptop it says so
plainly.

Pure standard library, no Streamlit dependency, so it is easy to unit-test.
"""

from __future__ import annotations

import os
import platform
from dataclasses import asdict, dataclass
from pathlib import Path

# IBM Z / LinuxONE reports these machine types from `uname -m`.
S390_ARCHES = {"s390x", "s390", "s390x64"}


@dataclass
class PlatformInfo:
    machine: str
    system: str
    release: str
    node: str
    python_version: str
    cpu_count: int
    distro: str
    on_linuxone: bool

    def as_dict(self) -> dict:
        return asdict(self)


def _read_os_release() -> str:
    for path in (Path("/etc/os-release"), Path("/usr/lib/os-release")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    return ""


def _read_cpu_machine() -> str:
    """`uname -m` equivalent; also peek at /proc/cpuinfo when present."""
    machine = platform.machine() or ""
    if machine:
        return machine
    try:
        for line in Path("/proc/cpuinfo").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            key, _, value = line.partition(":")
            if key.strip().lower() in {"machine", "architecture", "cpu architecture"}:
                return value.strip()
    except OSError:
        pass
    return "unknown"


def detect_platform() -> PlatformInfo:
    machine = _read_cpu_machine()
    system = platform.system() or "unknown"
    return PlatformInfo(
        machine=machine,
        system=system,
        release=platform.release() or "unknown",
        node=platform.node() or "unknown",
        python_version=platform.python_version(),
        cpu_count=os.cpu_count() or 0,
        distro=_read_os_release(),
        on_linuxone=(machine.lower() in S390_ARCHES and system.lower() == "linux"),
    )
