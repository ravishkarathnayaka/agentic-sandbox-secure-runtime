"""Unit tests verifying Linux seccomp syscall filtering and container hardening."""

import json

from runtime.backends.container_backend import ContainerBackend
from runtime.config import settings
from runtime.core.session import Session


def test_seccomp_profile_validity_and_structure():
    """Verify seccomp_profile.json parses cleanly and includes required architecture definitions."""
    profile_path = settings.SECCOMP_PROFILE_PATH
    assert profile_path.exists(), f"Seccomp profile not found at {profile_path}"

    with open(profile_path, "r", encoding="utf-8") as f:
        profile = json.load(f)

    assert "defaultAction" in profile
    assert "architectures" in profile
    assert "syscalls" in profile

    required_archs = {"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"}
    assert required_archs.issubset(set(profile["architectures"]))


def test_dangerous_syscalls_explicitly_blocked():
    """Verify that dangerous kernel exploitation and breakout syscalls are explicitly filtered."""
    with open(settings.SECCOMP_PROFILE_PATH, "r", encoding="utf-8") as f:
        profile = json.load(f)

    blocked_syscalls = set()
    for entry in profile.get("syscalls", []):
        action = entry.get("action")
        if action in ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL"):
            for name in entry.get("names", []):
                blocked_syscalls.add(name)

    mandatory_blocked = [
        "ptrace",          # Process tracing and cross-process code injection
        "bpf",             # eBPF kernel program attachment
        "mount",           # Filesystem mounting
        "umount",          # Filesystem unmounting
        "reboot",          # System reboot
        "keyctl",          # Kernel keyring modification
        "kexec_load",      # Kernel hot swapping
        "init_module",     # Kernel module loading
        "delete_module",   # Kernel module unloading
        "pivot_root",      # Container root directory pivot
        "setns",           # Namespace joining / container escape
        "unshare",         # Namespace detachment
        "io_uring_setup",  # io_uring attack surface
        "userfaultfd",     # Kernel memory exploit primitive
    ]

    for syscall in mandatory_blocked:
        assert syscall in blocked_syscalls, f"Critical syscall '{syscall}' must be blocked in seccomp profile!"


def test_container_hardening_flags_applied(tmp_path):
    """Verify that ContainerBackend generates maximum isolation options."""
    backend = ContainerBackend()
    session = Session(session_id="test_hardening_session", base_dir=tmp_path)
    session.create()

    config = backend.build_container_config(
        command=["python3", "-c", "print(1)"],
        session=session,
        memory_mb=256,
        cpu_quota=0.5,
        allow_network=False,
    )

    # 1. Dropped Linux Capabilities
    assert config["cap_drop"] == ["ALL"]

    # 2. Non-root unprivileged UID
    assert config["user"] == "65534:65534"

    # 3. Read-only root filesystem
    assert config["read_only"] is True

    # 4. Network isolation disabled by default
    assert config["network_mode"] == "none"

    # 5. Cgroups Memory and CPU bounds
    assert config["mem_limit"] == 256 * 1024 * 1024
    assert config["memswap_limit"] == 256 * 1024 * 1024
    assert config["nano_cpus"] == 500_000_000

    # 6. Seccomp profile attached
    assert any("seccomp" in opt for opt in config["security_opt"])

    # 7. Workspace mounted and tmpfs mounted
    assert "/workspace" in [v["bind"] for v in config["volumes"].values()]
    assert "/tmp" in config["tmpfs"]

    session.destroy()
