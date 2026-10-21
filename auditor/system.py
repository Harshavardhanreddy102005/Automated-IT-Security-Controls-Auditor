"""System interaction utilities for safe, read-only command execution and host detection."""

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Union

from auditor.models import SystemInfo


@dataclass
class CommandResult:
    """Outcome of a shell or subprocess execution."""
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    error: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None


def is_windows() -> bool:
    """Return True if running on a Windows operating system."""
    return platform.system().lower() == "windows"


def is_elevated() -> bool:
    """Check if the current process is running with administrator/root privileges."""
    if is_windows():
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except AttributeError:
            return False


def run_command(
    command: Union[str, List[str]],
    timeout: int = 15,
    shell: bool = False,
) -> CommandResult:
    """
    Execute a read-only command safely with a timeout and robust decoding.
    
    Catches timeouts, permission errors, and missing binaries without crashing.
    """
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=shell,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return CommandResult(
            returncode=process.returncode,
            stdout=process.stdout.strip(),
            stderr=process.stderr.strip(),
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr=f"Command timed out after {timeout} seconds",
            timed_out=True,
            error=f"TimeoutExpired: Execution exceeded {timeout}s",
        )
    except FileNotFoundError as exc:
        return CommandResult(
            returncode=127,
            stdout="",
            stderr=str(exc),
            error=f"ExecutableNotFound: {exc}",
        )
    except PermissionError as exc:
        return CommandResult(
            returncode=126,
            stdout="",
            stderr=str(exc),
            error=f"PermissionDenied: {exc}",
        )
    except Exception as exc:
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr=str(exc),
            error=f"UnexpectedExecutionError: {type(exc).__name__}: {exc}",
        )


def run_powershell(command: str, timeout: int = 20) -> CommandResult:
    """
    Execute a PowerShell command safely with execution policy bypass in non-interactive mode.
    """
    if not is_windows() and not shutil.which("powershell") and not shutil.which("pwsh"):
        return CommandResult(
            returncode=127,
            stdout="",
            stderr="PowerShell is not available on this platform",
            error="PowerShellNotFound",
        )

    ps_exe = "powershell" if shutil.which("powershell") else "pwsh"
    cmd = [
        ps_exe,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", command,
    ]
    return run_command(cmd, timeout=timeout)


def get_system_info(python_version: str) -> SystemInfo:
    """Gather host and operating system metadata safely without exposing credentials."""
    hostname = platform.node() or "Unknown-Host"
    current_user = os.environ.get("USERNAME") or os.environ.get("USER") or "Unknown"

    return SystemInfo(
        hostname=hostname,
        os_name=platform.system(),
        os_release=platform.release(),
        os_version=platform.version(),
        os_architecture=platform.machine(),
        python_version=python_version,
        is_elevated=is_elevated(),
        current_user=current_user,
    )
