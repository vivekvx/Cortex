from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Dict, Sequence


class SandboxUnavailableError(RuntimeError):
    pass


RunCommand = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class DockerShellSandbox:
    image: str = "alpine:3.20"
    timeout_seconds: int = 10
    memory: str = "128m"
    cpus: str = "0.5"
    pids_limit: int = 64
    run_command: RunCommand = subprocess.run

    def run(self, command: str) -> Dict[str, Any]:
        args = self._docker_args(command)
        try:
            completed = self.run_command(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise SandboxUnavailableError("docker executable not found") from exc
        except subprocess.TimeoutExpired as exc:
            return {
                "status": "timeout",
                "exit_code": None,
                "stdout": exc.stdout or "",
                "stderr": exc.stderr or "",
                "sandbox": self._metadata(),
            }

        return {
            "status": "completed" if completed.returncode == 0 else "failed",
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "sandbox": self._metadata(),
        }

    def _docker_args(self, command: str) -> Sequence[str]:
        return [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--pids-limit",
            str(self.pids_limit),
            "--memory",
            self.memory,
            "--cpus",
            self.cpus,
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--workdir",
            "/workspace",
            self.image,
            "sh",
            "-lc",
            command,
        ]

    def _metadata(self) -> Dict[str, Any]:
        return {
            "engine": "docker",
            "image": self.image,
            "network": "none",
            "read_only": True,
            "timeout_seconds": self.timeout_seconds,
        }
