import os
import socket
import subprocess
import sys
import time
from pathlib import Path


class ProcessManager:
    """Manages starting and stopping backend scenario applications as subprocesses."""

    def __init__(self, port: int, workdir: Path, app_module: str = "main:app") -> None:
        self.port: int = port
        self.workdir: Path = Path(workdir).resolve()
        self.app_module: str = app_module
        self.process: subprocess.Popen | None = None

    def _is_port_open(self) -> bool:
        """Checks if the port is already listening."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)
            return sock.connect_ex(("127.0.0.1", self.port)) == 0

    def start(self, env_vars: dict[str, str] | None = None) -> None:
        """Starts the uvicorn subprocess and waits for the port to open."""
        if self._is_port_open():
            # If the port is already in use, force close it using lsof/kill to prevent conflicts
            self.stop_lsof()

        # Try to find scenario-specific virtual environment uvicorn
        uvicorn_bin = self.workdir / "venv" / "bin" / "uvicorn"
        if not uvicorn_bin.exists():
            # Try Windows path
            uvicorn_bin = self.workdir / "venv" / "Scripts" / "uvicorn.exe"

        # Fallback to system uvicorn (which is available in the test runner/CI environment)
        cmd = [str(uvicorn_bin)] if uvicorn_bin.exists() else ["uvicorn"]
        cmd.extend([self.app_module, "--host", "127.0.0.1", "--port", str(self.port)])

        env = {**os.environ}
        if env_vars:
            env.update(env_vars)

        # For Module 04 and other apps requiring session key or encryption keys
        if "SESSION_SECRET_KEY" not in env:
            env["SESSION_SECRET_KEY"] = "test-secret-key-12345"
        if "ENCRYPTION_KEY" not in env:
            # Generate valid Fernet-compatible key
            import base64
            env["ENCRYPTION_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()

        self.process = subprocess.Popen(
            cmd,
            cwd=str(self.workdir),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for the server to bind to the port
        for _ in range(50):  # 5 seconds max
            if self._is_port_open():
                return
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"Process failed to start on port {self.port}. Exit code: {self.process.returncode}"
                )
            time.sleep(0.1)

        self.stop()
        raise TimeoutError(f"Timed out waiting for uvicorn on port {self.port} to start.")

    def stop(self) -> None:
        """Gracefully terminates the subprocess, with a fallback force kill if needed."""
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    self.process.kill()
            self.process = None

        # Always ensure the port is completely free
        self.stop_lsof()

    def stop_lsof(self) -> None:
        """Forces cleanup of any remaining processes binding to the port using lsof/kill (non-Windows)."""
        if sys.platform != "win32":
            try:
                out = subprocess.run(
                    ["lsof", "-ti", f"tcp:{self.port}"],
                    capture_output=True,
                    text=True,
                    timeout=2.0
                )
                pids = [p.strip() for p in out.stdout.split() if p.strip()]
                for pid in pids:
                    subprocess.run(["kill", "-9", pid], timeout=2.0)
            except Exception:
                pass
