from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import requests

SERVER_BINARY = "/app/rpt7_server"
DB_PATH = "/app/data/rpt7.db"
HOST = os.environ.get("RPT7_HOST", "127.0.0.1")
PORT = 8080
BASE_URL = f"http://{HOST}:{PORT}"
STARTUP_TIMEOUT_SEC = 15.0

RPT7RUNNER_UID = 65532
RPT7RUNNER_GID = 65532

startup_error: str | None = None


def privilege_drop_kwargs() -> dict[str, object]:
    if os.getuid() != 0:
        return {}
    return {"user": RPT7RUNNER_UID, "group": RPT7RUNNER_GID, "extra_groups": []}


def wait_for_health(base_url: str, timeout_sec: float = STARTUP_TIMEOUT_SEC) -> str | None:
    deadline = time.monotonic() + timeout_sec
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = requests.get(f"{base_url}/health", timeout=2.0)
            if response.status_code == 200:
                return None
        except requests.RequestException as exc:
            last_error = exc
        time.sleep(0.5)
    return f"{base_url} never became healthy: {last_error}"


@pytest.fixture(scope="session", autouse=True)
def rpt7_server() -> Iterator[None]:
    global startup_error

    process: subprocess.Popen[bytes] | None = None
    if not os.access(SERVER_BINARY, os.X_OK):
        startup_error = f"missing artifact: {SERVER_BINARY}"
    elif not Path(DB_PATH).is_file():
        startup_error = f"missing artifact: {DB_PATH}"
    else:
        env = {key: value for key, value in os.environ.items() if not key.startswith("RPT7_")}
        try:
            process = subprocess.Popen([SERVER_BINARY], env=env, **privilege_drop_kwargs())
        except OSError as exc:
            startup_error = f"could not launch {SERVER_BINARY}: {exc}"
        else:
            startup_error = wait_for_health(BASE_URL)

    try:
        yield
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
