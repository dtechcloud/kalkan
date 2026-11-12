# SPDX-License-Identifier: MIT
"""Shared helpers of the integration tests: the proxy trap of promise 3 (docs/SECURITY.md)."""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable, Iterator

import pytest

#: The proxy variables that the trap sets. Every proxy-aware client (all Go tools, Python, git)
#: sends its connections to the proxy.
PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY")


class TrapProxy:
    """A local TCP server that counts connections and answers nothing useful."""

    def __init__(self) -> None:
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(16)
        self.server.settimeout(0.2)
        self.port = self.server.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.connections: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self.server.accept()
            except OSError:
                continue
            with client:
                client.settimeout(1.0)
                try:
                    self.connections.append(client.recv(512))
                except OSError:
                    self.connections.append(b"")

    def env(self) -> dict[str, str]:
        """Return the proxy variables that point at the trap, with ``NO_PROXY`` empty."""
        return {**dict.fromkeys(PROXY_VARIABLES, self.url), "NO_PROXY": "", "no_proxy": ""}

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self.server.close()


@pytest.fixture
def trap_proxy() -> Iterator[Callable[[], TrapProxy]]:
    """Return a factory of :class:`TrapProxy` servers; each one closes after the test."""
    made: list[TrapProxy] = []

    def start() -> TrapProxy:
        proxy = TrapProxy()
        made.append(proxy)
        return proxy

    yield start
    for proxy in made:
        proxy.close()
