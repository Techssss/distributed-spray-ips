"""Bind a specific local source IP address for outgoing HTTP sessions."""

from __future__ import annotations

from pathlib import Path

import requests
from requests.adapters import HTTPAdapter


class SourceIPAdapter(HTTPAdapter):
    """HTTPAdapter that pins outgoing sockets to ``source_ip``."""

    def __init__(self, source_ip: str, **kwargs) -> None:
        self.source_ip = source_ip
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        if self.source_ip and self.source_ip != "default":
            pool_kwargs["source_address"] = (self.source_ip, 0)
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


def load_source_ips(path: str | Path) -> list[str]:
    """Read non-empty, non-comment source IPs from a text file."""
    lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    ips = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
    return ips or ["127.0.0.1"]


def build_session_for_ip(source_ip: str) -> requests.Session:
    """Create a requests.Session bound to ``source_ip``."""
    sess = requests.Session()
    adapter = SourceIPAdapter(source_ip)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    return sess
