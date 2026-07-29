"""AgentTesla FTP最小プローブが資格情報やファイルを送らないことを検証する。"""

from __future__ import annotations

import importlib.util
import io
from pathlib import Path


MODULE = (
    Path(__file__).parents[1]
    / "malware"
    / "agenttesla"
    / "c2_detector.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("agenttesla_c2_detector_v2", MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeSocket:
    def __init__(self) -> None:
        self.sent = io.BytesIO()
        self.reader = io.BytesIO(
            b"220-Welcome\r\n220 Ready\r\n"
            b"211-Features\r\n UTF8\r\n SIZE\r\n211 End\r\n"
            b"221-Bye\r\n221 Closed\r\n"
        )

    def settimeout(self, _timeout: float) -> None:
        pass

    def makefile(self, _mode: str, buffering: int = 0):
        outer = self

        class Stream:
            def readline(self, size: int = -1):
                return outer.reader.readline(size)

            def write(self, value: bytes):
                return outer.sent.write(value)

            def close(self):
                pass

        return Stream()

    def close(self) -> None:
        pass


def test_probe_sends_only_feat_and_quit() -> None:
    module = _load()
    fake = FakeSocket()
    resolver = lambda *_args, **_kwargs: [  # noqa: E731
        (2, 1, 6, "", ("93.184.216.34", 21))
    ]
    result = module.probe_ftp(
        "ftp.example.test",
        21,
        resolver=resolver,
        connector=lambda *_args, **_kwargs: fake,
        checked_at="2026-07-29T00:00:00Z",
    )
    assert fake.sent.getvalue() == b"FEAT\r\nQUIT\r\n"
    assert b"USER" not in fake.sent.getvalue()
    assert b"PASS" not in fake.sent.getvalue()
    assert result["banner"]["code"] == "220"
    assert result["feat"]["code"] == "211"
    assert result["quit"]["code"] == "221"
    assert result["authentication_attempted"] is False
    assert result["file_transfer_attempted"] is False
