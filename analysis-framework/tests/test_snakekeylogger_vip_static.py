"""Snake Keylogger／VIPKeyloggerの静的復元と専用handler契約を検証する。"""

from __future__ import annotations

import base64
import hashlib

from Cryptodome.Cipher import DES
import pytest

from extractors.config_extractor import get_extractor
from extractors.snakekeylogger import extractor


def _pad(value: bytes) -> bytes:
    width = 8 - len(value) % 8
    return value + bytes([width]) * width


def test_des_config_decoder_and_public_projection() -> None:
    master = "synthetic-master-key"
    key = hashlib.md5(master.encode("ascii")).digest()[:8]
    ciphertext = base64.b64encode(
        DES.new(key, DES.MODE_ECB).encrypt(_pad(b"mail.example.test"))
    ).decode("ascii")
    assert extractor._decrypt_des_ecb(ciphertext, master) == "mail.example.test"
    config = extractor._public_config(
        [
            "sender@example.test",
            "synthetic-password",
            "mail.example.test",
            "receiver@example.test",
            "587",
            "%$TeleToken$%",
            "%$TeleID$%",
            "",
        ],
        {"method_token": "0x06000001", "algorithm": "synthetic"},
    )
    assert config["config_endpoints"] == [
        {
            "protocol": "smtp",
            "host": "mail.example.test",
            "port": 587,
            "role": "credential_exfiltration",
            "confidence": "confirmed_static_config",
        }
    ]
    assert config["smtp_password_present"] is True
    assert config["credential_values_published"] is False
    assert config["telegram"]["token_configured"] is False
    rendered = repr(config)
    assert "synthetic-password" not in rendered
    assert "sender@" not in rendered
    assert "receiver@" not in rendered


@pytest.mark.parametrize(
    "values",
    [
        ["mail.example.test", "587"],
        ["a@example.test", "b@example.test", "one.example", "two.example", "587", "x"],
        ["a@example.test", "b@example.test", "mail.example.test", "0", "x"],
    ],
)
def test_public_config_requires_unique_smtp_semantics(values: list[str]) -> None:
    with pytest.raises(extractor.SnakeStaticRecoveryError):
        extractor._public_config(values, {})


def test_structural_evidence_requires_independent_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = (
        b"MZ BSJB Stub Version: VIP Recovery https://api.telegram.org/bot "
        b"/sendMessage?chat_id= SmtpClient MailMessage FtpWebRequest SetWindowsHookExA"
    )
    monkeypatch.setattr(extractor, "_is_dotnet", lambda _data: True)
    evidence = extractor.structural_evidence(fixture)
    assert evidence["matched"] is True
    assert set(evidence["matched_groups"]) == {
        "builder",
        "ftp",
        "keylogging",
        "smtp",
        "telegram",
    }
    assert extractor.structural_evidence(fixture.replace(b"VIP Recovery", b"generic"))[
        "matched"
    ] is False


def test_dedicated_extractor_overrides_shared_profile() -> None:
    assert get_extractor("snakekeylogger") is extractor.extract
    result = extractor.extract(b"not a managed payload", "fixture.bin")
    assert result["family"] == "snakekeylogger"
    assert result["config"]["static_config_recovered"] is False
    assert result["findings"] == []
    assert result["executed"] is False
    assert result["network_contacted"] is False
    assert result["credentials_published"] is False


def test_input_and_secret_boundaries() -> None:
    with pytest.raises(extractor.SnakeStaticRecoveryError, match="16 MiB"):
        extractor.analyze_chain(b"x" * (extractor.MAXIMUM_INPUT_SIZE + 1))
    with pytest.raises(extractor.SnakeStaticRecoveryError):
        extractor._decrypt_des_ecb("not-base64", "key")


def test_verified_terminal_is_worker_private_and_public_chain_stays_raw_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """検証済みterminalだけを明示roleで渡し、公開chainへbytesを混入させない。"""

    terminal = b"MZ" + b"PRIVATE-TERMINAL" * 4
    chain = {
        "status": "final_config_recovered",
        "layers": [extractor._layer("submitted", b"fixture")],
        "terminal_config": {
            "recovery_status": "confirmed_static_config",
            "config_endpoints": [],
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "credentials_published": False,
            "recovered_bytes_published": False,
        },
    }
    monkeypatch.setattr(
        extractor,
        "_analyze_chain_with_terminal",
        lambda _data: (chain, terminal),
    )

    assert "PRIVATE-TERMINAL" not in repr(extractor.analyze_chain(b"fixture"))
    result = extractor.extract(b"fixture", "fixture.js")
    assert result["terminal_payload"] == {
        "role": "terminal_payload",
        "name": f"{hashlib.sha256(terminal).hexdigest()}.exe",
        "data": terminal,
    }
    assert result["config"]["recovered_bytes_published"] is False
