from __future__ import annotations

from rsi_scanner.config import resolve_secret


def test_resolve_secret_prefers_env(monkeypatch):
    monkeypatch.setenv("TELEGRAM_TOKEN", "from_env")
    assert resolve_secret("TELEGRAM_TOKEN", "from_config") == "from_env"


def test_resolve_secret_uses_literal_when_env_missing(monkeypatch):
    monkeypatch.delenv("TELEGRAM_TOKEN", raising=False)
    assert resolve_secret("TELEGRAM_TOKEN", "from_config") == "from_config"


def test_resolve_secret_empty_when_missing():
    assert resolve_secret("DOES_NOT_EXIST", "") == ""


def test_resolve_secret_accepts_non_env_style_env_key_as_literal(monkeypatch):
    token_like = "12345:ABCDE_token_value"
    monkeypatch.delenv(token_like, raising=False)
    assert resolve_secret(token_like, "") == token_like
