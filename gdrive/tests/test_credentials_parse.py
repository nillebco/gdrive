"""Unit tests for GOOGLE_CREDENTIALS JSON parsing and OAuth client config."""

import pytest

from main import (
    _detect_credentials_type,
    _get_oauth_client_config,
    _parse_credentials_json,
)


def test_parse_raw_json() -> None:
    """Raw JSON without quotes is parsed correctly."""
    data = _parse_credentials_json('{"installed":{"client_id":"x","project_id":"y"}}')
    assert data == {"installed": {"client_id": "x", "project_id": "y"}}


def test_parse_single_quoted_json() -> None:
    """JSON wrapped in single quotes (e.g. from .env) is stripped and parsed."""
    data = _parse_credentials_json("'{\"installed\":{\"client_id\":\"x\"}}'")
    assert data == {"installed": {"client_id": "x"}}


def test_parse_whitespace_and_single_quotes() -> None:
    """Whitespace and single quotes are handled."""
    data = _parse_credentials_json("  \n  '{\"installed\":{\"client_id\":\"a\"}}'  \n  ")
    assert data == {"installed": {"client_id": "a"}}


def test_parse_empty_raises() -> None:
    """Empty or whitespace-only value raises ValueError."""
    with pytest.raises(ValueError, match="empty"):
        _parse_credentials_json("")
    with pytest.raises(ValueError, match="empty"):
        _parse_credentials_json("   \n  ")


def test_parse_invalid_json_raises() -> None:
    """Invalid JSON raises ValueError with a clear message."""
    with pytest.raises(ValueError, match="not valid JSON"):
        _parse_credentials_json("not json")


def test_get_oauth_client_config_installed() -> None:
    """OAuth client config returns 'installed' when present."""
    data = {"installed": {"client_id": "a", "client_secret": "b"}}
    assert _get_oauth_client_config(data) == {"client_id": "a", "client_secret": "b"}


def test_get_oauth_client_config_web() -> None:
    """OAuth client config returns 'web' for Web application credentials (token server)."""
    data = {
        "web": {
            "client_id": "x.apps.googleusercontent.com",
            "client_secret": "secret",
            "redirect_uris": ["http://localhost:8080/auth/callback"],
        }
    }
    config = _get_oauth_client_config(data)
    assert config is not None
    assert config["client_id"] == "x.apps.googleusercontent.com"
    assert config["client_secret"] == "secret"
    assert "http://localhost:8080/auth/callback" in config["redirect_uris"]


def test_get_oauth_client_config_prefers_installed() -> None:
    """When both 'installed' and 'web' exist, 'installed' is returned."""
    data = {
        "installed": {"client_id": "i"},
        "web": {"client_id": "w"},
    }
    assert _get_oauth_client_config(data)["client_id"] == "i"


def test_get_oauth_client_config_none() -> None:
    """OAuth client config returns None when neither installed nor web."""
    assert _get_oauth_client_config({}) is None
    assert _get_oauth_client_config({"service_account": {}}) is None


def test_detect_credentials_type_web() -> None:
    """Web application credentials are detected as client_secret (for token server)."""
    assert _detect_credentials_type({"web": {"client_id": "x", "client_secret": "y"}}) == "client_secret"
