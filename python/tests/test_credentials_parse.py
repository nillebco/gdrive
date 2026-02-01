"""Unit tests for GOOGLE_CREDENTIALS JSON parsing."""

import pytest

from main import _parse_credentials_json


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
