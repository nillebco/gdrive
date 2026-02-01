"""Unit tests for token server request handling (base URL from request)."""

import pytest

from __main__ import _request_base_url


def _make_handler(headers: dict, port: int = 8080):
    """Minimal mock handler with .headers.get() and .port."""
    class Headers:
        def get(self, key: str, default=None):
            return headers.get(key, default)

    class Handler:
        headers = Headers()
        pass

    h = Handler()
    h.port = port
    h.headers = Headers()
    # Replace get to use our dict (Headers().get above uses the class-level Headers)
    h.headers.get = lambda k, d=None: headers.get(k, d)
    return h


def test_request_base_url_uses_host() -> None:
    """Base URL uses Host header when no proxy headers."""
    handler = _make_handler({"Host": "myserver.example.com:8080"}, port=8080)
    assert _request_base_url(handler, 8080) == "http://myserver.example.com:8080"


def test_request_base_url_uses_x_forwarded() -> None:
    """Base URL uses X-Forwarded-Proto and X-Forwarded-Host when behind proxy."""
    handler = _make_handler(
        {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "token.example.com"},
        port=8080,
    )
    assert _request_base_url(handler, 8080) == "https://token.example.com"


def test_request_base_url_fallback_localhost() -> None:
    """Base URL falls back to localhost:port when no Host."""
    handler = _make_handler({}, port=3000)
    assert _request_base_url(handler, 3000) == "http://localhost:3000"


def test_request_base_url_first_value_only() -> None:
    """First value is used when header has multiple (e.g. multiple proxies)."""
    handler = _make_handler(
        {"X-Forwarded-Proto": "https, http", "X-Forwarded-Host": "token.example.com, internal"},
        port=8080,
    )
    assert _request_base_url(handler, 8080) == "https://token.example.com"
