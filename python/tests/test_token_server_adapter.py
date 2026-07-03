"""
Unit tests for the Token Server Adapter.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path to import the adapter
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from token_server_adapter import TokenServerAdapter, create_adapter


class TestServerTypeDetection(unittest.TestCase):
    """Test server type detection."""

    def test_detect_gdrive_server(self):
        """Test detection of gdrive server via /health endpoint."""
        adapter = TokenServerAdapter("http://localhost:8080")
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response
            
            server_type = adapter.detect_server_type()
            
            self.assertEqual(server_type, "gdrive")
            self.assertEqual(adapter._server_type, "gdrive")

    def test_detect_nextjs_server(self):
        """Test detection of Next.js server via /api/ping endpoint."""
        adapter = TokenServerAdapter("http://localhost:3000")
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            # First call (/health) fails
            # Second call (/api/ping) succeeds
            def urlopen_side_effect(req, timeout=None):
                if '/health' in str(req.full_url if hasattr(req, 'full_url') else req):
                    raise Exception("Not found")
                else:
                    mock_response = MagicMock()
                    mock_response.status = 200
                    mock_response.__enter__ = Mock(return_value=mock_response)
                    mock_response.__exit__ = Mock(return_value=False)
                    return mock_response
            
            mock_urlopen.side_effect = urlopen_side_effect
            
            server_type = adapter.detect_server_type()
            
            self.assertEqual(server_type, "nextjs")
            self.assertEqual(adapter._server_type, "nextjs")

    def test_detect_unknown_defaults_to_gdrive(self):
        """Test that unknown servers default to gdrive for backward compatibility."""
        adapter = TokenServerAdapter("http://localhost:9999")
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = Exception("Connection refused")
            
            server_type = adapter.detect_server_type()
            
            self.assertEqual(server_type, "gdrive")

    def test_cached_server_type(self):
        """Test that server type detection is cached."""
        adapter = TokenServerAdapter("http://localhost:8080")
        adapter._server_type = "gdrive"
        
        # Should return cached value without making HTTP requests
        with patch('urllib.request.urlopen') as mock_urlopen:
            server_type = adapter.detect_server_type()
            
            self.assertEqual(server_type, "gdrive")
            mock_urlopen.assert_not_called()


class TestRefreshToken(unittest.TestCase):
    """Test token refresh functionality."""

    def test_refresh_token_gdrive_server(self):
        """Test token refresh with gdrive server."""
        adapter = TokenServerAdapter("http://localhost:8080")
        adapter._server_type = "gdrive"
        
        expected_response = {
            'token': 'ya29.new_access_token',
            'expiry': '2026-02-15T10:00:00Z'
        }
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = json.dumps(expected_response).encode('utf-8')
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response
            
            result = adapter.refresh_token('refresh_token_123')
            
            self.assertEqual(result, expected_response)
            self.assertEqual(result['token'], 'ya29.new_access_token')

    def test_refresh_token_nextjs_server(self):
        """Test token refresh with Next.js server."""
        adapter = TokenServerAdapter("http://localhost:3000")
        adapter._server_type = "nextjs"
        
        nextjs_response = {
            'access_token': 'ya29.new_access_token',
            'expires_in': 3599
        }
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = json.dumps(nextjs_response).encode('utf-8')
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response
            
            result = adapter.refresh_token('refresh_token_123')
            
            # Should transform Next.js format to standard format
            self.assertIsNotNone(result)
            self.assertEqual(result['token'], 'ya29.new_access_token')
            self.assertIn('expiry', result)

    def test_refresh_token_http_error(self):
        """Test token refresh with HTTP error."""
        adapter = TokenServerAdapter("http://localhost:8080")
        adapter._server_type = "gdrive"
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            import urllib.error
            error_response = json.dumps({'error': 'invalid_grant'})
            http_error = urllib.error.HTTPError(
                'url', 401, 'Unauthorized', {}, MagicMock()
            )
            http_error.read = Mock(return_value=error_response.encode('utf-8'))
            mock_urlopen.side_effect = http_error
            
            result = adapter.refresh_token('invalid_refresh_token')
            
            self.assertIsNone(result)

    def test_refresh_token_network_error(self):
        """Test token refresh with network error."""
        adapter = TokenServerAdapter("http://localhost:8080")
        adapter._server_type = "gdrive"
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = Exception("Network error")
            
            result = adapter.refresh_token('refresh_token_123')
            
            self.assertIsNone(result)


class TestCreateAdapter(unittest.TestCase):
    """Test adapter factory function."""

    def test_create_adapter(self):
        """Test that create_adapter returns a TokenServerAdapter instance."""
        adapter = create_adapter("http://localhost:8080")
        
        self.assertIsInstance(adapter, TokenServerAdapter)
        self.assertEqual(adapter.server_url, "http://localhost:8080")

    def test_create_adapter_strips_trailing_slash(self):
        """Test that create_adapter strips trailing slash from URL."""
        adapter = create_adapter("http://localhost:8080/")
        
        self.assertEqual(adapter.server_url, "http://localhost:8080")


class TestNextjsManualFlow(unittest.TestCase):
    """Test manual token entry flow for Next.js server."""

    def test_fetch_token_nextjs_requires_manual_input(self):
        """Test that Next.js server uses manual token entry flow."""
        adapter = TokenServerAdapter("http://localhost:3000")
        adapter._server_type = "nextjs"

        # The _fetch_token_nextjs_server method requires stdin input
        # We can't easily test interactive input, so we just verify
        # that the method exists and has the right signature
        self.assertTrue(hasattr(adapter, '_fetch_token_nextjs_server'))
        self.assertTrue(callable(adapter._fetch_token_nextjs_server))

    def test_supplied_refresh_token_skips_browser(self):
        """A supplied refresh token is exchanged without opening a browser."""
        adapter = TokenServerAdapter("https://ogd.richardxiong.com")
        adapter._server_type = "nextjs"

        with patch.object(
            adapter, "_refresh_token_nextjs_server",
            return_value={"token": "ya29.abc", "expiry": "2026-02-15T10:00:00"}
        ) as mock_exchange, patch("webbrowser.open") as mock_browser:
            token_data = adapter.fetch_token_interactive(refresh_token="1//validtoken")

        mock_browser.assert_not_called()
        mock_exchange.assert_called_once_with("1//validtoken")
        self.assertEqual(token_data["token"], "ya29.abc")
        self.assertEqual(token_data["refresh_token"], "1//validtoken")
        self.assertEqual(token_data["token_server"], "https://ogd.richardxiong.com")

    def test_build_token_rejects_non_google_token(self):
        """A token not starting with 1// is rejected before any HTTP call."""
        adapter = TokenServerAdapter("https://ogd.richardxiong.com")
        adapter._server_type = "nextjs"
        with self.assertRaises(RuntimeError):
            adapter._build_token_from_refresh("not-a-real-token")

    def test_build_token_raises_actionable_error_on_exchange_failure(self):
        """A failed exchange (e.g. wrong OAuth client) raises a clear error."""
        adapter = TokenServerAdapter("https://ogd.richardxiong.com")
        adapter._server_type = "nextjs"
        with patch.object(adapter, "_refresh_token_nextjs_server", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                adapter._build_token_from_refresh("1//tokenfromwrongclient")
        self.assertIn("different OAuth client", str(ctx.exception))

    def test_non_interactive_stdin_does_not_loop(self):
        """Without a supplied token and a non-tty stdin, fail fast (no infinite loop)."""
        adapter = TokenServerAdapter("https://ogd.richardxiong.com")
        adapter._server_type = "nextjs"
        with patch("sys.stdin.isatty", return_value=False), patch("webbrowser.open"):
            with self.assertRaises(RuntimeError):
                adapter._fetch_token_nextjs_server()


if __name__ == '__main__':
    unittest.main()
