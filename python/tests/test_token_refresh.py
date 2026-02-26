"""Tests for token refresh functionality."""
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, MagicMock
import pytest
from google.oauth2.credentials import Credentials as OAuthCredentials
from google.auth.transport.requests import Request

# Import functions to test
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from main import (
    _refresh_token_from_server,
    _refresh_token_via_server,
    _load_token,
    _fetch_token_from_server,
    TokenServerHandler,
)


class TestTokenRefreshFromServer:
    """Test client-side token refresh via server."""

    def test_refresh_token_from_server_success(self):
        """Test successful token refresh from server."""
        # Mock urllib.request.urlopen
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            'token': 'new_access_token',
            'expiry': '2026-02-02T13:00:00Z'
        }).encode('utf-8')
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        
        with patch('urllib.request.urlopen', return_value=mock_response):
            result = _refresh_token_from_server('http://localhost:8080', 'refresh_token_123')
        
        assert result is not None
        assert result['token'] == 'new_access_token'
        assert result['expiry'] == '2026-02-02T13:00:00Z'

    def test_refresh_token_from_server_http_error(self):
        """Test token refresh when server returns HTTP error."""
        import urllib.error
        
        mock_error = urllib.error.HTTPError(
            'http://localhost:8080/auth/refresh',
            401,
            'Unauthorized',
            {},
            None
        )
        mock_error.read = lambda: json.dumps({'error': 'Invalid refresh token'}).encode('utf-8')
        
        with patch('urllib.request.urlopen', side_effect=mock_error):
            result = _refresh_token_from_server('http://localhost:8080', 'invalid_token')
        
        assert result is None

    def test_refresh_token_from_server_network_error(self):
        """Test token refresh when network error occurs."""
        with patch('urllib.request.urlopen', side_effect=Exception('Network error')):
            result = _refresh_token_from_server('http://localhost:8080', 'refresh_token_123')
        
        assert result is None


class TestTokenRefreshViaServer:
    """Test higher-level token refresh via server."""

    def test_refresh_token_via_server_success(self, tmp_path):
        """Test successful token refresh and file update."""
        # Create a token file
        token_path = tmp_path / "token.json"
        token_data = {
            'token': 'old_access_token',
            'refresh_token': 'refresh_token_123',
            'expiry': '2026-02-02T11:00:00Z'
        }
        token_path.write_text(json.dumps(token_data))
        
        # Mock _refresh_token_from_server
        with patch('main._refresh_token_from_server', return_value={
            'token': 'new_access_token',
            'expiry': '2026-02-02T13:00:00Z'
        }):
            creds = _refresh_token_via_server(str(token_path), 'http://localhost:8080')
        
        assert creds is not None
        assert creds.token == 'new_access_token'
        
        # Verify file was updated
        updated_data = json.loads(token_path.read_text())
        assert updated_data['token'] == 'new_access_token'
        assert updated_data['expiry'] == '2026-02-02T13:00:00Z'

    def test_refresh_token_via_server_no_refresh_token(self, tmp_path):
        """Test when token file has no refresh_token."""
        token_path = tmp_path / "token.json"
        token_data = {'token': 'access_token_only'}
        token_path.write_text(json.dumps(token_data))
        
        creds = _refresh_token_via_server(str(token_path), 'http://localhost:8080')
        
        assert creds is None

    def test_refresh_token_via_server_file_not_found(self, tmp_path):
        """Test when token file doesn't exist."""
        token_path = tmp_path / "nonexistent.json"
        
        creds = _refresh_token_via_server(str(token_path), 'http://localhost:8080')
        
        assert creds is None


class TestLoadTokenWithServer:
    """Test _load_token with token_server parameter."""

    def test_load_token_with_server_valid(self, tmp_path):
        """Test loading a valid token with token_server."""
        token_path = tmp_path / "token.json"
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        token_data = {
            'token': 'valid_access_token',
            'refresh_token': 'refresh_token_123',
            'token_uri': 'https://oauth2.googleapis.com/token',
            'expiry': expiry,
            'scopes': ['https://www.googleapis.com/auth/drive.file']
        }
        token_path.write_text(json.dumps(token_data))
        
        creds = _load_token(str(token_path), token_server='http://localhost:8080')
        
        assert creds is not None
        assert creds.token == 'valid_access_token'

    def test_load_token_without_server_needs_credentials(self, tmp_path):
        """Test loading token without server requires client credentials."""
        token_path = tmp_path / "token.json"
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        token_data = {
            'token': 'valid_access_token',
            'refresh_token': 'refresh_token_123',
            'token_uri': 'https://oauth2.googleapis.com/token',
            'expiry': expiry,
            'scopes': ['https://www.googleapis.com/auth/drive.file']
        }
        token_path.write_text(json.dumps(token_data))
        
        # Without client_id/client_secret and without token_server, should fail
        creds = _load_token(str(token_path))
        
        assert creds is None


class TestFetchTokenFromServer:
    """Test _fetch_token_from_server function behavior."""

    def test_fetch_token_with_valid_existing_token(self, tmp_path):
        """Test that _fetch_token_from_server doesn't fetch when valid token exists."""
        token_path = tmp_path / "token.json"
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        token_data = {
            'token': 'valid_access_token',
            'refresh_token': 'refresh_token_123',
            'token_uri': 'https://oauth2.googleapis.com/token',
            'expiry': expiry,
            'scopes': ['https://www.googleapis.com/auth/drive.file']
        }
        token_path.write_text(json.dumps(token_data))
        
        # Mock webbrowser to ensure it's NOT called
        with patch('main.webbrowser.open') as mock_browser:
            _fetch_token_from_server('http://localhost:8080', str(token_path))
            # Should not open browser since we have valid token
            mock_browser.assert_not_called()

    def test_fetch_token_with_expired_token_refreshes(self, tmp_path):
        """Test that _fetch_token_from_server refreshes expired token."""
        token_path = tmp_path / "token.json"
        expiry = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        token_data = {
            'token': 'expired_access_token',
            'refresh_token': 'refresh_token_123',
            'token_uri': 'https://oauth2.googleapis.com/token',
            'expiry': expiry,
            'scopes': ['https://www.googleapis.com/auth/drive.file']
        }
        token_path.write_text(json.dumps(token_data))
        
        # Mock refresh to succeed
        with patch('main._refresh_token_via_server') as mock_refresh:
            mock_creds = MagicMock()
            mock_creds.valid = True
            mock_refresh.return_value = mock_creds
            
            with patch('main.webbrowser.open') as mock_browser:
                _fetch_token_from_server('http://localhost:8080', str(token_path))
                # Should call refresh instead of opening browser
                mock_refresh.assert_called_once()
                mock_browser.assert_not_called()

    def test_fetch_token_with_no_token_opens_browser(self, tmp_path):
        """Test that _fetch_token_from_server opens browser when no token exists."""
        token_path = tmp_path / "token.json"
        
        # Mock browser and server - we'll make datetime.now() advance quickly to trigger timeout
        with patch('main.webbrowser.open') as mock_browser:
            with patch('main.socketserver.TCPServer') as mock_server:
                with patch('main.datetime') as mock_datetime:
                    # Setup mock server
                    mock_server_instance = MagicMock()
                    mock_server_instance.server_address = ('localhost', 12345)
                    mock_server_instance.__enter__ = MagicMock(return_value=mock_server_instance)
                    mock_server_instance.__exit__ = MagicMock(return_value=None)
                    mock_server.return_value = mock_server_instance
                    
                    # Make time advance immediately to trigger timeout
                    start_time = datetime.now()
                    mock_datetime.now.side_effect = [start_time, start_time + timedelta(seconds=400)]
                    
                    # Simulate timeout
                    with pytest.raises(TimeoutError):
                        _fetch_token_from_server('http://localhost:8080', str(token_path))
                    
                    # Should open browser since no token exists
                    mock_browser.assert_called_once()


class TestTokenServerRefreshEndpoint:
    """Test the token server's POST /auth/refresh endpoint integration."""

    def test_refresh_endpoint_e2e(self):
        """Integration test: successful token refresh via HTTP server."""
        import urllib.request
        import threading
        import socketserver
        import time
        
        # Mock credentials
        mock_credentials = {
            'web': {
                'client_id': 'test_client_id',
                'client_secret': 'test_client_secret'
            }
        }
        
        # Configure handler
        TokenServerHandler.credentials = mock_credentials
        TokenServerHandler.port = 0  # Use any available port
        
        # Mock the OAuth credentials refresh
        mock_creds = MagicMock(spec=OAuthCredentials)
        mock_creds.token = 'new_access_token'
        mock_creds.expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        
        # Start server in background thread
        server = socketserver.TCPServer(('localhost', 0), TokenServerHandler)
        server_port = server.server_address[1]
        
        server_thread = threading.Thread(target=lambda: server.handle_request())
        server_thread.daemon = True
        server_thread.start()
        
        # Give server time to start
        time.sleep(0.1)
        
        try:
            # Mock the credential refresh
            with patch('main.OAuthCredentials.from_authorized_user_info', return_value=mock_creds):
                with patch.object(mock_creds, 'refresh'):
                    # Make request to refresh endpoint
                    request_data = json.dumps({'refresh_token': 'test_refresh_token'}).encode('utf-8')
                    req = urllib.request.Request(
                        f'http://localhost:{server_port}/auth/refresh',
                        data=request_data,
                        headers={'Content-Type': 'application/json'},
                        method='POST'
                    )
                    
                    response = urllib.request.urlopen(req, timeout=5)
                    result = json.loads(response.read().decode('utf-8'))
                    
                    # Verify response
                    assert 'token' in result
                    assert result['token'] == 'new_access_token'
        finally:
            server.server_close()
            server_thread.join(timeout=1)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
