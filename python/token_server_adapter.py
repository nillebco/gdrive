"""
Token Server Adapter - Unified interface for multiple OAuth token server types.

This adapter supports two server implementations:
1. Current gdrive server (Python/Node.js) - /auth/start, /auth/callback, /auth/refresh
2. Next.js server (obsidian-google-drive-website) - /api/tokens, /api/access

The adapter automatically detects the server type and adapts requests/responses accordingly.
"""

import json
import urllib.request
import urllib.error
import webbrowser
import secrets
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler
import socketserver
from typing import Optional, Dict, Any, Literal
from urllib.parse import urlparse, parse_qs, quote, urlencode


ServerType = Literal["gdrive", "nextjs", "unknown"]


class TokenServerAdapter:
    """Adapter for communicating with different types of OAuth token servers."""
    
    def __init__(self, server_url: str):
        """
        Initialize the adapter with a server URL.
        
        Args:
            server_url: Base URL of the token server
        """
        self.server_url = server_url.rstrip('/')
        self._server_type: Optional[ServerType] = None
    
    def detect_server_type(self) -> ServerType:
        """
        Detect the type of token server by probing its endpoints.
        
        Returns:
            The detected server type: "gdrive", "nextjs", or "unknown"
        """
        if self._server_type:
            return self._server_type
        
        # Try gdrive server health check
        try:
            req = urllib.request.Request(f"{self.server_url}/health", method='GET')
            with urllib.request.urlopen(req, timeout=3) as response:
                if response.status == 200:
                    self._server_type = "gdrive"
                    return self._server_type
        except Exception:
            pass
        
        # Try to detect Next.js server by checking if /api/ping exists
        try:
            req = urllib.request.Request(f"{self.server_url}/api/ping", method='GET')
            with urllib.request.urlopen(req, timeout=3) as response:
                if response.status == 200:
                    self._server_type = "nextjs"
                    return self._server_type
        except Exception:
            pass
        
        # Default to gdrive server (backward compatibility)
        self._server_type = "gdrive"
        return self._server_type
    
    def fetch_token_interactive(self, token_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch a new OAuth token by opening a browser for user authentication.
        
        Args:
            token_path: Path where the token will be saved (for logging purposes)
            
        Returns:
            Token data in standardized format with keys:
            - token: access token
            - refresh_token: refresh token
            - expiry: ISO 8601 expiry time
            - token_uri: OAuth token endpoint
            - scopes: list of scopes
            - issuer: OAuth issuer (https://accounts.google.com)
            - token_server: URL of token server that issued the token
        """
        server_type = self.detect_server_type()
        
        if server_type == "gdrive":
            return self._fetch_token_gdrive_server()
        elif server_type == "nextjs":
            return self._fetch_token_nextjs_server()
        else:
            raise RuntimeError(f"Unknown server type: {server_type}")
    
    def refresh_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Refresh an access token using a refresh token.
        
        Args:
            refresh_token: The refresh token to use
            
        Returns:
            Dict with 'token' and 'expiry', or None if refresh failed
        """
        server_type = self.detect_server_type()
        
        if server_type == "gdrive":
            return self._refresh_token_gdrive_server(refresh_token)
        elif server_type == "nextjs":
            return self._refresh_token_nextjs_server(refresh_token)
        else:
            return None
    
    def _fetch_token_gdrive_server(self) -> Dict[str, Any]:
        """Fetch token from gdrive server using /auth/start flow."""
        print(f"Opening browser to authenticate via {self.server_url}...")
        
        # Generate a session ID
        session_id = secrets.token_hex(16)
        
        # Token received flag
        token_received = threading.Event()
        received_token = [None]
        server_url = self.server_url  # Capture for closure
        
        class CallbackHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress logging
            
            def do_GET(handler_self):
                parsed = urlparse(handler_self.path)
                if parsed.path == '/callback':
                    params = parse_qs(parsed.query)
                    if 'token' in params:
                        try:
                            token_data = json.loads(params['token'][0])
                            received_token[0] = token_data
                            
                            handler_self.send_response(200)
                            handler_self.send_header('Content-Type', 'text/html')
                            handler_self.end_headers()
                            handler_self.wfile.write(b'''
                                <html>
                                    <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                                        <h1>Token received!</h1>
                                        <p>You can close this window and return to the terminal.</p>
                                    </body>
                                </html>
                            ''')
                            token_received.set()
                        except Exception as e:
                            handler_self.send_response(400)
                            handler_self.end_headers()
                            handler_self.wfile.write(f"Error: {e}".encode())
                    else:
                        handler_self.send_response(400)
                        handler_self.end_headers()
                        handler_self.wfile.write(b"No token received")
        
        # Start local server on a random port
        with socketserver.TCPServer(('localhost', 0), CallbackHandler) as httpd:
            local_port = httpd.server_address[1]
            callback_url = quote(f"http://localhost:{local_port}/callback")
            auth_url = f"{self.server_url}/auth/start?callback={callback_url}&session={session_id}"
            print(f"Authenticate at: {auth_url}")

            # Open browser
            webbrowser.open(auth_url)
            
            # Wait for callback with timeout
            httpd.timeout = 1
            start_time = datetime.now()
            timeout = 300  # 5 minutes
            
            while not token_received.is_set():
                httpd.handle_request()
                if (datetime.now() - start_time).total_seconds() > timeout:
                    raise TimeoutError("Authentication timed out")
        
        if received_token[0]:
            # Already in standard format from gdrive server
            # Add token_server field to track where it came from
            token_data = received_token[0]
            token_data['token_server'] = server_url
            return token_data
        else:
            raise RuntimeError("Failed to receive token")
    
    def _fetch_token_nextjs_server(self) -> Dict[str, Any]:
        """
        Fetch token from Next.js server using manual web flow.
        
        Note: Next.js servers are designed as web applications where OAuth happens
        in the browser. The redirect_uri must be pre-registered and points to the
        website, not a CLI callback. Therefore, we use a semi-manual flow:
        
        1. Open the Next.js website in browser
        2. User completes OAuth in browser
        3. Wait for user to provide the token
        """
        print(f"\n{'='*70}")
        print(f"MANUAL AUTHENTICATION REQUIRED")
        print(f"{'='*70}\n")
        print(f"The Next.js server at {self.server_url} requires manual authentication.")
        print(f"\nSteps:")
        print(f"  1. Opening browser to {self.server_url}...")
        print(f"  2. Sign in with Google when prompted")
        print(f"  3. Copy the displayed refresh token")
        print(f"  4. Return here to paste it\n")
        
        # Open the Next.js website
        webbrowser.open(self.server_url)
        
        # Wait a moment for browser to open
        import time
        time.sleep(2)
        
        print("Waiting for you to complete authentication in the browser...")
        print("\nOnce you've signed in and see your refresh token:")
        
        # Prompt for refresh token input
        while True:
            print("\nPaste the refresh token from the browser (or press Ctrl+C to cancel):")
            print("(It should look like: 1//01abc...xyz)\n")
            
            try:
                import sys
                print("→ ", end="", flush=True)
                
                # Read the refresh token
                refresh_token = sys.stdin.readline().strip()
                
                if not refresh_token:
                    print("\n✗ Error: No token provided")
                    continue
                
                # Validate it looks like a refresh token (basic check)
                if not refresh_token.startswith('1//'):
                    print("\n✗ Error: This doesn't look like a valid refresh token")
                    print("Refresh tokens typically start with '1//'")
                    print("Please copy the token exactly as shown in the browser")
                    continue
                
                print("\n⏳ Exchanging refresh token for access token...")
                
                # Use the server's /api/access endpoint to get an access token
                try:
                    result = self._refresh_token_nextjs_server(refresh_token)
                    
                    if result and 'token' in result:
                        # Build complete token data
                        token_data = {
                            'token': result['token'],
                            'refresh_token': refresh_token,
                            'expiry': result['expiry'],
                            'token_uri': 'https://oauth2.googleapis.com/token',
                            'scopes': ['https://www.googleapis.com/auth/drive.file'],
                            'issuer': 'https://accounts.google.com',
                            'token_server': self.server_url,
                        }
                        
                        print("✓ Token validated and access token obtained successfully!")
                        return token_data
                    else:
                        print("\n✗ Error: Failed to get access token from refresh token")
                        print("The refresh token may be invalid or expired")
                        print("Please try authenticating again in the browser")
                        continue
                        
                except Exception as e:
                    print(f"\n✗ Error: Failed to exchange refresh token: {e}")
                    print("Please try authenticating again in the browser")
                    continue
                    
            except KeyboardInterrupt:
                print("\n\nAuthentication cancelled by user.")
                raise RuntimeError("Authentication cancelled")
            except Exception as e:
                print(f"\n✗ Error: {e}")
                print("Please try again")
                continue
    
    
    def _refresh_token_gdrive_server(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Refresh token using gdrive server /auth/refresh endpoint."""
        refresh_url = f"{self.server_url}/auth/refresh"
        request_data = json.dumps({'refresh_token': refresh_token}).encode('utf-8')
        
        try:
            req = urllib.request.Request(
                refresh_url,
                data=request_data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                # Already in standard format
                return result
        except urllib.error.HTTPError as e:
            try:
                error_body = e.read().decode('utf-8')
                error_data = json.loads(error_body)
                print(f"Token refresh failed: {error_data.get('error', 'Unknown error')}")
            except Exception:
                print(f"Token refresh failed with HTTP {e.code}")
            return None
        except Exception as e:
            print(f"Token refresh failed: {e}")
            return None
    
    def _refresh_token_nextjs_server(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Refresh token using Next.js server /api/access endpoint."""
        access_url = f"{self.server_url}/api/access"
        request_data = json.dumps({'refresh_token': refresh_token}).encode('utf-8')
        
        try:
            req = urllib.request.Request(
                access_url,
                data=request_data,
                headers={
                    'Content-Type': 'application/json',
                    'Origin': self.server_url,
                },
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                # Transform Next.js format to standard format
                now = datetime.now()
                expires_in = result.get('expires_in', 3599)
                expiry = now + timedelta(seconds=expires_in)
                
                return {
                    'token': result['access_token'],
                    'expiry': expiry.isoformat(),
                }
        except urllib.error.HTTPError as e:
            try:
                error_body = e.read().decode('utf-8')
                print(f"Token refresh failed: {error_body}")
            except Exception:
                print(f"Token refresh failed with HTTP {e.code}")
            return None
        except Exception as e:
            print(f"Token refresh failed: {e}")
            return None


def create_adapter(server_url: str) -> TokenServerAdapter:
    """
    Factory function to create a token server adapter.
    
    Args:
        server_url: Base URL of the token server
        
    Returns:
        TokenServerAdapter instance
    """
    return TokenServerAdapter(server_url)
