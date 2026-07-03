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
    
    def fetch_token_interactive(
        self, token_path: Optional[str] = None, refresh_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Fetch a new OAuth token, either non-interactively from a supplied refresh
        token or by opening a browser for user authentication.

        Args:
            token_path: Path where the token will be saved (for logging purposes)
            refresh_token: A refresh token to exchange directly (non-interactive).
                When provided for a Next.js server, the browser prompt is skipped.

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
            return self._fetch_token_nextjs_server(refresh_token)
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
    
    def _build_token_from_refresh(self, refresh_token: str) -> Dict[str, Any]:
        """Exchange a Next.js-issued refresh token for a full token payload.

        Raises RuntimeError with an actionable message if the exchange fails
        (most commonly because the refresh token was issued by a different
        OAuth client than the one this server uses).
        """
        refresh_token = (refresh_token or "").strip()
        if not refresh_token:
            raise RuntimeError("No refresh token provided.")
        if not refresh_token.startswith("1//"):
            raise RuntimeError(
                "That doesn't look like a Google refresh token (they start with '1//'). "
                "Copy it exactly as shown by the token server."
            )

        result = self._refresh_token_nextjs_server(refresh_token)
        if not result or "token" not in result:
            raise RuntimeError(
                f"{self.server_url} could not exchange this refresh token. "
                "This usually means the token was issued by a different OAuth client "
                f"(each token server has its own). Re-provision a refresh token from "
                f"{self.server_url} and try again."
            )

        return {
            "token": result["token"],
            "refresh_token": refresh_token,
            "expiry": result["expiry"],
            "token_uri": "https://oauth2.googleapis.com/token",
            "scopes": ["https://www.googleapis.com/auth/drive.file"],
            "issuer": "https://accounts.google.com",
            "token_server": self.server_url,
        }

    def _fetch_token_nextjs_server(
        self, refresh_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Fetch token from Next.js server.

        Note: Next.js servers are designed as web applications where OAuth happens
        in the browser. The redirect_uri must be pre-registered and points to the
        website, not a CLI callback. Therefore, when no refresh token is supplied
        we use a semi-manual flow:

        1. Open the Next.js website in browser
        2. User completes OAuth in browser
        3. User pastes the displayed refresh token

        If ``refresh_token`` is supplied (e.g. via ``login --refresh-token`` or the
        ``OGD_REFRESH_TOKEN`` env var), the browser step is skipped entirely.
        """
        # Non-interactive path: a token was supplied up front.
        if refresh_token:
            return self._build_token_from_refresh(refresh_token)

        import sys

        # Without an interactive terminal we cannot prompt for a paste. Fail loud
        # with guidance instead of spinning on EOF forever.
        if not sys.stdin.isatty():
            raise RuntimeError(
                f"{self.server_url} needs a refresh token, but stdin is not interactive. "
                f"Sign in at {self.server_url}, copy the refresh token, and pass it via "
                "`login --refresh-token <token>` or the OGD_REFRESH_TOKEN env var."
            )

        print(f"\n{'='*70}")
        print("MANUAL AUTHENTICATION REQUIRED")
        print(f"{'='*70}\n")
        print(f"The server at {self.server_url} requires manual authentication.")
        print("\nSteps:")
        print(f"  1. Opening browser to {self.server_url}...")
        print("  2. Sign in with Google when prompted")
        print("  3. Copy the displayed refresh token")
        print("  4. Return here to paste it\n")

        webbrowser.open(self.server_url)

        import time
        time.sleep(2)

        print("Waiting for you to complete authentication in the browser...")

        # Prompt for refresh token input. Bail after a bounded number of empty
        # reads so a closed/redirected stdin can never cause an infinite loop.
        empty_reads = 0
        while True:
            print("\nPaste the refresh token from the browser (or press Ctrl+C to cancel):")
            print("(It should look like: 1//01abc...xyz)\n")
            try:
                print("→ ", end="", flush=True)
                line = sys.stdin.readline()
                if line == "":  # EOF
                    raise RuntimeError(
                        "stdin closed before a refresh token was provided. "
                        "Use `login --refresh-token <token>` instead."
                    )
                token = line.strip()
                if not token:
                    empty_reads += 1
                    if empty_reads >= 3:
                        raise RuntimeError("No refresh token provided after several attempts.")
                    print("\n✗ Error: No token provided")
                    continue

                print("\n⏳ Exchanging refresh token for access token...")
                try:
                    token_data = self._build_token_from_refresh(token)
                    print("✓ Token validated and access token obtained successfully!")
                    return token_data
                except RuntimeError as e:
                    print(f"\n✗ {e}")
                    print("Please try authenticating again in the browser")
                    continue
            except KeyboardInterrupt:
                print("\n\nAuthentication cancelled by user.")
                raise RuntimeError("Authentication cancelled")


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
            # The Next.js /api/access route has no error handling: when Google
            # rejects the refresh token (e.g. it was minted by a different OAuth
            # client) it bubbles up as a bare HTTP 500 HTML page. Translate that
            # into an actionable hint rather than dumping the HTML.
            if e.code >= 500:
                print(
                    f"Token refresh failed (HTTP {e.code} from {access_url}). "
                    "The server rejected this refresh token — most likely it was "
                    "issued by a different OAuth client than this token server uses. "
                    f"Re-provision a refresh token from {self.server_url}."
                )
            else:
                try:
                    print(f"Token refresh failed: {e.read().decode('utf-8')[:300]}")
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
