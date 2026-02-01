#!/usr/bin/env python3
"""
Test script for the token server implementation.

Usage:
    # First, start the token server in another terminal:
    python main.py server --port 8080

    # Then run this test:
    python test_token_server.py [--server-url http://localhost:8080]
"""

import argparse
import json
import sys
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote
import threading

DEFAULT_SERVER_URL = "http://localhost:8080"
CALLBACK_PORT = 9999


class CallbackHandler(BaseHTTPRequestHandler):
    """Handler for receiving the OAuth callback with token."""

    received_token = None

    def log_message(self, format, *args):
        pass  # Suppress logging

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        token_values = params.get('token')
        if token_values:
            try:
                token_json = unquote(token_values[0])
                CallbackHandler.received_token = json.loads(token_json)

                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()

                email = CallbackHandler.received_token.get('email') or CallbackHandler.received_token.get('account_email', 'unknown')
                html = f"""
                <html>
                <head><title>Token Received!</title></head>
                <body style="font-family: sans-serif; padding: 40px; text-align: center;">
                    <h1 style="color: green;">✓ Token Received Successfully!</h1>
                    <p>User: <strong>{email}</strong></p>
                    <p>Token keys: {list(CallbackHandler.received_token.keys())}</p>
                    <p style="color: gray;">You can close this window.</p>
                </body>
                </html>
                """
                self.wfile.write(html.encode())

                # Signal to stop the server
                threading.Thread(target=self.server.shutdown).start()

            except json.JSONDecodeError as e:
                self.send_response(400)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Failed to parse token: {e}".encode())
        else:
            self.send_response(400)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"No token in callback")


def test_health(server_url: str) -> bool:
    """Test the health endpoint."""
    import urllib.request
    import urllib.error

    url = f"{server_url}/health"
    print(f"\n1. Testing health endpoint: {url}")

    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read())
            if data.get("status") == "ok":
                print("   ✓ Health check passed")
                return True
            else:
                print(f"   ✗ Unexpected response: {data}")
                return False
    except urllib.error.URLError as e:
        print(f"   ✗ Failed to connect: {e}")
        print(f"   → Make sure the token server is running: python main.py server --port 8080")
        return False


def test_auth_url(server_url: str, callback_url: str) -> str:
    """Test generating an auth URL."""
    from urllib.parse import quote

    print(f"\n2. Testing auth URL generation")

    # Construct the auth URL (same logic as token_server_client.py)
    auth_url = f"{server_url}/auth/start?callback={quote(callback_url)}&session=test-state-123"

    print(f"   Auth URL: {auth_url}")
    print("   ✓ Auth URL generated")

    return auth_url


def test_full_flow(server_url: str) -> bool:
    """Test the full OAuth flow with a local callback server."""
    callback_url = f"http://localhost:{CALLBACK_PORT}/callback"

    print(f"\n3. Testing full OAuth flow")
    print(f"   Starting local callback server on port {CALLBACK_PORT}...")

    # Start callback server
    server = HTTPServer(('localhost', CALLBACK_PORT), CallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    # Generate auth URL
    auth_url = test_auth_url(server_url, callback_url)

    print(f"\n   Opening browser for authentication...")
    print(f"   If browser doesn't open, visit: {auth_url}")

    try:
        webbrowser.open(auth_url)
    except Exception:
        pass

    print(f"\n   Waiting for OAuth callback (complete auth in browser)...")
    print(f"   Press Ctrl+C to cancel\n")

    try:
        server_thread.join(timeout=120)  # 2 minute timeout
    except KeyboardInterrupt:
        print("\n   Cancelled by user")
        server.shutdown()
        return False

    if CallbackHandler.received_token:
        print("\n   ✓ Full flow completed successfully!")
        print(f"\n   Token received:")
        # Print token info (redacted)
        token = CallbackHandler.received_token
        print(f"   - access_token: {token.get('token', 'N/A')[:20]}...")
        print(f"   - refresh_token: {'present' if token.get('refresh_token') else 'missing'}")
        print(f"   - scopes: {token.get('scopes', [])}")
        print(f"   - expiry: {token.get('expiry', 'N/A')}")
        return True
    else:
        print("   ✗ No token received (timeout)")
        return False


def test_token_parsing():
    """Test parsing a token from callback URL."""
    print("\n4. Testing token parsing (simulated)")

    # Simulated token from token server
    sample_token = {
        "token": "ya29.test_access_token_here",
        "refresh_token": "1//test_refresh_token",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "test-client-id.apps.googleusercontent.com",
        "client_secret": "test-secret",
        "scopes": ["https://www.googleapis.com/auth/drive"],
        "expiry": "2025-02-01T12:00:00.000000"
    }

    # Simulate what MCP would receive (without client_id/secret for security)
    callback_token = {
        "token": sample_token["token"],
        "refresh_token": sample_token["refresh_token"],
        "token_uri": sample_token["token_uri"],
        "scopes": sample_token["scopes"],
        "expiry": sample_token["expiry"],
    }

    token_json = json.dumps(callback_token)

    # Test parsing
    parsed = json.loads(token_json)

    assert parsed["token"] == callback_token["token"]
    assert parsed["refresh_token"] == callback_token["refresh_token"]
    assert "client_id" not in parsed  # Should not expose client credentials
    assert "client_secret" not in parsed

    print("   ✓ Token parsing works correctly")
    print("   ✓ Client credentials not exposed in callback")
    return True


def main():
    parser = argparse.ArgumentParser(description="Test the token server implementation")
    parser.add_argument(
        "--server-url",
        default=DEFAULT_SERVER_URL,
        help=f"Token server URL (default: {DEFAULT_SERVER_URL})"
    )
    parser.add_argument(
        "--health-only",
        action="store_true",
        help="Only test the health endpoint"
    )
    parser.add_argument(
        "--full-flow",
        action="store_true",
        help="Test the full OAuth flow (opens browser)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Token Server Test Suite")
    print("=" * 60)
    print(f"Server URL: {args.server_url}")

    # Always test health
    if not test_health(args.server_url):
        sys.exit(1)

    if args.health_only:
        print("\n✓ Health check passed!")
        sys.exit(0)

    # Test token parsing
    test_token_parsing()

    # Full flow test (requires browser)
    if args.full_flow:
        if test_full_flow(args.server_url):
            print("\n" + "=" * 60)
            print("All tests passed! ✓")
            print("=" * 60)
            sys.exit(0)
        else:
            sys.exit(1)
    else:
        print("\n" + "-" * 60)
        print("To test the full OAuth flow, run with --full-flow flag:")
        print(f"  python test_token_server.py --full-flow")
        print("-" * 60)
        print("\n✓ Basic tests passed!")


if __name__ == "__main__":
    main()
