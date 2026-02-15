/**
 * Token Server Adapter - Unified interface for multiple OAuth token server types.
 *
 * This adapter supports two server implementations:
 * 1. Current gdrive server (Python/Node.js) - /auth/start, /auth/callback, /auth/refresh
 * 2. Next.js server (obsidian-google-drive-website) - /api/tokens, /api/access
 *
 * The adapter automatically detects the server type and adapts requests/responses accordingly.
 */

import http from 'http';
import https from 'https';
import { URL } from 'url';
import crypto from 'crypto';
import open from 'open';

/**
 * @typedef {'gdrive' | 'nextjs' | 'unknown'} ServerType
 */

/**
 * @typedef {Object} TokenData
 * @property {string} token - Access token
 * @property {string} refresh_token - Refresh token
 * @property {string} expiry - ISO 8601 expiry time
 * @property {string} token_uri - OAuth token endpoint
 * @property {string[]} scopes - List of scopes
 * @property {string} issuer - OAuth issuer (https://accounts.google.com)
 * @property {string} token_server - URL of token server that issued the token
 */

export class TokenServerAdapter {
  /**
   * Initialize the adapter with a server URL.
   * @param {string} serverUrl - Base URL of the token server
   */
  constructor(serverUrl) {
    this.serverUrl = serverUrl.replace(/\/$/, '');
    this._serverType = null;
  }

  /**
   * Detect the type of token server by probing its endpoints.
   * @returns {Promise<ServerType>}
   */
  async detectServerType() {
    if (this._serverType) {
      return this._serverType;
    }

    // Try gdrive server health check
    try {
      const result = await this._httpRequest(`${this.serverUrl}/health`, 'GET', null, 3000);
      if (result.statusCode === 200) {
        this._serverType = 'gdrive';
        return this._serverType;
      }
    } catch (error) {
      // Continue to next check
    }

    // Try to detect Next.js server by checking if /api/ping exists
    try {
      const result = await this._httpRequest(`${this.serverUrl}/api/ping`, 'GET', null, 3000);
      if (result.statusCode === 200) {
        this._serverType = 'nextjs';
        return this._serverType;
      }
    } catch (error) {
      // Continue
    }

    // Default to gdrive server (backward compatibility)
    this._serverType = 'gdrive';
    return this._serverType;
  }

  /**
   * Fetch a new OAuth token by opening a browser for user authentication.
   * @param {string} [tokenPath] - Path where the token will be saved (for logging)
   * @returns {Promise<TokenData>}
   */
  async fetchTokenInteractive(tokenPath = null) {
    const serverType = await this.detectServerType();

    if (serverType === 'gdrive') {
      return this._fetchTokenGdriveServer();
    } else if (serverType === 'nextjs') {
      return this._fetchTokenNextjsServer();
    } else {
      throw new Error(`Unknown server type: ${serverType}`);
    }
  }

  /**
   * Refresh an access token using a refresh token.
   * @param {string} refreshToken - The refresh token to use
   * @returns {Promise<Object|null>} Dict with 'token' and 'expiry', or null if failed
   */
  async refreshToken(refreshToken) {
    const serverType = await this.detectServerType();

    if (serverType === 'gdrive') {
      return this._refreshTokenGdriveServer(refreshToken);
    } else if (serverType === 'nextjs') {
      return this._refreshTokenNextjsServer(refreshToken);
    } else {
      return null;
    }
  }

  /**
   * Fetch token from gdrive server using /auth/start flow.
   * @private
   */
  async _fetchTokenGdriveServer() {
    console.log(`Opening browser to authenticate via ${this.serverUrl}...`);

    const sessionId = crypto.randomBytes(16).toString('hex');
    const serverUrl = this.serverUrl; // Capture for closure

    return new Promise((resolve, reject) => {
      let receivedToken = null;

      // Create local callback server
      const server = http.createServer((req, res) => {
        const url = new URL(req.url, 'http://localhost');

        if (url.pathname === '/callback') {
          const tokenParam = url.searchParams.get('token');
          if (tokenParam) {
            try {
              receivedToken = JSON.parse(tokenParam);

              res.writeHead(200, { 'Content-Type': 'text/html' });
              res.end(`
                <html>
                  <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h1>Token received!</h1>
                    <p>You can close this window and return to the terminal.</p>
                  </body>
                </html>
              `);

              setTimeout(() => {
                server.close();
                // Add token_server field to track where it came from
                receivedToken.token_server = serverUrl;
                resolve(receivedToken);
              }, 100);
            } catch (error) {
              res.writeHead(400);
              res.end(`Error: ${error.message}`);
            }
          } else {
            res.writeHead(400);
            res.end('No token received');
          }
        }
      });

      server.listen(0, 'localhost', () => {
        const localPort = server.address().port;
        const callbackUrl = encodeURIComponent(`http://localhost:${localPort}/callback`);
        const authUrl = `${this.serverUrl}/auth/start?callback=${callbackUrl}&session=${sessionId}`;

        open(authUrl).catch(err => {
          console.error('Failed to open browser:', err);
          console.log(`Please open this URL manually: ${authUrl}`);
        });

        // Timeout after 5 minutes
        setTimeout(() => {
          if (!receivedToken) {
            server.close();
            reject(new Error('Authentication timed out'));
          }
        }, 300000);
      });
    });
  }

  /**
   * Fetch token from Next.js server using manual web flow.
   * @private
   */
  async _fetchTokenNextjsServer() {
    const serverUrl = this.serverUrl; // Capture for use in closure
    
    console.log('\n' + '='.repeat(70));
    console.log('MANUAL AUTHENTICATION REQUIRED');
    console.log('='.repeat(70) + '\n');
    console.log(`The Next.js server at ${serverUrl} requires manual authentication.`);
    console.log('\nSteps:');
    console.log(`  1. Opening browser to ${serverUrl}...`);
    console.log('  2. Sign in with Google when prompted');
    console.log('  3. Copy the displayed refresh token');
    console.log('  4. Return here to paste it\n');

    // Open the Next.js website
    await open(serverUrl);

    // Wait a moment for browser to open
    await new Promise(resolve => setTimeout(resolve, 2000));

    console.log('Waiting for you to complete authentication in the browser...');
    console.log('\nOnce you\'ve signed in and see your refresh token:');

    // Import readline for user input
    const readline = await import('readline');
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    // Prompt for refresh token input
    return new Promise((resolve, reject) => {
      const promptForToken = async () => {
        console.log('\nPaste the refresh token from the browser (or press Ctrl+C to cancel):');
        console.log('(It should look like: 1//01abc...xyz)\n');
        process.stdout.write('→ ');

        rl.once('line', async (refreshToken) => {
          try {
            refreshToken = refreshToken.trim();

            if (!refreshToken) {
              console.log('\n✗ Error: No token provided');
              await promptForToken();
              return;
            }

            // Validate it looks like a refresh token (basic check)
            if (!refreshToken.startsWith('1//')) {
              console.log('\n✗ Error: This doesn\'t look like a valid refresh token');
              console.log('Refresh tokens typically start with \'1//\'');
              console.log('Please copy the token exactly as shown in the browser');
              await promptForToken();
              return;
            }

            console.log('\n⏳ Exchanging refresh token for access token...');

            // Use the server's /api/access endpoint to get an access token
            try {
              const result = await this._refreshTokenNextjsServer(refreshToken);

              if (result && result.token) {
                // Build complete token data
                const tokenData = {
                  token: result.token,
                  refresh_token: refreshToken,
                  expiry: result.expiry,
                  token_uri: 'https://oauth2.googleapis.com/token',
                  scopes: ['https://www.googleapis.com/auth/drive.file'],
                  issuer: 'https://accounts.google.com',
                  token_server: serverUrl,
                };

                console.log('✓ Token validated and access token obtained successfully!');
                rl.close();
                resolve(tokenData);
              } else {
                console.log('\n✗ Error: Failed to get access token from refresh token');
                console.log('The refresh token may be invalid or expired');
                console.log('Please try authenticating again in the browser');
                await promptForToken();
              }
            } catch (error) {
              console.log(`\n✗ Error: Failed to exchange refresh token: ${error.message}`);
              console.log('Please try authenticating again in the browser');
              await promptForToken();
            }
          } catch (error) {
            console.log(`\n✗ Error: ${error.message}`);
            console.log('Please try again');
            await promptForToken();
          }
        });
      };

      rl.on('close', () => {
        reject(new Error('Authentication cancelled'));
      });

      promptForToken();
    });
  }


  /**
   * Refresh token using gdrive server /auth/refresh endpoint.
   * @private
   */
  async _refreshTokenGdriveServer(refreshToken) {
    try {
      const refreshUrl = `${this.serverUrl}/auth/refresh`;
      const requestData = JSON.stringify({ refresh_token: refreshToken });

      const result = await this._httpRequest(refreshUrl, 'POST', requestData, 10000, {
        'Content-Type': 'application/json',
      });

      return JSON.parse(result.body);
    } catch (error) {
      console.error('Token refresh failed:', error.message);
      return null;
    }
  }

  /**
   * Refresh token using Next.js server /api/access endpoint.
   * @private
   */
  async _refreshTokenNextjsServer(refreshToken) {
    try {
      const accessUrl = `${this.serverUrl}/api/access`;
      const requestData = JSON.stringify({ refresh_token: refreshToken });

      const result = await this._httpRequest(accessUrl, 'POST', requestData, 10000, {
        'Content-Type': 'application/json',
        'Origin': this.serverUrl,
      });

      const data = JSON.parse(result.body);

      // Transform Next.js format to standard format
      const now = new Date();
      const expiresIn = data.expires_in || 3599;
      const expiry = new Date(now.getTime() + expiresIn * 1000);

      return {
        token: data.access_token,
        expiry: expiry.toISOString(),
      };
    } catch (error) {
      console.error('Token refresh failed:', error.message);
      return null;
    }
  }

  /**
   * Make an HTTP(S) request.
   * @private
   */
  _httpRequest(url, method, data = null, timeout = 10000, headers = {}) {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const isHttps = urlObj.protocol === 'https:';
      const httpModule = isHttps ? https : http;

      // Prepare headers
      const requestHeaders = { ...headers };
      
      // Add Content-Length if we have data
      if (data) {
        requestHeaders['Content-Length'] = Buffer.byteLength(data);
      }

      const options = {
        method,
        headers: requestHeaders,
        timeout,
      };

      const req = httpModule.request(url, options, (res) => {
        let body = '';
        res.on('data', (chunk) => body += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ statusCode: res.statusCode, body });
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${body}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      if (data) {
        req.write(data);
      }

      req.end();
    });
  }
}

/**
 * Factory function to create a token server adapter.
 * @param {string} serverUrl - Base URL of the token server
 * @returns {TokenServerAdapter}
 */
export function createAdapter(serverUrl) {
  return new TokenServerAdapter(serverUrl);
}
