# gdrive

A CLI tool for Google Drive file operations — upload files and export Google Workspace documents.

Available in both Python and Node.js implementations.

## Quick Start

```bash
# Login to Google (first time setup)
./cli login

# Check which account you're logged in as
./cli whoami

# Upload a file (Python, default)
./cli upload document.md

# Export a Google Doc to Markdown
./cli export 1abc123xyz output.md

# Share an uploaded file with someone
./cli share document.md user@example.com

# Re-export all previously exported documents (sync with latest from Drive)
./cli pull

# Re-upload all previously uploaded files (sync local changes to Drive)
./cli push

# Sync: pull then push in one command
./cli sync

# List all shared drives you have access to
./cli list-drives

# Upload to a shared drive
./cli upload document.md --drive-name "My Shared Drive"

# Use Node.js implementation instead
./cli --node login
./cli --node upload document.md
./cli --node export 1abc123xyz output.md
./cli --node pull
```

## Installation

Dependencies are **automatically installed** on first run:

- **Python**: Uses `uv run` which automatically manages dependencies from `pyproject.toml`
- **Node.js**: Runs `npm install` automatically if `node_modules` doesn't exist

### Prerequisites

- **Python**: Requires [uv](https://docs.astral.sh/uv/) to be installed
- **Node.js**: Requires [Node.js](https://nodejs.org/) (v18+) and npm

## Authentication

The tool supports three authentication methods:

### Option 1: Token Server (No Credentials Required)

If someone in your organization runs a token server, you can authenticate without having your own Google Cloud credentials:

```bash
# Set the token server URL once via environment variable
export OAUTH_TOKEN_SERVER=http://your-server:8080

# Then just use the CLI normally
./cli login
./cli upload document.md

# Or pass it explicitly
./cli upload document.md --token-server http://your-server:8080
```

See [Token Server](#token-server) section for how to run your own server.

### Option 2: OAuth 2.0 (Client Secret)

1. Create OAuth 2.0 credentials in the [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Download the credentials JSON file
3. Either:
   - Set the `GOOGLE_CREDENTIALS` environment variable with the JSON content
   - Or pass the file path with `--credentials-fpath`

On first run, a browser window will open for authentication. The token is saved to `token.json` (or the path specified by `--token-path` / `GOOGLE_TOKEN` env var) for future use.

### Option 3: Service Account

1. Create a service account in the [Google Cloud Console](https://console.cloud.google.com/iam-admin/serviceaccounts)
2. Download the service account JSON key
3. Either:
   - Set the `GOOGLE_CREDENTIALS` environment variable with the JSON content
   - Or save it as `service_account.json` in the working directory
   - Or pass the file path with `--credentials-fpath`

## Logging In to a New Google Account

If you're setting up gdrive for the first time or need to authenticate with a different Google account:

### Quick Login (OAuth)

1. **Get OAuth credentials** from [Google Cloud Console](https://console.cloud.google.com/apis/credentials):
   - Create a new project (or select existing)
   - Enable the Google Drive API
   - Create OAuth 2.0 Client ID (Desktop application type)
   - Download the credentials JSON file

2. **Run the login command**:

   ```bash
   # Set credentials via environment variable
   export GOOGLE_CREDENTIALS=$(cat path/to/credentials.json)
   ./cli login

   # Or pass credentials file directly
   ./cli login --credentials-fpath path/to/credentials.json
   ```

3. **Authorize in browser**: A browser window opens automatically. Sign in with your Google account and grant access to Google Drive.

4. **Token saved**: The OAuth token is saved to `token.json` for future use. Subsequent commands won't require browser authentication.

### Switching Accounts

To login with a different Google account:

```bash
# Force re-authentication with a new account
./cli login --force
```

Or manually remove the existing token:

```bash
rm token.json
./cli login
```

### Using a Token Server

If your organization runs a token server, you don't need your own Google Cloud credentials:

```bash
./cli login --token-server http://your-server:8080
```

This opens a browser for Google authentication via the shared server.

## Commands

> **Tip:** Add `--node` before any command to use the Node.js implementation instead of Python.

### login

Authenticate with Google and save the OAuth token for future use.

```bash
./cli [--node] login [options]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--credentials-fpath` | `-c` | Path to credentials JSON file |
| `--token-path` | `-t` | Path to save OAuth token (default: `token.json`) |
| `--token-server` | | URL of token server to fetch OAuth token from |
| `--force` | `-f` | Force re-authentication even if a valid token exists |

**Examples:**

```bash
# Login with default settings (opens browser)
./cli login

# Login with specific credentials file
./cli login -c my-credentials.json

# Force re-authentication (switch accounts)
./cli login --force

# Login via token server
./cli login --token-server http://your-server:8080

# Save token to custom path
./cli login --token-path ~/.config/gdrive/token.json
```

### whoami

Show the currently authenticated Google account.

```bash
./cli [--node] whoami [options]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--token-path` | `-t` | Path to OAuth token (default: `token.json`) |

**Examples:**

```bash
# Show current account
./cli whoami

# Check account with custom token path
./cli whoami --token-path ~/.config/gdrive/token.json
```

The account email is stored in `token.json` when you authenticate and displayed automatically during login.

### server

Start an OAuth token server that allows users without their own Google Cloud credentials to authenticate.

```bash
./cli [--node] server [options]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--port` | `-p` | Port to listen on (default: `8080`) |
| `--credentials-fpath` | `-c` | Path to credentials JSON file |

**Examples:**

```bash
# Start server on default port 8080
./cli server

# Start server on custom port
./cli server --port 3000

# Use specific credentials file
./cli server -c my-credentials.json
```

**How it works:**

1. The server operator runs the server with their OAuth credentials
2. Users visit the server URL (e.g., `http://your-server:8080`)
3. Users click "Sign in with Google" and authorize the application
4. The token is displayed for manual copying, or automatically received when using `--token-server`

**Using the server from CLI:**

```bash
# Authenticate via token server and upload
./cli upload document.md --token-server http://your-server:8080

# Authenticate via token server and export
./cli export 1abc123xyz output.md --token-server http://your-server:8080
```

### upload

Upload a file to Google Drive. If the same file was previously uploaded, it will be updated instead of creating a duplicate. Supports shared drives.

```bash
./cli [--node] upload <file_path> [options]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--source-mimetype` | `-s` | MIME type of the source file (auto-detected from extension) |
| `--destination-mimetype` | `-d` | MIME type for the destination file in Drive |
| `--credentials-fpath` | `-c` | Path to credentials JSON file |
| `--token-path` | `-t` | Path to save/load OAuth token (default: `token.json`) |
| `--mapping-path` | `-m` | Path to files mapping JSON (default: `files-mapping.json`) |
| `--token-server` | | URL of token server to fetch OAuth token from |
| `--overwrite` | | Skip upstream modification check and overwrite without prompting |
| `--folder-id` | | Parent folder ID to upload into (shared drive root or folder within) |
| `--drive-id` | | Shared drive ID (for tracking in mapping file) |
| `--drive-name` | | Shared drive name (resolved to ID automatically) |

**MIME Type Aliases:**

Instead of full MIME types, you can use short aliases:

| Alias | MIME Type |
|-------|-----------|
| `md` | `text/markdown` |
| `txt` | `text/plain` |
| `html` | `text/html` |
| `pdf` | `application/pdf` |
| `docx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| `xlsx` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` |
| `pptx` | `application/vnd.openxmlformats-officedocument.presentationml.presentation` |
| `csv` | `text/csv` |
| `json` | `application/json` |
| `gdoc` | `application/vnd.google-apps.document` |
| `gsheet` | `application/vnd.google-apps.spreadsheet` |
| `gslide` | `application/vnd.google-apps.presentation` |
| `gdraw` | `application/vnd.google-apps.drawing` |

**Examples:**

```bash
# Upload a markdown file as-is
./cli upload document.md

# Upload a markdown file and convert it to Google Docs (short form)
./cli upload document.md -s md -d gdoc

# Upload a markdown file and convert it to Google Docs (long form)
./cli upload document.md \
  --source-mimetype text/markdown \
  --destination-mimetype "application/vnd.google-apps.document"

# Upload a CSV and convert to Google Sheets
./cli upload data.csv -d gsheet

# Upload a PDF
./cli upload report.pdf

# Upload using a token server for authentication
./cli upload document.md --token-server http://your-server:8080

# Upload to a shared drive (by name)
./cli upload document.md --drive-name "Engineering"

# Upload to a specific folder in a shared drive
./cli upload document.md --folder-id FOLDER_ID --drive-id DRIVE_ID
```

### export

Export a Google Workspace document (Docs, Sheets, Slides, Drawings) to a local file. Supports shared drives.

```bash
./cli [--node] export <file_id> <output_path> [options]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--format` | `-f` | Export format (default: `md`) |
| `--credentials-fpath` | `-c` | Path to credentials JSON file |
| `--token-path` | `-t` | Path to save/load OAuth token (default: `token.json`) |
| `--mapping-path` | `-m` | Path to files mapping JSON (default: `files-mapping.json`) |
| `--token-server` | | URL of token server to fetch OAuth token from |
| `--drive-id` | | Shared drive ID (for tracking in mapping file) |
| `--drive-name` | | Shared drive name (resolved to ID for tracking) |

**Examples:**

```bash
# Export a Google Doc to Markdown
./cli export 1abc123xyz output.md

# Export a Google Doc to Word
./cli export 1abc123xyz document.docx --format docx

# Export a Google Sheet to CSV
./cli export 1abc123xyz data.csv --format csv

# Export a Google Doc to PDF
./cli export 1abc123xyz document.pdf --format pdf

# Export using a token server for authentication
./cli export 1abc123xyz output.md --token-server http://your-server:8080

# Export from a shared drive (track drive ID in mapping)
./cli export 1abc123xyz output.md --drive-name "Engineering"
```

### pull

Re-export all documents that have been previously exported. This is useful for syncing local files with the latest content from Google Drive.

```bash
./cli [--node] pull [options]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--credentials-fpath` | `-c` | Path to credentials JSON file |
| `--token-path` | `-t` | Path to save/load OAuth token (default: `token.json`) |
| `--mapping-path` | `-m` | Path to files mapping JSON (default: `files-mapping.json`) |
| `--token-server` | | URL of token server to fetch OAuth token from |

**Examples:**

```bash
# Re-export all previously exported documents
./cli pull

# Re-export using a custom mapping file
./cli pull --mapping-path my-mapping.json

# Re-export using Node.js implementation
./cli --node pull

# Re-export using a token server for authentication
./cli pull --token-server http://your-server:8080
```

**How it works:**

1. Reads the `exports` section from `files-mapping.json`
2. For each exported file, downloads the latest version from Google Drive
3. Writes the content to the same local path as the original export
4. Updates the `last_operation` timestamp in the mapping

### push

Re-upload all files that have been previously uploaded. This is useful for syncing local changes back to Google Drive.

```bash
./cli [--node] push [options]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--credentials-fpath` | `-c` | Path to credentials JSON file |
| `--token-path` | `-t` | Path to save/load OAuth token (default: `token.json`) |
| `--mapping-path` | `-m` | Path to files mapping JSON (default: `files-mapping.json`) |
| `--overwrite` | | Skip upstream modification check and overwrite without prompting |
| `--token-server` | | URL of token server to fetch OAuth token from |

**Examples:**

```bash
# Re-upload all previously uploaded files
./cli push

# Re-upload using a custom mapping file
./cli push --mapping-path my-mapping.json

# Re-upload without prompting for upstream changes
./cli push --overwrite

# Re-upload using Node.js implementation
./cli --node push

# Re-upload using a token server for authentication
./cli push --token-server http://your-server:8080
```

**How it works:**

1. Reads the `uploads` section from `files-mapping.json`
2. For each uploaded file, uploads the local version to Google Drive
3. Warns if the upstream file was modified after the last operation (unless `--overwrite` is used)
4. Updates the `last_operation` timestamp in the mapping

### sync

Sync all documents: first pull (re-export), then push (re-upload). Combines both operations in a single command.

```bash
./cli [--node] sync [options]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--credentials-fpath` | `-c` | Path to credentials JSON file |
| `--token-path` | `-t` | Path to save/load OAuth token (default: `token.json`) |
| `--mapping-path` | `-m` | Path to files mapping JSON (default: `files-mapping.json`) |
| `--overwrite` | | Skip upstream modification check and overwrite without prompting |
| `--token-server` | | URL of token server to fetch OAuth token from |

**Examples:**

```bash
# Sync all files (pull then push)
./cli sync

# Sync with overwrite (no prompts for conflicts)
./cli sync --overwrite

# Sync using Node.js implementation
./cli --node sync
```

### list-drives

List all shared drives accessible to the user.

```bash
./cli [--node] list-drives [options]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--credentials-fpath` | `-c` | Path to credentials JSON file |
| `--token-path` | `-t` | Path to save/load OAuth token (default: `token.json`) |
| `--token-server` | | URL of token server to fetch OAuth token from |
| `--query` | `-q` | Search query to filter drives |

**Examples:**

```bash
# List all shared drives
./cli list-drives

# Filter by name
./cli list-drives --query "name contains 'Engineering'"

# Filter by creation date
./cli list-drives --query "createdTime > '2024-01-01'"
```

**Query Operators:**

| Operator | Example | Description |
|----------|---------|-------------|
| `=` | `name = 'Engineering'` | Exact match |
| `contains` | `name contains 'project'` | Partial match |
| `>` / `>=` | `createdTime > '2024-01-01'` | Date/number comparison |
| `and` | `name contains 'dev' and createdTime > '2024-01-01'` | Combine conditions |

### share

Share an uploaded file with one or more email addresses.

```bash
./cli [--node] share <file_path> <emails> [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `file_path` | Path to the local file (must have been previously uploaded) |
| `emails` | Email address(es) to share with (comma-separated for multiple) |

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--role` | `-r` | Permission role: `reader`, `writer`, or `commenter` (default: `reader`) |
| `--notify/--no-notify` | | Send notification email to recipients (default: `--notify`) |
| `--credentials-fpath` | `-c` | Path to credentials JSON file |
| `--token-path` | `-t` | Path to save/load OAuth token (default: `token.json`) |
| `--mapping-path` | `-m` | Path to files mapping JSON (default: `files-mapping.json`) |
| `--token-server` | | URL of token server to fetch OAuth token from |

**Examples:**

```bash
# Share with a single user as viewer (default)
./cli share document.md user@example.com

# Share with multiple users
./cli share document.md "user1@example.com,user2@example.com"

# Share with write access
./cli share document.md user@example.com --role writer

# Share with comment access
./cli share document.md user@example.com --role commenter

# Share without sending notification email
./cli share document.md user@example.com --no-notify

# Share using Node.js implementation
./cli --node share document.md user@example.com
```

**Note:** The file must have been previously uploaded using the `upload` command. The command uses the local file path to look up the corresponding Google Drive file ID from the mapping.

## Supported Export Formats

| Format | Extension | Document Types |
|--------|-----------|----------------|
| Markdown | `md` | Documents |
| Microsoft Word | `docx` | Documents |
| OpenDocument Text | `odt` | Documents |
| Rich Text | `rtf` | Documents |
| PDF | `pdf` | Documents, Spreadsheets, Presentations, Drawings |
| Plain Text | `txt` | Documents, Presentations |
| HTML (zipped) | `html` | Documents, Spreadsheets |
| EPUB | `epub` | Documents |
| Microsoft Excel | `xlsx` | Spreadsheets |
| OpenDocument Spreadsheet | `ods` | Spreadsheets |
| CSV | `csv` | Spreadsheets (first sheet only) |
| TSV | `tsv` | Spreadsheets (first sheet only) |
| Microsoft PowerPoint | `pptx` | Presentations |
| OpenDocument Presentation | `odp` | Presentations |
| JPEG | `jpg` | Drawings, Presentations (first slide) |
| PNG | `png` | Drawings, Presentations (first slide) |
| SVG | `svg` | Drawings, Presentations (first slide) |
| JSON | `json` | Apps Script |
| MP4 | `mp4` | Google Vids |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GOOGLE_CREDENTIALS` | JSON content of the credentials file (OAuth or Service Account) |
| `GOOGLE_TOKEN` | JSON content of the OAuth token (alternative to `token.json` file) |
| `OAUTH_TOKEN_SERVER` | URL of token server for authentication (alternative to `--token-server` option) |

**Docker:** When running the app in Docker, pass credentials via `--env-file .env` so the JSON is not broken by the shell. In your `.env` file use raw JSON (no quotes around the value), e.g. `GOOGLE_CREDENTIALS={"installed":{"client_id":"..."}}`.

## Token File

The OAuth token is stored in `token.json` with the following structure:

```json
{
  "token": "ya29...",
  "refresh_token": "1//...",
  "token_uri": "https://oauth2.googleapis.com/token",
  "scopes": ["https://www.googleapis.com/auth/drive"],
  "account_email": "user@example.com",
  "issuer": "https://accounts.google.com",
  "token_server": "http://localhost:8080"
}
```

**Note:** `client_id` and `client_secret` are **not** stored in `token.json`. They are read from the `GOOGLE_CREDENTIALS` environment variable or `credentials.json` file during authentication and token refresh operations.

**Field Descriptions:**
- `account_email` - Automatically fetched from Google's userinfo API during authentication for quick identification (use `./cli whoami` to display)
- `issuer` - OAuth issuer identifier (`https://accounts.google.com`) for token validation
- `token_server` - URL of the token server that issued this token (e.g., `http://localhost:8080`). **Automatically used for token refresh** - you don't need to specify `--token-server` on subsequent commands

## Files Mapping

The tool maintains a `files-mapping.json` file that tracks both uploads and exports with timestamps. The structure is defined using Pydantic:

```json
{
  "uploads": {
    "/absolute/path/to/file.md": {
      "local_path": "/absolute/path/to/file.md",
      "drive_file_id": "1abc123xyz",
      "last_operation": "2025-12-02T10:30:00Z",
      "source_mimetype": "text/markdown",
      "destination_mimetype": "application/vnd.google-apps.document",
      "drive_id": "0ABC123DEF"
    }
  },
  "exports": {
    "1abc123xyz": {
      "local_path": "/absolute/path/to/exported.md",
      "drive_file_id": "1abc123xyz",
      "last_operation": "2025-12-02T10:35:00Z",
      "export_format": "md",
      "drive_id": "0ABC123DEF"
    }
  }
}
```

**Fields:**

| Field | Description |
|-------|-------------|
| `local_path` | Absolute path to the local file |
| `drive_file_id` | Google Drive file ID |
| `last_operation` | ISO 8601 timestamp of last operation |
| `source_mimetype` | MIME type of the source file (uploads only) |
| `destination_mimetype` | MIME type for Drive conversion (uploads only) |
| `export_format` | Export format used (exports only) |
| `drive_id` | Shared drive ID if file is in a shared drive (optional) |

This allows:

- **Updating existing files** instead of creating duplicates when you upload the same file again
- **Tracking** which files have been uploaded and exported
- **Re-exporting all documents** with a single `pull` command, preserving the original export format
- **Re-uploading all files** with a single `push` command, preserving the original MIME type conversions
- **Timestamps** showing when each operation was last performed

### Automatic Discovery

The tool automatically searches for `files-mapping.json` in the current directory and parent directories, similar to how Git finds `.git` folders. This means you can run commands from any subdirectory of your project and it will find and use the correct mapping file.

If no mapping file is found, a new one will be created in the current directory.

You can override this behavior by specifying an explicit path with `--mapping-path`.

## Shared Drives Support

The tool fully supports Google Shared Drives (formerly Team Drives). All operations work seamlessly with files in shared drives.

### Listing Shared Drives

```bash
# List all shared drives you have access to
./cli list-drives

# Filter by name
./cli list-drives --query "name contains 'Engineering'"
```

### Uploading to Shared Drives

```bash
# Upload to a shared drive by name (uploads to root)
./cli upload document.md --drive-name "Engineering"

# Upload to a specific folder in a shared drive
./cli upload document.md --folder-id FOLDER_ID --drive-id DRIVE_ID

# Upload to shared drive root using drive ID
./cli upload document.md --drive-id 0ABC123DEF
```

### Exporting from Shared Drives

Files in shared drives can be exported normally using their file ID. To track the shared drive in the mapping file:

```bash
# Export and track the shared drive
./cli export FILE_ID output.md --drive-name "Engineering"
```

### How It Works

- The `--drive-name` option resolves the drive name to its ID automatically
- The `--drive-id` is stored in `files-mapping.json` for tracking purposes
- All API calls include `supportsAllDrives=true` for shared drive compatibility
- Files in shared drives are owned by the drive, not individual users

## Token Server

The token server allows users without their own Google Cloud credentials to authenticate through a shared OAuth application. This is useful for teams or organizations where:

- Only a few people have access to Google Cloud Console
- You want to simplify onboarding for new users
- You need to provide CLI access to external collaborators

### Multiple Server Types Support

The CLI automatically detects and works with different token server implementations:

1. **gdrive server** (this repository) - Lightweight Python/Node.js server with fully automated OAuth
2. **Next.js server** - Full-featured web application (e.g., obsidian-google-drive-website) with manual token copy/paste

The adapter automatically detects the server type and adapts the authentication flow accordingly.

**Note:** Next.js servers require a semi-manual flow where you:
1. Complete OAuth in the browser
2. Copy the displayed refresh token  
3. Paste it into the CLI

This is because Next.js servers are designed for browser-based OAuth (Obsidian plugin use case) and only display the refresh token, not full token JSON. See [USAGE_WITH_NEXTJS.md](USAGE_WITH_NEXTJS.md) for detailed instructions.

### Setting Up a Token Server

The server accepts **Web application** or **Desktop (installed)** OAuth credentials (both Python and Node.js implementations). For running a token server, **Web application** is recommended.

1. **Create OAuth credentials** in Google Cloud Console:
   - Go to [APIs & Services > Credentials](https://console.cloud.google.com/apis/credentials)
   - Create an OAuth 2.0 Client ID (**Web application** type for the server)
   - Enable the Google Drive API for the project
   - Under **Authorized redirect URIs**, add the exact callback URL your server will use:
     - For default port: `http://localhost:8080/auth/callback`
     - For a custom port (e.g. 3000): `http://localhost:3000/auth/callback`
   - For production, also add your server’s public callback URL (e.g. `https://your-server.example.com/auth/callback`)

   The server builds the callback URL from each request’s **Host** (or **X-Forwarded-Host** / **X-Forwarded-Proto** when behind a reverse proxy), so the redirect URI matches how users reach the server. When using a proxy, ensure it forwards these headers.

2. **Start the server**:
   ```bash
   # Using credentials from file (download the JSON from GCP Console; it has a "web" key)
   ./cli server -c credentials.json --port 8080

   # Using credentials from environment variable (Web application format)
   export GOOGLE_CREDENTIALS='{"web":{"client_id":"...","client_secret":"...","redirect_uris":["http://localhost:8080/auth/callback"]}}'
   ./cli server --port 8080
   ```

   Desktop (installed) credentials also work: the server accepts either `"web"` or `"installed"` in the credentials JSON.

3. **Share the URL** with your users (e.g., `http://your-server:8080`)

### Token Refresh

The token server provides a `/auth/refresh` endpoint that allows clients to refresh their access tokens without storing client credentials. This is automatically used by the CLI when tokens expire.

**Endpoint:** `POST /auth/refresh`

**Request:**
```json
{
  "refresh_token": "1//..."
}
```

**Response (success):**
```json
{
  "token": "ya29...",
  "expiry": "2026-02-02T13:00:00Z"
}
```

**Response (error):**
```json
{
  "error": "Failed to refresh token: invalid_grant"
}
```

The CLI automatically refreshes tokens when they expire if you're using a token server. You don't need to manually call this endpoint.

### Security Considerations

- The token server only generates OAuth tokens; it doesn't store them
- Each user gets their own token linked to their Google account
- Users can revoke access at any time in their [Google Account settings](https://myaccount.google.com/permissions)
- Client credentials (client_id and client_secret) never leave the server
- Tokens are automatically refreshed via the server without exposing credentials
- Consider running behind HTTPS in production
- The server doesn't require any database or persistent storage

## Project Structure

```
gdrive/
├── cli              # Shell script wrapper (handles both implementations)
├── README.md
├── python/          # Python implementation (default)
│   ├── main.py
│   ├── token_server_adapter.py  # Universal token server adapter
│   ├── pyproject.toml
│   └── uv.lock
└── nodejs/          # Node.js implementation (use --node flag)
    ├── main.js
    ├── token-server-adapter.js   # Universal token server adapter
    ├── package.json
    └── README.md
```

Both implementations have feature parity and use the same `files-mapping.json` format, so you can switch between them as needed.

### Token Server Adapter

The `token_server_adapter.py` (Python) and `token-server-adapter.js` (Node.js) modules provide a unified interface for communicating with different OAuth token server implementations. The adapter:

- **Auto-detects** server type by probing endpoints (`/health` for gdrive, `/api/ping` for Next.js)
- **Adapts** authentication flow based on server capabilities
- **Transforms** responses to a common format
- **Supports** both token fetching and token refresh operations

This allows the CLI to work seamlessly with multiple token server implementations without any user configuration.
