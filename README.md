# gdrive

A CLI tool for Google Drive file operations — upload files and export Google Workspace documents.

Available in both Python and Node.js implementations.

## Quick Start

```bash
# Upload a file (Python, default)
./cli upload document.md

# Export a Google Doc to Markdown
./cli export 1abc123xyz output.md

# Re-export all previously exported documents (sync with latest from Drive)
./cli pull

# Re-upload all previously uploaded files (sync local changes to Drive)
./cli push

# Use Node.js implementation instead
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
# Authenticate via token server and upload a file
./cli upload document.md --token-server http://your-server:8080

# The token is automatically saved for future use
./cli upload another-doc.md
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

## Commands

> **Tip:** Add `--node` before any command to use the Node.js implementation instead of Python.

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

Upload a file to Google Drive. If the same file was previously uploaded, it will be updated instead of creating a duplicate.

```bash
./cli [--node] upload <file_path> [options]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--source-mimetype` | | MIME type of the source file (auto-detected from extension) |
| `--destination-mimetype` | | MIME type for the destination file in Drive |
| `--credentials-fpath` | `-c` | Path to credentials JSON file |
| `--token-path` | `-t` | Path to save/load OAuth token (default: `token.json`) |
| `--mapping-path` | `-m` | Path to files mapping JSON (default: `files-mapping.json`) |
| `--token-server` | | URL of token server to fetch OAuth token from |
| `--overwrite` | | Skip upstream modification check and overwrite without prompting |

**Examples:**

```bash
# Upload a markdown file as-is
./cli upload document.md

# Upload a markdown file and convert it to Google Docs
./cli upload document.md \
  --source-mimetype text/markdown \
  --destination-mimetype "application/vnd.google-apps.document"

# Upload a PDF
./cli upload report.pdf

# Upload using a token server for authentication
./cli upload document.md --token-server http://your-server:8080
```

### export

Export a Google Workspace document (Docs, Sheets, Slides, Drawings) to a local file.

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
      "destination_mimetype": "application/vnd.google-apps.document"
    }
  },
  "exports": {
    "1abc123xyz": {
      "local_path": "/absolute/path/to/exported.md",
      "drive_file_id": "1abc123xyz",
      "last_operation": "2025-12-02T10:35:00Z",
      "export_format": "md"
    }
  }
}
```

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

## Token Server

The token server allows users without their own Google Cloud credentials to authenticate through a shared OAuth application. This is useful for teams or organizations where:

- Only a few people have access to Google Cloud Console
- You want to simplify onboarding for new users
- You need to provide CLI access to external collaborators

### Setting Up a Token Server

1. **Create OAuth credentials** in Google Cloud Console:
   - Go to [APIs & Services > Credentials](https://console.cloud.google.com/apis/credentials)
   - Create an OAuth 2.0 Client ID (Web application type)
   - Add `http://localhost:8080/auth/callback` to Authorized redirect URIs
   - For production, also add your server's public URL

2. **Start the server**:
   ```bash
   # Using credentials from environment variable
   export GOOGLE_CREDENTIALS='{"installed":{"client_id":"...","client_secret":"..."}}'
   ./cli server --port 8080

   # Using credentials from file
   ./cli server -c credentials.json --port 8080
   ```

3. **Share the URL** with your users (e.g., `http://your-server:8080`)

### Security Considerations

- The token server only generates OAuth tokens; it doesn't store them
- Each user gets their own token linked to their Google account
- Users can revoke access at any time in their [Google Account settings](https://myaccount.google.com/permissions)
- Consider running behind HTTPS in production
- The server doesn't require any database or persistent storage

## Project Structure

```
gdrive/
├── cli              # Shell script wrapper (handles both implementations)
├── README.md
├── python/          # Python implementation (default)
│   ├── main.py
│   ├── pyproject.toml
│   └── uv.lock
└── nodejs/          # Node.js implementation (use --node flag)
    ├── main.js
    ├── package.json
    └── README.md
```

Both implementations have feature parity and use the same `files-mapping.json` format, so you can switch between them as needed.
