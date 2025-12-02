# gdrive

A CLI tool for Google Drive file operations — upload files and export Google Workspace documents.

Available in both Python and Node.js implementations.

## Quick Start

```bash
# Upload a file (Python, default)
./cli upload document.md

# Export a Google Doc to Markdown
./cli export 1abc123xyz output.md

# Use Node.js implementation instead
./cli --node upload document.md
./cli --node export 1abc123xyz output.md
```

## Installation

Dependencies are **automatically installed** on first run:

- **Python**: Uses `uv run` which automatically manages dependencies from `pyproject.toml`
- **Node.js**: Runs `npm install` automatically if `node_modules` doesn't exist

### Prerequisites

- **Python**: Requires [uv](https://docs.astral.sh/uv/) to be installed
- **Node.js**: Requires [Node.js](https://nodejs.org/) (v18+) and npm

## Authentication

The tool supports two authentication methods:

### Option 1: OAuth 2.0 (Client Secret)

1. Create OAuth 2.0 credentials in the [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Download the credentials JSON file
3. Either:
   - Set the `GOOGLE_CREDENTIALS` environment variable with the JSON content
   - Or pass the file path with `--credentials-fpath`

On first run, a browser window will open for authentication. The token is saved to `token.json` (or the path specified by `--token-path` / `GOOGLE_TOKEN` env var) for future use.

### Option 2: Service Account

1. Create a service account in the [Google Cloud Console](https://console.cloud.google.com/iam-admin/serviceaccounts)
2. Download the service account JSON key
3. Either:
   - Set the `GOOGLE_CREDENTIALS` environment variable with the JSON content
   - Or save it as `service_account.json` in the working directory
   - Or pass the file path with `--credentials-fpath`

## Commands

> **Tip:** Add `--node` before any command to use the Node.js implementation instead of Python.

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
```

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
      "last_operation": "2025-12-02T10:30:00Z"
    }
  },
  "exports": {
    "1abc123xyz": {
      "local_path": "/absolute/path/to/exported.md",
      "drive_file_id": "1abc123xyz",
      "last_operation": "2025-12-02T10:35:00Z"
    }
  }
}
```

This allows:

- **Updating existing files** instead of creating duplicates when you upload the same file again
- **Tracking** which files have been uploaded and exported
- **Timestamps** showing when each operation was last performed

You can specify a custom path with `--mapping-path`.

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
