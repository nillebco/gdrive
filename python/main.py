import asyncio
from datetime import datetime, timezone
import html
from http.server import BaseHTTPRequestHandler
import json
import os
import secrets
import socketserver
import threading
from typing import Annotated, Optional
from urllib.parse import parse_qs, urlparse
import webbrowser

import typer
from asyncer import asyncify
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials as OAuthCredentials
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from pydantic import BaseModel

SCOPES = ["https://www.googleapis.com/auth/drive"]

CREDENTIALS_ENV_VAR = "GOOGLE_CREDENTIALS"
TOKEN_ENV_VAR = "GOOGLE_TOKEN"
TOKEN_SERVER_ENV_VAR = "GDRIVE_TOKEN_SERVER"
DEFAULT_TOKEN_PATH = "token.json"
DEFAULT_MAPPING_PATH = "files-mapping.json"
DEFAULT_SERVER_PORT = 8080

# Token server: in-memory store for pending OAuth sessions
pending_sessions: dict[str, dict] = {}


def _get_token_server(token_server: Optional[str]) -> Optional[str]:
    """Get token server URL from CLI option or environment variable."""
    if token_server:
        return token_server
    return os.environ.get(TOKEN_SERVER_ENV_VAR)


class FileRecord(BaseModel):
    """Record of a file operation (upload or export)."""
    local_path: str
    drive_file_id: str
    last_operation: datetime
    source_mimetype: Optional[str] = None
    destination_mimetype: Optional[str] = None
    export_format: Optional[str] = None  # For exports: the format used (e.g., 'md', 'docx')
    drive_id: Optional[str] = None  # Shared drive ID (if file is in a shared drive)


class FilesMapping(BaseModel):
    """Mapping of files between local filesystem and Google Drive."""
    uploads: dict[str, FileRecord] = {}  # keyed by local_path
    exports: dict[str, FileRecord] = {}  # keyed by drive_file_id


def _find_mapping_file(filename: str = DEFAULT_MAPPING_PATH) -> Optional[str]:
    """Find the mapping file by searching current directory and parents.
    
    Args:
        filename: The mapping filename to search for
        
    Returns:
        The absolute path to the found mapping file, or None if not found
    """
    current = os.path.abspath(os.getcwd())
    
    while True:
        candidate = os.path.join(current, filename)
        if os.path.exists(candidate):
            return candidate
        
        parent = os.path.dirname(current)
        if parent == current:
            # Reached filesystem root
            break
        current = parent
    
    return None


def _load_mapping(mapping_path: Optional[str] = None) -> FilesMapping:
    """Load the files mapping from disk.
    
    If no explicit path is provided, searches for the mapping file
    in the current directory and parent directories.
    """
    if mapping_path:
        # Explicit path provided, use it directly
        path = mapping_path
    else:
        # Search for existing mapping file in current and parent directories
        found_path = _find_mapping_file(DEFAULT_MAPPING_PATH)
        path = found_path or DEFAULT_MAPPING_PATH
    
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
        return FilesMapping.model_validate(data)
    return FilesMapping()


def _get_mapping_path(mapping_path: Optional[str] = None) -> str:
    """Get the path to use for the mapping file.
    
    If no explicit path is provided, searches for an existing mapping file
    in the current directory and parent directories. If not found,
    returns the default path in the current directory.
    """
    if mapping_path:
        return mapping_path
    
    found_path = _find_mapping_file(DEFAULT_MAPPING_PATH)
    return found_path or DEFAULT_MAPPING_PATH


def _save_mapping(mapping: FilesMapping, mapping_path: Optional[str] = None):
    """Save the files mapping to disk.
    
    If no explicit path is provided, saves to the found mapping file location
    (from current or parent directories) or to the default path in the current directory.
    """
    path = _get_mapping_path(mapping_path)
    with open(path, "w") as f:
        f.write(mapping.model_dump_json(indent=2))


def _get_absolute_path(fpath: str) -> str:
    """Get the absolute path for consistent record-keeping."""
    return os.path.abspath(fpath)


def _load_token(
    token_path: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None
) -> Optional[OAuthCredentials]:
    """Load saved OAuth token from file or environment variable.

    Args:
        token_path: Path to token.json file
        client_id: OAuth client ID (required for token refresh)
        client_secret: OAuth client secret (required for token refresh)
    """
    token_data = None

    # Try environment variable first
    token_json = os.environ.get(TOKEN_ENV_VAR)
    if token_json:
        token_data = json.loads(token_json)
    else:
        # Try file
        path = token_path or DEFAULT_TOKEN_PATH
        if os.path.exists(path):
            with open(path, "r") as f:
                token_data = json.load(f)

    if token_data is None:
        return None

    # Inject client_id and client_secret if not present (required by the library)
    if client_id and "client_id" not in token_data:
        token_data["client_id"] = client_id
    if client_secret and "client_secret" not in token_data:
        token_data["client_secret"] = client_secret

    try:
        return OAuthCredentials.from_authorized_user_info(token_data, SCOPES)
    except ValueError:
        # Token data is incomplete (missing client_id/client_secret)
        return None


def _save_token(creds: OAuthCredentials, token_path: Optional[str] = None, account_email: Optional[str] = None):
    """Save OAuth token to file for future use."""
    path = token_path or DEFAULT_TOKEN_PATH
    # Parse the credentials JSON and add account_email if provided
    token_data = json.loads(creds.to_json())
    # Remove client_id and client_secret - they should come from GOOGLE_CREDENTIALS
    token_data.pop("client_id", None)
    token_data.pop("client_secret", None)
    if account_email:
        token_data["account_email"] = account_email
    with open(path, "w") as f:
        json.dump(token_data, f, indent=2)


def _fetch_user_email(access_token: str) -> Optional[str]:
    """Fetch the authenticated user's email from Google's userinfo API."""
    import urllib.request
    import urllib.error
    try:
        req = urllib.request.Request(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            return data.get("email")
    except Exception:
        return None


def _get_stored_account_email(token_path: Optional[str] = None) -> Optional[str]:
    """Get the account email from the stored token."""
    path = token_path or DEFAULT_TOKEN_PATH
    if os.path.exists(path):
        with open(path, "r") as f:
            token_data = json.load(f)
        return token_data.get("account_email")
    return None


def _get_client_credentials(credentials_path: Optional[str] = None) -> tuple[Optional[str], Optional[str]]:
    """Extract client_id and client_secret from credentials source.

    Args:
        credentials_path: Path to credentials JSON file

    Returns:
        Tuple of (client_id, client_secret), both may be None if not found
    """
    data = None

    # Try environment variable first
    credentials_json = os.environ.get(CREDENTIALS_ENV_VAR)
    if credentials_json:
        data = json.loads(credentials_json)
    elif credentials_path and os.path.exists(credentials_path):
        with open(credentials_path, "r") as f:
            data = json.load(f)

    if data and "installed" in data:
        installed = data["installed"]
        return installed.get("client_id"), installed.get("client_secret")

    return None, None


def _get_credentials_client_secret_from_dict(
    data: dict, token_path: Optional[str] = None
) -> OAuthCredentials:
    """Get OAuth credentials, using cached token if available."""
    # Extract client_id and client_secret from credentials data
    installed = data.get("installed", {})
    client_id = installed.get("client_id")
    client_secret = installed.get("client_secret")

    # Try to load existing token (inject client creds for refresh capability)
    creds = _load_token(token_path, client_id=client_id, client_secret=client_secret)

    if creds and creds.valid:
        return creds

    # Try to refresh expired token
    if creds and creds.expired and creds.refresh_token:
        try:
            # Preserve existing account email
            existing_email = _get_stored_account_email(token_path)
            creds.refresh(Request())
            _save_token(creds, token_path, existing_email)
            return creds
        except Exception:
            pass  # Fall through to new OAuth flow

    # Run OAuth flow
    flow = InstalledAppFlow.from_client_config(data, SCOPES)
    creds = flow.run_local_server(port=0)

    # Fetch user email and save with token
    account_email = _fetch_user_email(creds.token)
    _save_token(creds, token_path, account_email)
    return creds


def _get_credentials_service_account_from_dict(data: dict) -> ServiceAccountCredentials:
    return ServiceAccountCredentials.from_service_account_info(data, scopes=SCOPES)


def _detect_credentials_type(data: dict) -> str:
    if "installed" in data:
        return "client_secret"
    return "service_account"


def _get_credentials_from_dict(
    data: dict, token_path: Optional[str] = None
) -> OAuthCredentials | ServiceAccountCredentials:
    """Get credentials from a dict."""
    credentials_type = _detect_credentials_type(data)
    if credentials_type == "service_account":
        return _get_credentials_service_account_from_dict(data)
    elif credentials_type == "client_secret":
        return _get_credentials_client_secret_from_dict(data, token_path)
    else:
        raise ValueError(f"Invalid credentials type: {credentials_type}")


def _parse_credentials_json(credentials_json: str) -> dict:
    """Parse GOOGLE_CREDENTIALS JSON string; raise a clear error on failure."""
    stripped = credentials_json.strip()
    if not stripped:
        raise ValueError(
            f"{CREDENTIALS_ENV_VAR} is set but empty. "
            "Use a .env file with Docker (--env-file .env) or set the variable to valid JSON."
        )
    # Env files often use single quotes around JSON; Docker passes them literally.
    if len(stripped) >= 2 and stripped[0] == "'" and stripped[-1] == "'":
        stripped = stripped[1:-1]
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"{CREDENTIALS_ENV_VAR} is not valid JSON (parse error: {e}). "
            "In .env, use raw JSON: GOOGLE_CREDENTIALS={\"installed\":...} without wrapping in quotes."
        ) from e


def get_credentials(
    fpath: Optional[str] = None, token_path: Optional[str] = None
) -> OAuthCredentials | ServiceAccountCredentials:
    """Get credentials from file path or GOOGLE_CREDENTIALS environment variable."""
    # First, check environment variable
    credentials_json = os.environ.get(CREDENTIALS_ENV_VAR)
    if credentials_json:
        return _get_credentials_from_dict(_parse_credentials_json(credentials_json), token_path)
    
    # Fall back to file path
    if fpath is None:
        fpath = "service_account.json"
    
    with open(fpath, "r") as f:
        data = json.load(f)
    return _get_credentials_from_dict(data, token_path)


MIME_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "md": "text/markdown",
    "txt": "text/plain",
    "html": "text/html",
    "csv": "text/csv",
    "tsv": "text/tab-separated-values",
    "json": "application/json",
    "xml": "application/xml",
    # Google Workspace types (for destination)
    "gdoc": "application/vnd.google-apps.document",
    "gsheet": "application/vnd.google-apps.spreadsheet",
    "gslide": "application/vnd.google-apps.presentation",
    "gdraw": "application/vnd.google-apps.drawing",
}


def _resolve_mimetype(value: Optional[str]) -> Optional[str]:
    """Resolve a MIME type from a short alias or return as-is if it's a full MIME type."""
    if value is None:
        return None
    # If it looks like a full MIME type (contains /), return as-is
    if "/" in value:
        return value
    # Otherwise, look up in the mapping
    return MIME_TYPES.get(value.lower(), value)


def _resolve_drive_id(drive, drive_name: str) -> str:
    """Resolve a shared drive name to its ID.

    Args:
        drive: Google Drive API client
        drive_name: Name of the shared drive

    Returns:
        The drive ID

    Raises:
        ValueError: If drive not found or multiple matches
    """
    # Escape single quotes in the name
    escaped_name = drive_name.replace("'", "\\'")
    response = drive.drives().list(
        q=f"name = '{escaped_name}'",
        fields="drives(id, name)",
        pageSize=10
    ).execute()

    drives = response.get("drives", [])

    if len(drives) == 0:
        raise ValueError(f'Shared drive not found: "{drive_name}"')
    if len(drives) > 1:
        names = "\n".join(f"  - {d['name']} ({d['id']})" for d in drives)
        raise ValueError(
            f'Multiple shared drives match "{drive_name}":\n{names}\n'
            "Please use --drive-id instead."
        )

    return drives[0]["id"]


def _get_drive_id_from_options(drive, drive_id: Optional[str], drive_name: Optional[str]) -> Optional[str]:
    """Get drive ID from either --drive-id or --drive-name option."""
    if drive_id:
        return drive_id
    if drive_name:
        return _resolve_drive_id(drive, drive_name)
    return None


def _get_upstream_modified_time(drive, file_id: str) -> Optional[datetime]:
    """Get the modification time of a file on Google Drive."""
    try:
        response = drive.files().get(
            fileId=file_id,
            fields="modifiedTime",
            supportsAllDrives=True
        ).execute()
        # Parse the ISO format datetime from Google Drive
        modified_time_str = response.get("modifiedTime")
        if modified_time_str:
            # Google Drive returns ISO format with Z suffix
            return datetime.fromisoformat(modified_time_str.replace("Z", "+00:00"))
        return None
    except Exception:
        return None


def _prompt_confirmation(message: str) -> bool:
    """Prompt the user for yes/no confirmation."""
    response = input(f"{message} [y/N]: ")
    return response.lower() in ("y", "yes")

# Export MIME types for Google Workspace documents
EXPORT_MIME_TYPES = {
    # Documents
    "md": "text/markdown",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "odt": "application/vnd.oasis.opendocument.text",
    "rtf": "application/rtf",
    "pdf": "application/pdf",
    "txt": "text/plain",
    "html": "application/zip",
    "epub": "application/epub+zip",
    # Spreadsheets
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ods": "application/vnd.oasis.opendocument.spreadsheet",
    "csv": "text/csv",
    "tsv": "text/tab-separated-values",
    # Presentations
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "odp": "application/vnd.oasis.opendocument.presentation",
    # Drawings
    "jpg": "image/jpeg",
    "png": "image/png",
    "svg": "image/svg+xml",
    # Apps Script
    "json": "application/vnd.google-apps.script+json",
    # Google Vids
    "mp4": "video/mp4",
}

def upload_file(
    fpath: str,
    source_mimetype: Optional[str] = None,
    destination_mimetype: Optional[str] = None,
    credentials_fpath: Optional[str] = None,
    token_path: Optional[str] = None,
    mapping_path: Optional[str] = None,
    overwrite: bool = False,
    folder_id: Optional[str] = None,
    drive_id: Optional[str] = None,
):
    """Upload a file to Google Drive (supports shared drives).

    Args:
        fpath: Path to file to upload
        source_mimetype: MIME type of source file
        destination_mimetype: MIME type for destination file in Drive
        credentials_fpath: Path to credentials file
        token_path: Path to token file
        mapping_path: Path to files mapping file
        overwrite: Skip upstream modification check
        folder_id: Parent folder ID (can be a shared drive root or folder within)
        drive_id: Shared drive ID (for tracking in mapping)
    """
    creds = get_credentials(credentials_fpath, token_path)
    drive = build("drive", "v3", credentials=creds)
    if source_mimetype is None:
        source_mimetype = MIME_TYPES.get(fpath.split(".")[-1])
    if source_mimetype is None:
        raise ValueError(f"Invalid source mimetype: {fpath}, source mimetype: {source_mimetype}")

    # Load existing mapping
    mapping = _load_mapping(mapping_path)
    abs_path = _get_absolute_path(fpath)

    metadata = {"name": os.path.basename(fpath)}
    if destination_mimetype:
        metadata["mimeType"] = destination_mimetype

    # Set parent folder if provided (for shared drives or specific folders)
    if folder_id:
        metadata["parents"] = [folder_id]

    media = MediaFileUpload(fpath, mimetype=source_mimetype)

    # Check if this file was previously uploaded
    existing_record = mapping.uploads.get(abs_path)

    if existing_record:
        # Check for upstream modifications before updating
        if not overwrite:
            upstream_modified_time = _get_upstream_modified_time(drive, existing_record.drive_file_id)
            if upstream_modified_time:
                last_operation = existing_record.last_operation
                # Ensure last_operation is timezone-aware for comparison
                if last_operation.tzinfo is None:
                    last_operation = last_operation.replace(tzinfo=timezone.utc)
                if upstream_modified_time > last_operation:
                    import sys
                    print("Warning: The file on Google Drive was modified after your last operation.", file=sys.stderr)
                    print(f"  Last local operation: {last_operation.isoformat()}", file=sys.stderr)
                    print(f"  Upstream modified:    {upstream_modified_time.isoformat()}", file=sys.stderr)
                    proceed = _prompt_confirmation("Do you want to overwrite the upstream changes?")
                    if not proceed:
                        raise RuntimeError("Upload cancelled by user")
                    # Recreate media in case time passed
                    media = MediaFileUpload(fpath, mimetype=source_mimetype)

        # Update existing file (don't change parents on update)
        update_metadata = {"name": metadata["name"]}
        if destination_mimetype:
            update_metadata["mimeType"] = destination_mimetype
        try:
            result = drive.files().update(
                fileId=existing_record.drive_file_id,
                body=update_metadata,
                media_body=media,
                fields="id",
                supportsAllDrives=True
            ).execute()
            # Update timestamp and mimetypes
            existing_record.last_operation = datetime.now(timezone.utc)
            existing_record.source_mimetype = source_mimetype
            existing_record.destination_mimetype = destination_mimetype
            _save_mapping(mapping, mapping_path)
        except Exception:
            # If update fails (e.g., file was deleted), create a new one
            result = drive.files().create(
                body=metadata,
                media_body=media,
                fields="id",
                supportsAllDrives=True
            ).execute()
            mapping.uploads[abs_path] = FileRecord(
                local_path=abs_path,
                drive_file_id=result["id"],
                last_operation=datetime.now(timezone.utc),
                source_mimetype=source_mimetype,
                destination_mimetype=destination_mimetype,
                drive_id=drive_id,
            )
            _save_mapping(mapping, mapping_path)
    else:
        # Create new file
        result = drive.files().create(
            body=metadata,
            media_body=media,
            fields="id",
            supportsAllDrives=True
        ).execute()
        mapping.uploads[abs_path] = FileRecord(
            local_path=abs_path,
            drive_file_id=result["id"],
            last_operation=datetime.now(timezone.utc),
            source_mimetype=source_mimetype,
            destination_mimetype=destination_mimetype,
            drive_id=drive_id,
        )
        _save_mapping(mapping, mapping_path)

    return result


def export_file(
    file_id: str,
    output_path: str,
    export_format: str = "md",
    credentials_fpath: Optional[str] = None,
    token_path: Optional[str] = None,
    mapping_path: Optional[str] = None,
    drive_id: Optional[str] = None,
) -> str:
    """Export a Google Workspace document to the specified format (supports shared drives).

    Args:
        file_id: Google Drive file ID
        output_path: Path where the exported file will be saved
        export_format: Export format (default: 'md')
        credentials_fpath: Path to credentials file
        token_path: Path to token file
        mapping_path: Path to files mapping file
        drive_id: Shared drive ID (for tracking in mapping)
    """
    creds = get_credentials(credentials_fpath, token_path)
    drive = build("drive", "v3", credentials=creds)

    # Get the MIME type for the export format
    mime_type = EXPORT_MIME_TYPES.get(export_format)
    if mime_type is None:
        raise ValueError(
            f"Invalid export format: {export_format}. "
            f"Supported formats: {', '.join(EXPORT_MIME_TYPES.keys())}"
        )

    # Export the file
    request = drive.files().export(fileId=file_id, mimeType=mime_type)
    content = request.execute()

    # Write to output file
    # For text formats, decode as UTF-8; for binary formats, write as bytes
    text_formats = {"md", "txt", "csv", "tsv", "rtf", "json", "svg"}

    if export_format in text_formats:
        with open(output_path, "w", encoding="utf-8") as f:
            if isinstance(content, bytes):
                f.write(content.decode("utf-8"))
            else:
                f.write(content)
    else:
        with open(output_path, "wb") as f:
            if isinstance(content, bytes):
                f.write(content)
            else:
                f.write(content.encode("utf-8"))

    # Record the export in the mapping
    abs_output_path = _get_absolute_path(output_path)
    mapping = _load_mapping(mapping_path)
    mapping.exports[file_id] = FileRecord(
        local_path=abs_output_path,
        drive_file_id=file_id,
        last_operation=datetime.now(timezone.utc),
        export_format=export_format,
        drive_id=drive_id,
    )
    _save_mapping(mapping, mapping_path)

    return output_path


def pull_all(
    credentials_fpath: Optional[str] = None,
    token_path: Optional[str] = None,
    mapping_path: Optional[str] = None,
) -> list[str]:
    """Re-export all documents that have been previously exported.
    
    Args:
        credentials_fpath: Path to credentials file
        token_path: Path to token file
        mapping_path: Path to files mapping file
    
    Returns:
        List of paths to the re-exported files
    """
    mapping = _load_mapping(mapping_path)
    
    if not mapping.exports:
        return []
    
    creds = get_credentials(credentials_fpath, token_path)
    drive = build("drive", "v3", credentials=creds)
    
    results = []
    for file_id, record in mapping.exports.items():
        output_path = record.local_path
        
        # Use stored export format if available, otherwise determine from file extension
        export_format = record.export_format
        if export_format is None:
            ext = os.path.splitext(output_path)[1].lstrip('.').lower()
            export_format = ext if ext in EXPORT_MIME_TYPES else "md"
        
        # Get the MIME type for the export format
        mime_type = EXPORT_MIME_TYPES.get(export_format)
        if mime_type is None:
            print(f"Warning: Skipping {output_path} - unsupported format: {export_format}")
            continue
        
        try:
            # Export the file
            request = drive.files().export(fileId=file_id, mimeType=mime_type)
            content = request.execute()
            
            # Write to output file
            text_formats = {"md", "txt", "csv", "tsv", "rtf", "json", "svg"}
            
            if export_format in text_formats:
                with open(output_path, "w", encoding="utf-8") as f:
                    if isinstance(content, bytes):
                        f.write(content.decode("utf-8"))
                    else:
                        f.write(content)
            else:
                with open(output_path, "wb") as f:
                    if isinstance(content, bytes):
                        f.write(content)
                    else:
                        f.write(content.encode("utf-8"))
            
            # Update the timestamp in the mapping
            record.last_operation = datetime.now(timezone.utc)
            results.append(output_path)
        except Exception as e:
            print(f"Warning: Failed to re-export {output_path}: {e}")
            continue
    
    # Save updated mapping
    _save_mapping(mapping, mapping_path)
    
    return results


def push_all(
    credentials_fpath: Optional[str] = None,
    token_path: Optional[str] = None,
    mapping_path: Optional[str] = None,
    overwrite: bool = False,
) -> list[str]:
    """Re-upload all files that have been previously uploaded.
    
    Args:
        credentials_fpath: Path to credentials file
        token_path: Path to token file
        mapping_path: Path to files mapping file
        overwrite: Skip upstream modification check and overwrite without prompting
    
    Returns:
        List of paths to the re-uploaded files
    """
    mapping = _load_mapping(mapping_path)
    
    if not mapping.uploads:
        return []
    
    creds = get_credentials(credentials_fpath, token_path)
    drive = build("drive", "v3", credentials=creds)
    
    results = []
    for local_path, record in mapping.uploads.items():
        # Check if local file exists
        if not os.path.exists(local_path):
            print(f"Warning: Skipping {local_path} - file not found")
            continue
        
        # Use stored MIME type if available, otherwise determine from extension
        source_mimetype = record.source_mimetype
        if source_mimetype is None:
            ext = os.path.splitext(local_path)[1].lstrip('.').lower()
            source_mimetype = MIME_TYPES.get(ext)
        if source_mimetype is None:
            ext = os.path.splitext(local_path)[1].lstrip('.').lower()
            print(f"Warning: Skipping {local_path} - unsupported format: {ext}")
            continue
        
        # Use stored destination MIME type if available
        destination_mimetype = record.destination_mimetype
        
        try:
            # Check for upstream modifications before updating
            if not overwrite:
                upstream_modified_time = _get_upstream_modified_time(drive, record.drive_file_id)
                if upstream_modified_time:
                    last_operation = record.last_operation
                    # Ensure last_operation is timezone-aware for comparison
                    if last_operation.tzinfo is None:
                        last_operation = last_operation.replace(tzinfo=timezone.utc)
                    if upstream_modified_time > last_operation:
                        import sys
                        print(f"Warning: {local_path} - upstream was modified after last operation.", file=sys.stderr)
                        print(f"  Last local operation: {last_operation.isoformat()}", file=sys.stderr)
                        print(f"  Upstream modified:    {upstream_modified_time.isoformat()}", file=sys.stderr)
                        proceed = _prompt_confirmation("Do you want to overwrite the upstream changes?")
                        if not proceed:
                            print(f"Skipping: {local_path}")
                            continue
            
            # Prepare metadata and media
            metadata = {"name": os.path.basename(local_path)}
            if destination_mimetype:
                metadata["mimeType"] = destination_mimetype
            media = MediaFileUpload(local_path, mimetype=source_mimetype)
            
            # Update existing file
            result = drive.files().update(
                fileId=record.drive_file_id,
                body=metadata,
                media_body=media,
                fields="id",
                supportsAllDrives=True
            ).execute()
            
            # Update timestamp
            record.last_operation = datetime.now(timezone.utc)
            results.append(local_path)
            
        except Exception as e:
            print(f"Warning: Failed to re-upload {local_path}: {e}")
            continue
    
    # Save updated mapping
    _save_mapping(mapping, mapping_path)
    
    return results


def share_file(
    fpath: str,
    emails: str,
    role: str = "reader",
    notify: bool = True,
    credentials_fpath: Optional[str] = None,
    token_path: Optional[str] = None,
    mapping_path: Optional[str] = None,
) -> list[dict]:
    """Share a file on Google Drive with one or more email addresses.
    
    Args:
        fpath: Local file path (must have been previously uploaded)
        emails: Email address(es) to share with (comma-separated for multiple)
        role: Permission role ('reader', 'writer', or 'commenter')
        notify: Whether to send notification email
        credentials_fpath: Path to credentials file
        token_path: Path to token file
        mapping_path: Path to files mapping file
    
    Returns:
        List of created permission metadata
    """
    # Load mapping and resolve file path to Drive ID
    mapping = _load_mapping(mapping_path)
    abs_path = _get_absolute_path(fpath)
    
    existing_record = mapping.uploads.get(abs_path)
    if not existing_record:
        raise ValueError(
            f"File not found in mapping: {fpath}\n"
            "Make sure the file has been uploaded first using the 'upload' command."
        )
    
    file_id = existing_record.drive_file_id
    
    creds = get_credentials(credentials_fpath, token_path)
    drive = build("drive", "v3", credentials=creds)
    
    # Parse comma-separated email addresses
    email_list = [e.strip() for e in emails.split(",") if e.strip()]
    
    if not email_list:
        raise ValueError("No valid email addresses provided")
    
    # Create permissions for each email address
    results = []
    for email in email_list:
        permission = {
            "type": "user",
            "role": role,
            "emailAddress": email,
        }
        
        result = drive.permissions().create(
            fileId=file_id,
            body=permission,
            sendNotificationEmail=notify,
            fields="id,type,role,emailAddress",
            supportsAllDrives=True,
        ).execute()
        
        results.append(result)
    
    return results


# ============================================================================
# Token Server Functionality
# ============================================================================

def _generate_landing_page(base_url: str, error: Optional[str] = None) -> str:
    """Generate the landing page HTML."""
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ''
    
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>gdrive — Google Drive CLI Authentication</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Outfit:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-dark: #0a0a0f;
      --bg-card: #12121a;
      --accent: #00d4aa;
      --accent-dim: #00a88a;
      --text-primary: #f0f0f5;
      --text-secondary: #8888a0;
      --border: #2a2a3a;
      --error: #ff4466;
      --success: #00d4aa;
    }}
    
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    
    body {{
      font-family: 'Outfit', sans-serif;
      background: var(--bg-dark);
      color: var(--text-primary);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem;
      background-image: 
        radial-gradient(circle at 20% 80%, rgba(0, 212, 170, 0.08) 0%, transparent 50%),
        radial-gradient(circle at 80% 20%, rgba(0, 168, 138, 0.06) 0%, transparent 50%);
    }}
    
    .container {{ max-width: 520px; width: 100%; }}
    
    .card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 3rem;
      text-align: center;
    }}
    
    .logo {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 2.5rem;
      font-weight: 600;
      color: var(--accent);
      margin-bottom: 0.5rem;
      letter-spacing: -0.02em;
    }}
    
    .tagline {{ color: var(--text-secondary); font-size: 1rem; margin-bottom: 2.5rem; }}
    
    .steps {{
      text-align: left;
      margin-bottom: 2.5rem;
      padding: 1.5rem;
      background: rgba(0, 212, 170, 0.04);
      border-radius: 12px;
      border: 1px solid rgba(0, 212, 170, 0.1);
    }}
    
    .steps h3 {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--accent);
      margin-bottom: 1rem;
    }}
    
    .step {{
      display: flex;
      gap: 1rem;
      align-items: flex-start;
      padding: 0.75rem 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }}
    
    .step:last-child {{ border-bottom: none; }}
    
    .step-num {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: var(--accent);
      background: rgba(0, 212, 170, 0.15);
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      flex-shrink: 0;
    }}
    
    .step-text {{ color: var(--text-secondary); font-size: 0.95rem; line-height: 1.5; }}
    
    .google-btn {{
      display: inline-flex;
      align-items: center;
      gap: 0.75rem;
      background: #fff;
      color: #333;
      font-family: 'Outfit', sans-serif;
      font-size: 1rem;
      font-weight: 500;
      padding: 1rem 2rem;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: transform 0.15s ease, box-shadow 0.15s ease;
      text-decoration: none;
    }}
    
    .google-btn:hover {{
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
    }}
    
    .google-btn svg {{ width: 20px; height: 20px; }}
    
    .error {{
      background: rgba(255, 68, 102, 0.1);
      border: 1px solid rgba(255, 68, 102, 0.3);
      color: var(--error);
      padding: 1rem;
      border-radius: 8px;
      margin-bottom: 1.5rem;
      font-size: 0.9rem;
    }}
    
    .footer {{ margin-top: 2rem; font-size: 0.8rem; color: var(--text-secondary); }}
    .footer a {{ color: var(--accent); text-decoration: none; }}
    .footer a:hover {{ text-decoration: underline; }}
    code {{
      font-family: 'JetBrains Mono', monospace;
      background: rgba(255, 255, 255, 0.08);
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-size: 0.85em;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="logo">gdrive</div>
      <p class="tagline">Command-line Google Drive operations</p>
      
      {error_html}
      
      <div class="steps">
        <h3>How it works</h3>
        <div class="step">
          <span class="step-num">1</span>
          <span class="step-text">Click the button below to sign in with your Google account</span>
        </div>
        <div class="step">
          <span class="step-num">2</span>
          <span class="step-text">Grant access to Google Drive (read & write files)</span>
        </div>
        <div class="step">
          <span class="step-num">3</span>
          <span class="step-text">Copy the token and use it with the CLI</span>
        </div>
      </div>
      
      <a href="{base_url}/auth/start" class="google-btn">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
          <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
          <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
          <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
        </svg>
        Sign in with Google
      </a>
      
      <p class="footer">
        This token server enables CLI authentication.<br>
        Learn more at <a href="https://github.com/nillebco/gdrive">github.com/nillebco/gdrive</a>
      </p>
    </div>
  </div>
</body>
</html>'''


def _generate_success_page(token: dict, session_id: str) -> str:
    """Generate the success page HTML with the token."""
    token_json = json.dumps(token, indent=2)
    token_escaped = html.escape(token_json)
    token_js = json.dumps(token_json)
    
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Success — gdrive Authentication</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Outfit:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-dark: #0a0a0f;
      --bg-card: #12121a;
      --accent: #00d4aa;
      --accent-dim: #00a88a;
      --text-primary: #f0f0f5;
      --text-secondary: #8888a0;
      --border: #2a2a3a;
      --success: #00d4aa;
    }}
    
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    
    body {{
      font-family: 'Outfit', sans-serif;
      background: var(--bg-dark);
      color: var(--text-primary);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem;
      background-image: 
        radial-gradient(circle at 20% 80%, rgba(0, 212, 170, 0.08) 0%, transparent 50%),
        radial-gradient(circle at 80% 20%, rgba(0, 168, 138, 0.06) 0%, transparent 50%);
    }}
    
    .container {{ max-width: 700px; width: 100%; }}
    
    .card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 3rem;
      text-align: center;
    }}
    
    .success-icon {{
      width: 64px;
      height: 64px;
      background: rgba(0, 212, 170, 0.15);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 1.5rem;
    }}
    
    .success-icon svg {{ width: 32px; height: 32px; color: var(--success); }}
    
    h1 {{ font-size: 1.75rem; margin-bottom: 0.5rem; }}
    .subtitle {{ color: var(--text-secondary); margin-bottom: 2rem; }}
    
    .token-section {{ text-align: left; margin-bottom: 2rem; }}
    
    .token-section h3 {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--accent);
      margin-bottom: 0.75rem;
    }}
    
    .token-box {{
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      position: relative;
    }}
    
    .token-content {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      color: var(--text-secondary);
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 200px;
      overflow-y: auto;
    }}
    
    .copy-btn {{
      position: absolute;
      top: 0.75rem;
      right: 0.75rem;
      background: var(--accent);
      color: var(--bg-dark);
      border: none;
      padding: 0.5rem 1rem;
      border-radius: 6px;
      font-family: 'Outfit', sans-serif;
      font-size: 0.8rem;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.15s ease;
    }}
    
    .copy-btn:hover {{ background: var(--accent-dim); }}
    .copy-btn.copied {{ background: var(--success); }}
    
    .cli-section {{
      background: rgba(0, 212, 170, 0.04);
      border: 1px solid rgba(0, 212, 170, 0.1);
      border-radius: 12px;
      padding: 1.5rem;
      text-align: left;
      margin-bottom: 1.5rem;
    }}
    
    .cli-section h3 {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--accent);
      margin-bottom: 0.75rem;
    }}
    
    .cli-section p {{ color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 1rem; }}
    
    .cli-section code {{
      display: block;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      background: rgba(0, 0, 0, 0.3);
      padding: 1rem;
      border-radius: 6px;
      color: var(--text-primary);
      overflow-x: auto;
    }}
    
    .done-btn {{
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-secondary);
      padding: 0.75rem 2rem;
      border-radius: 8px;
      font-family: 'Outfit', sans-serif;
      font-size: 0.95rem;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    
    .done-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="success-icon">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
        </svg>
      </div>
      
      <h1>Authentication Successful!</h1>
      <p class="subtitle">Your Google Drive access token has been generated.</p>
      
      <div class="cli-section">
        <h3>Using with CLI</h3>
        <p>If you started authentication from the CLI, your token is automatically saved. Otherwise, save the token below to a file named <code style="display: inline; padding: 0.1rem 0.3rem;">token.json</code>:</p>
        <code>./cli upload document.md</code>
      </div>
      
      <div class="token-section">
        <h3>Your Token</h3>
        <div class="token-box">
          <button class="copy-btn" onclick="copyToken()">Copy</button>
          <div class="token-content" id="token">{token_escaped}</div>
        </div>
      </div>
      
      <button class="done-btn" onclick="window.close()">Close Window</button>
    </div>
  </div>
  
  <script>
    const token = {token_js};
    
    function copyToken() {{
      navigator.clipboard.writeText(token).then(() => {{
        const btn = document.querySelector('.copy-btn');
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => {{
          btn.textContent = 'Copy';
          btn.classList.remove('copied');
        }}, 2000);
      }});
    }}
  </script>
</body>
</html>'''


def _fetch_token_from_server(server_url: str, token_path: Optional[str] = None) -> None:
    """Fetch token from a token server."""
    from urllib.parse import quote
    
    # Check if we already have a valid token
    existing_token = _load_token(token_path)
    if existing_token and existing_token.valid:
        return
    
    print(f"Opening browser to authenticate via {server_url}...")
    
    # Generate a session ID
    session_id = secrets.token_hex(16)
    
    # Token received flag
    token_received = threading.Event()
    received_token = [None]  # Using list to allow modification in nested function
    
    class CallbackHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Suppress logging
        
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == '/callback':
                params = parse_qs(parsed.query)
                if 'token' in params:
                    try:
                        token_data = json.loads(params['token'][0])
                        received_token[0] = token_data
                        
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/html')
                        self.end_headers()
                        self.wfile.write(b'''
                            <html>
                                <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                                    <h1>Token received!</h1>
                                    <p>You can close this window and return to the terminal.</p>
                                </body>
                            </html>
                        ''')
                        token_received.set()
                    except Exception as e:
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(f"Error: {e}".encode())
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"No token received")
    
    # Start local server on a random port
    with socketserver.TCPServer(('localhost', 0), CallbackHandler) as httpd:
        local_port = httpd.server_address[1]
        callback_url = quote(f"http://localhost:{local_port}/callback")
        auth_url = f"{server_url}/auth/start?callback={callback_url}&session={session_id}"
        
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
        # Save the token
        path = token_path or DEFAULT_TOKEN_PATH
        with open(path, 'w') as f:
            json.dump(received_token[0], f, indent=2)
        print("Token saved successfully!")
    else:
        raise RuntimeError("Failed to receive token")


class TokenServerHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the token server."""
    
    credentials = None
    port = DEFAULT_SERVER_PORT
    
    def log_message(self, format, *args):
        pass  # Suppress default logging
    
    def _send_html(self, content: str, status: int = 200):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))
    
    def _send_redirect(self, location: str):
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()
    
    def do_GET(self):
        parsed = urlparse(self.path)
        base_url = f"http://localhost:{self.port}"
        
        try:
            # Landing page
            if parsed.path in ('/', ''):
                self._send_html(_generate_landing_page(base_url))
                return
            
            # Start OAuth flow
            if parsed.path == '/auth/start':
                params = parse_qs(parsed.query)
                callback = params.get('callback', [None])[0]
                session_id = params.get('session', [secrets.token_hex(16)])[0]
                
                # Store callback URL for this session
                pending_sessions[session_id] = {
                    'callback': callback,
                    'timestamp': datetime.now()
                }
                
                # Clean up old sessions (older than 10 minutes)
                now = datetime.now()
                old_sessions = [
                    sid for sid, sess in pending_sessions.items()
                    if (now - sess['timestamp']).total_seconds() > 600
                ]
                for sid in old_sessions:
                    del pending_sessions[sid]
                
                redirect_uri = f"{base_url}/auth/callback"
                
                # Create OAuth flow
                flow = Flow.from_client_config(
                    self.credentials,
                    scopes=SCOPES,
                    redirect_uri=redirect_uri
                )
                
                auth_url, _ = flow.authorization_url(
                    access_type='offline',
                    state=session_id,
                    prompt='consent'
                )
                
                self._send_redirect(auth_url)
                return
            
            # OAuth callback from Google
            if parsed.path == '/auth/callback':
                params = parse_qs(parsed.query)
                code = params.get('code', [None])[0]
                state = params.get('state', [None])[0]
                error = params.get('error', [None])[0]
                
                if error:
                    self._send_html(_generate_landing_page(base_url, f"Google authentication error: {error}"))
                    return
                
                if not code:
                    self._send_html(_generate_landing_page(base_url, "No authorization code received"))
                    return
                
                redirect_uri = f"{base_url}/auth/callback"
                
                try:
                    # Set environment variable to allow scope changes
                    # Google may return additional previously-granted scopes
                    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
                    
                    flow = Flow.from_client_config(
                        self.credentials,
                        scopes=SCOPES,
                        redirect_uri=redirect_uri
                    )
                    flow.fetch_token(code=code)
                    creds = flow.credentials
                    
                    # Convert credentials to token dict
                    token = {
                        'token': creds.token,
                        'refresh_token': creds.refresh_token,
                        'token_uri': creds.token_uri,
                        'client_id': creds.client_id,
                        'client_secret': creds.client_secret,
                        'scopes': list(creds.scopes) if creds.scopes else SCOPES,
                    }
                    if creds.expiry:
                        token['expiry'] = creds.expiry.isoformat()
                    
                    # Check if there's a CLI callback waiting
                    session = pending_sessions.get(state)
                    if session and session.get('callback'):
                        from urllib.parse import quote
                        token_param = quote(json.dumps(token))
                        callback_url = f"{session['callback']}?token={token_param}"
                        del pending_sessions[state]
                        self._send_redirect(callback_url)
                        return
                    
                    # No CLI callback, show success page
                    if state in pending_sessions:
                        del pending_sessions[state]
                    self._send_html(_generate_success_page(token, state or ''))
                    
                except Exception as e:
                    self._send_html(_generate_landing_page(base_url, f"Failed to exchange code for token: {e}"))
                return
            
            # Health check
            if parsed.path == '/health':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
                return
            
            # 404
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found')
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Internal Server Error: {e}".encode())


def start_token_server(port: int, credentials_fpath: Optional[str] = None):
    """Start the OAuth token server."""
    # Load credentials
    credentials_json = os.environ.get(CREDENTIALS_ENV_VAR)
    
    if credentials_json:
        credentials = json.loads(credentials_json)
    elif credentials_fpath and os.path.exists(credentials_fpath):
        with open(credentials_fpath, 'r') as f:
            credentials = json.load(f)
    else:
        raise ValueError(
            f"Credentials required. Set {CREDENTIALS_ENV_VAR} env var or use --credentials-fpath"
        )
    
    # Validate credentials
    creds_data = credentials.get('installed') or credentials.get('web')
    if not creds_data or not creds_data.get('client_id') or not creds_data.get('client_secret'):
        raise ValueError("Invalid credentials: missing client_id or client_secret")
    
    # Configure handler
    TokenServerHandler.credentials = credentials
    TokenServerHandler.port = port
    
    # Start server
    with socketserver.TCPServer(('', port), TokenServerHandler) as httpd:
        print(f"\n🚀 gdrive token server running at http://localhost:{port}\n")
        print("Share this URL with users who need to authenticate.")
        print("Press Ctrl+C to stop the server.\n")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")


app = typer.Typer(help="Google Drive file operations")

@app.command()
def login(
    credentials_fpath: Annotated[
        Optional[str],
        typer.Option(
            "--credentials-fpath",
            "-c",
            help=f"Path to credentials JSON file. Can also be set via {CREDENTIALS_ENV_VAR} env var"
        )
    ] = None,
    token_path: Annotated[
        Optional[str],
        typer.Option(
            "--token-path",
            "-t",
            help=f"Path to save/load OAuth token. Can also be set via {TOKEN_ENV_VAR} env var. Default: {DEFAULT_TOKEN_PATH}"
        )
    ] = None,
    token_server: Annotated[
        Optional[str],
        typer.Option(
            "--token-server",
            help="URL of token server to fetch OAuth token from (or set GDRIVE_TOKEN_SERVER env var)"
        )
    ] = None,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Force re-authentication even if a valid token exists"
        )
    ] = False,
):
    """Authenticate with Google and save the OAuth token.

    This command initiates the OAuth flow to authenticate with your Google account
    and saves the token for future use. If a valid token already exists, it will
    be reused unless --force is specified.

    Examples:
        python main.py login
        python main.py login --force
        python main.py login --token-server http://your-server:8080
    """
    # If token-server is provided (via CLI or env var), fetch token from server
    server_url = _get_token_server(token_server)
    if server_url:
        _fetch_token_from_server(server_url, token_path)
        account_email = _get_stored_account_email(token_path)
        if account_email:
            print(f"Logged in as: {account_email}")
        return

    # Check for existing valid token
    if not force:
        client_id, client_secret = _get_client_credentials(credentials_fpath)
        existing_token = _load_token(token_path, client_id=client_id, client_secret=client_secret)
        if existing_token and existing_token.valid:
            print("Already authenticated. Use --force to re-authenticate.")
            account_email = _get_stored_account_email(token_path)
            if account_email:
                print(f"Logged in as: {account_email}")
            return

        # Try to refresh expired token
        if existing_token and existing_token.expired and existing_token.refresh_token:
            try:
                existing_email = _get_stored_account_email(token_path)
                existing_token.refresh(Request())
                _save_token(existing_token, token_path, existing_email)
                print("Token refreshed successfully.")
                if existing_email:
                    print(f"Logged in as: {existing_email}")
                return
            except Exception:
                pass  # Fall through to new OAuth flow

    # Run OAuth flow
    try:
        get_credentials(credentials_fpath, token_path)
        path = token_path or DEFAULT_TOKEN_PATH
        print(f"Authentication successful. Token saved to {path}")
        account_email = _get_stored_account_email(token_path)
        if account_email:
            print(f"Logged in as: {account_email}")
    except Exception as e:
        print(f"Authentication failed: {e}")
        raise typer.Exit(code=1)


@app.command()
def whoami(
    credentials_path: Annotated[
        Optional[str],
        typer.Option(
            "--credentials-path",
            "-c",
            help=f"Path to credentials JSON. Can also be set via {CREDENTIALS_ENV_VAR} env var."
        )
    ] = None,
    token_path: Annotated[
        Optional[str],
        typer.Option(
            "--token-path",
            "-t",
            help=f"Path to OAuth token. Can also be set via {TOKEN_ENV_VAR} env var. Default: {DEFAULT_TOKEN_PATH}"
        )
    ] = None,
):
    """Show the currently authenticated Google account.

    Examples:
        python main.py whoami
    """
    path = token_path or DEFAULT_TOKEN_PATH

    if not os.path.exists(path) and not os.environ.get(TOKEN_ENV_VAR):
        print("Not logged in. Run 'gdrive login' to authenticate.")
        raise typer.Exit(code=1)

    # Check for stored email
    account_email = _get_stored_account_email(token_path)
    if account_email:
        print(account_email)
        return

    # Try to fetch email from API using full credentials
    try:
        creds = get_credentials(credentials_path, token_path)
        if creds and hasattr(creds, 'token') and creds.token:
            email = _fetch_user_email(creds.token)
            if email:
                # Update token file with email
                _save_token(creds, token_path, email)
                print(email)
                return
    except Exception:
        pass  # Fall through to generic message

    print("Logged in (email not available)")


@app.command()
def upload(
    fpath: Annotated[str, typer.Argument(help="Path to the file to upload")],
    source_mimetype: Annotated[
        Optional[str],
        typer.Option(
            "--source-mimetype",
            "-s",
            help="MIME type of the source file. Accepts short aliases: md, txt, pdf, docx, xlsx, csv, etc."
        )
    ] = None,
    destination_mimetype: Annotated[
        Optional[str],
        typer.Option(
            "--destination-mimetype",
            "-d",
            help="MIME type for the destination file in Drive. Accepts short aliases: gdoc, gsheet, gslide, gdraw"
        )
    ] = None,
    credentials_fpath: Annotated[
        Optional[str],
        typer.Option(
            "--credentials-fpath",
            "-c",
            help=f"Path to credentials JSON file. Can also be set via {CREDENTIALS_ENV_VAR} env var"
        )
    ] = None,
    token_path: Annotated[
        Optional[str],
        typer.Option(
            "--token-path",
            "-t",
            help=f"Path to save/load OAuth token. Can also be set via {TOKEN_ENV_VAR} env var. Default: {DEFAULT_TOKEN_PATH}"
        )
    ] = None,
    mapping_path: Annotated[
        Optional[str],
        typer.Option(
            "--mapping-path",
            "-m",
            help=f"Path to files mapping JSON. Default: {DEFAULT_MAPPING_PATH}"
        )
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Skip upstream modification check and overwrite without prompting"
        )
    ] = False,
    token_server: Annotated[
        Optional[str],
        typer.Option(
            "--token-server",
            help="URL of token server to fetch OAuth token from (or set GDRIVE_TOKEN_SERVER env var)"
        )
    ] = None,
    folder_id: Annotated[
        Optional[str],
        typer.Option(
            "--folder-id",
            help="Parent folder ID to upload into (can be a shared drive root or folder within)"
        )
    ] = None,
    drive_id: Annotated[
        Optional[str],
        typer.Option(
            "--drive-id",
            help="Shared drive ID (for tracking; use --folder-id for the actual destination)"
        )
    ] = None,
    drive_name: Annotated[
        Optional[str],
        typer.Option(
            "--drive-name",
            help="Shared drive name (resolved to ID; use --folder-id for the actual destination)"
        )
    ] = None,
):
    """Upload a file to Google Drive (supports shared drives).

    Examples:
        python main.py upload myfile.md
        python main.py upload myfile.md --drive-name "My Shared Drive"
        python main.py upload myfile.md --folder-id FOLDER_ID --drive-id DRIVE_ID
    """
    async def _upload():
        # If token-server is provided (via CLI or env var), fetch token from server first
        server_url = _get_token_server(token_server)
        if server_url:
            _fetch_token_from_server(server_url, token_path)

        # Resolve drive name to ID if provided
        resolved_drive_id = drive_id
        if drive_name and not resolved_drive_id:
            creds = get_credentials(credentials_fpath, token_path)
            drive = build("drive", "v3", credentials=creds)
            resolved_drive_id = _resolve_drive_id(drive, drive_name)

        # If drive ID is provided but no folder ID, use drive ID as folder (upload to root of shared drive)
        resolved_folder_id = folder_id or resolved_drive_id

        # Resolve short aliases to full MIME types
        resolved_source = _resolve_mimetype(source_mimetype)
        resolved_dest = _resolve_mimetype(destination_mimetype)
        file = await asyncify(upload_file)(
            fpath, resolved_source, resolved_dest, credentials_fpath, token_path,
            mapping_path, overwrite, resolved_folder_id, resolved_drive_id
        )
        print(file["id"])

    asyncio.run(_upload())


@app.command()
def export(
    file_id: Annotated[str, typer.Argument(help="The Google Drive file ID to export")],
    output_path: Annotated[str, typer.Argument(help="Path where the exported file will be saved")],
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help=f"Export format. Supported: {', '.join(EXPORT_MIME_TYPES.keys())}"
        )
    ] = "md",
    credentials_fpath: Annotated[
        Optional[str],
        typer.Option(
            "--credentials-fpath",
            "-c",
            help=f"Path to credentials JSON file. Can also be set via {CREDENTIALS_ENV_VAR} env var"
        )
    ] = None,
    token_path: Annotated[
        Optional[str],
        typer.Option(
            "--token-path",
            "-t",
            help=f"Path to save/load OAuth token. Can also be set via {TOKEN_ENV_VAR} env var. Default: {DEFAULT_TOKEN_PATH}"
        )
    ] = None,
    mapping_path: Annotated[
        Optional[str],
        typer.Option(
            "--mapping-path",
            "-m",
            help=f"Path to files mapping JSON. Default: {DEFAULT_MAPPING_PATH}"
        )
    ] = None,
    token_server: Annotated[
        Optional[str],
        typer.Option(
            "--token-server",
            help="URL of token server to fetch OAuth token from (or set GDRIVE_TOKEN_SERVER env var)"
        )
    ] = None,
    drive_id: Annotated[
        Optional[str],
        typer.Option(
            "--drive-id",
            help="Shared drive ID (for tracking in the mapping file)"
        )
    ] = None,
    drive_name: Annotated[
        Optional[str],
        typer.Option(
            "--drive-name",
            help="Shared drive name (resolved to ID for tracking)"
        )
    ] = None,
):
    """Export a Google Workspace document to a local file (supports shared drives).

    Exports Google Docs, Sheets, Slides, Drawings, or Apps Script files to various formats.
    The default format is Markdown (md).

    Examples:
        python main.py export 1abc123xyz output.md
        python main.py export 1abc123xyz document.docx --format docx
        python main.py export 1abc123xyz spreadsheet.csv --format csv
        python main.py export 1abc123xyz output.md --drive-name "My Shared Drive"
    """
    async def _export():
        # If token-server is provided (via CLI or env var), fetch token from server first
        server_url = _get_token_server(token_server)
        if server_url:
            _fetch_token_from_server(server_url, token_path)

        # Resolve drive name to ID if provided
        resolved_drive_id = drive_id
        if drive_name and not resolved_drive_id:
            creds = get_credentials(credentials_fpath, token_path)
            drive = build("drive", "v3", credentials=creds)
            resolved_drive_id = _resolve_drive_id(drive, drive_name)

        result = await asyncify(export_file)(
            file_id, output_path, format, credentials_fpath, token_path, mapping_path, resolved_drive_id
        )
        print(f"Exported to: {result}")

    asyncio.run(_export())


@app.command()
def share(
    fpath: Annotated[str, typer.Argument(help="Path to the local file (must have been uploaded)")],
    emails: Annotated[str, typer.Argument(help="Email address(es) to share with (comma-separated for multiple)")],
    role: Annotated[
        str,
        typer.Option(
            "--role",
            "-r",
            help="Permission role: reader, writer, or commenter"
        )
    ] = "reader",
    notify: Annotated[
        bool,
        typer.Option(
            "--notify/--no-notify",
            help="Send notification email to the recipient"
        )
    ] = True,
    credentials_fpath: Annotated[
        Optional[str], 
        typer.Option(
            "--credentials-fpath", 
            "-c",
            help=f"Path to credentials JSON file. Can also be set via {CREDENTIALS_ENV_VAR} env var"
        )
    ] = None,
    token_path: Annotated[
        Optional[str],
        typer.Option(
            "--token-path",
            "-t",
            help=f"Path to save/load OAuth token. Can also be set via {TOKEN_ENV_VAR} env var. Default: {DEFAULT_TOKEN_PATH}"
        )
    ] = None,
    mapping_path: Annotated[
        Optional[str],
        typer.Option(
            "--mapping-path",
            "-m",
            help=f"Path to files mapping JSON. Default: {DEFAULT_MAPPING_PATH}"
        )
    ] = None,
    token_server: Annotated[
        Optional[str],
        typer.Option(
            "--token-server",
            help="URL of token server to fetch OAuth token from (or set GDRIVE_TOKEN_SERVER env var)"
        )
    ] = None,
):
    """Share an uploaded file with one or more email addresses.
    
    Shares a file that has been previously uploaded to Google Drive with
    one or more email addresses. The file must exist in the local mapping.
    Multiple emails can be provided as a comma-separated list.
    
    Examples:
        python main.py share document.md user@example.com
        python main.py share document.md "user1@example.com,user2@example.com"
        python main.py share document.md user@example.com --role writer
        python main.py share document.md user@example.com --no-notify
    """
    # Validate role
    valid_roles = ["reader", "writer", "commenter"]
    if role not in valid_roles:
        raise typer.BadParameter(
            f"Invalid role: {role}. Must be one of: {', '.join(valid_roles)}"
        )
    
    async def _share():
        # If token-server is provided (via CLI or env var), fetch token from server first
        server_url = _get_token_server(token_server)
        if server_url:
            _fetch_token_from_server(server_url, token_path)
        results = await asyncify(share_file)(fpath, emails, role, notify, credentials_fpath, token_path, mapping_path)
        for result in results:
            print(f"Shared with {result['emailAddress']} as {result['role']}")
    
    asyncio.run(_share())


@app.command()
def pull(
    credentials_fpath: Annotated[
        Optional[str], 
        typer.Option(
            "--credentials-fpath", 
            "-c",
            help=f"Path to credentials JSON file. Can also be set via {CREDENTIALS_ENV_VAR} env var"
        )
    ] = None,
    token_path: Annotated[
        Optional[str],
        typer.Option(
            "--token-path",
            "-t",
            help=f"Path to save/load OAuth token. Can also be set via {TOKEN_ENV_VAR} env var. Default: {DEFAULT_TOKEN_PATH}"
        )
    ] = None,
    mapping_path: Annotated[
        Optional[str],
        typer.Option(
            "--mapping-path",
            "-m",
            help=f"Path to files mapping JSON. Default: {DEFAULT_MAPPING_PATH}"
        )
    ] = None,
    token_server: Annotated[
        Optional[str],
        typer.Option(
            "--token-server",
            help="URL of token server to fetch OAuth token from (or set GDRIVE_TOKEN_SERVER env var)"
        )
    ] = None,
):
    """Re-export all documents that have been previously exported.
    
    This command reads the files mapping and re-exports all documents
    that were previously exported, updating them with the latest content
    from Google Drive.
    
    Examples:
        python main.py pull
        python main.py pull --mapping-path custom-mapping.json
    """
    async def _pull():
        # If token-server is provided (via CLI or env var), fetch token from server first
        server_url = _get_token_server(token_server)
        if server_url:
            _fetch_token_from_server(server_url, token_path)
        results = await asyncify(pull_all)(credentials_fpath, token_path, mapping_path)
        if not results:
            print("No previously exported documents found.")
        else:
            for path in results:
                print(f"Re-exported: {path}")
            print(f"\nTotal: {len(results)} document(s) re-exported.")
    
    asyncio.run(_pull())


@app.command()
def push(
    credentials_fpath: Annotated[
        Optional[str], 
        typer.Option(
            "--credentials-fpath", 
            "-c",
            help=f"Path to credentials JSON file. Can also be set via {CREDENTIALS_ENV_VAR} env var"
        )
    ] = None,
    token_path: Annotated[
        Optional[str],
        typer.Option(
            "--token-path",
            "-t",
            help=f"Path to save/load OAuth token. Can also be set via {TOKEN_ENV_VAR} env var. Default: {DEFAULT_TOKEN_PATH}"
        )
    ] = None,
    mapping_path: Annotated[
        Optional[str],
        typer.Option(
            "--mapping-path",
            "-m",
            help=f"Path to files mapping JSON. Default: {DEFAULT_MAPPING_PATH}"
        )
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Skip upstream modification check and overwrite without prompting"
        )
    ] = False,
    token_server: Annotated[
        Optional[str],
        typer.Option(
            "--token-server",
            help="URL of token server to fetch OAuth token from (or set GDRIVE_TOKEN_SERVER env var)"
        )
    ] = None,
):
    """Re-upload all files that have been previously uploaded.
    
    This command reads the files mapping and re-uploads all files
    that were previously uploaded, updating them with the latest local content.
    
    Examples:
        python main.py push
        python main.py push --mapping-path custom-mapping.json
        python main.py push --overwrite
    """
    async def _push():
        # If token-server is provided (via CLI or env var), fetch token from server first
        server_url = _get_token_server(token_server)
        if server_url:
            _fetch_token_from_server(server_url, token_path)
        results = await asyncify(push_all)(credentials_fpath, token_path, mapping_path, overwrite)
        if not results:
            print("No previously uploaded files found.")
        else:
            for path in results:
                print(f"Re-uploaded: {path}")
            print(f"\nTotal: {len(results)} file(s) re-uploaded.")
    
    asyncio.run(_push())


@app.command()
def sync(
    credentials_fpath: Annotated[
        Optional[str],
        typer.Option(
            "--credentials-fpath",
            "-c",
            help=f"Path to credentials JSON file. Can also be set via {CREDENTIALS_ENV_VAR} env var"
        )
    ] = None,
    token_path: Annotated[
        Optional[str],
        typer.Option(
            "--token-path",
            "-t",
            help=f"Path to save/load OAuth token. Can also be set via {TOKEN_ENV_VAR} env var. Default: {DEFAULT_TOKEN_PATH}"
        )
    ] = None,
    mapping_path: Annotated[
        Optional[str],
        typer.Option(
            "--mapping-path",
            "-m",
            help=f"Path to files mapping JSON. Default: {DEFAULT_MAPPING_PATH}"
        )
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Skip upstream modification check and overwrite without prompting"
        )
    ] = False,
    token_server: Annotated[
        Optional[str],
        typer.Option(
            "--token-server",
            help="URL of token server to fetch OAuth token from (or set GDRIVE_TOKEN_SERVER env var)"
        )
    ] = None,
):
    """Sync all documents: first pull (re-export), then push (re-upload).

    This command combines pull and push operations to synchronize your
    local files with Google Drive. It first re-exports all previously
    exported documents, then re-uploads all previously uploaded files.

    Examples:
        python main.py sync
        python main.py sync --mapping-path custom-mapping.json
        python main.py sync --overwrite
    """
    async def _sync():
        # If token-server is provided (via CLI or env var), fetch token from server first
        server_url = _get_token_server(token_server)
        if server_url:
            _fetch_token_from_server(server_url, token_path)

        # First, pull (re-export all documents)
        print("--- Pull (re-exporting documents) ---")
        pull_results = await asyncify(pull_all)(credentials_fpath, token_path, mapping_path)
        if not pull_results:
            print("No previously exported documents found.")
        else:
            for path in pull_results:
                print(f"Re-exported: {path}")
            print(f"Pull complete: {len(pull_results)} document(s) re-exported.\n")

        # Then, push (re-upload all files)
        print("--- Push (re-uploading files) ---")
        push_results = await asyncify(push_all)(credentials_fpath, token_path, mapping_path, overwrite)
        if not push_results:
            print("No previously uploaded files found.")
        else:
            for path in push_results:
                print(f"Re-uploaded: {path}")
            print(f"Push complete: {len(push_results)} file(s) re-uploaded.\n")

        # Summary
        print("--- Sync Summary ---")
        print(f"Documents pulled: {len(pull_results)}")
        print(f"Files pushed: {len(push_results)}")

    asyncio.run(_sync())


@app.command("list-drives")
def list_drives(
    credentials_fpath: Annotated[
        Optional[str],
        typer.Option(
            "--credentials-fpath",
            "-c",
            help=f"Path to credentials JSON file. Can also be set via {CREDENTIALS_ENV_VAR} env var"
        )
    ] = None,
    token_path: Annotated[
        Optional[str],
        typer.Option(
            "--token-path",
            "-t",
            help=f"Path to save/load OAuth token. Can also be set via {TOKEN_ENV_VAR} env var. Default: {DEFAULT_TOKEN_PATH}"
        )
    ] = None,
    token_server: Annotated[
        Optional[str],
        typer.Option(
            "--token-server",
            help="URL of token server to fetch OAuth token from (or set GDRIVE_TOKEN_SERVER env var)"
        )
    ] = None,
    query: Annotated[
        Optional[str],
        typer.Option(
            "--query",
            "-q",
            help="Search query (e.g., \"name contains 'project'\")"
        )
    ] = None,
):
    """List all shared drives accessible to the user.

    Examples:
        python main.py list-drives
        python main.py list-drives --query "name contains 'project'"
    """
    # If token-server is provided (via CLI or env var), fetch token from server first
    server_url = _get_token_server(token_server)
    if server_url:
        _fetch_token_from_server(server_url, token_path)

    creds = get_credentials(credentials_fpath, token_path)
    drive = build("drive", "v3", credentials=creds)

    all_drives = []
    page_token = None

    while True:
        params = {
            "pageSize": 100,
            "fields": "nextPageToken, drives(id, name, createdTime)",
        }
        if query:
            params["q"] = query
        if page_token:
            params["pageToken"] = page_token

        response = drive.drives().list(**params).execute()
        all_drives.extend(response.get("drives", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    if not all_drives:
        print("No shared drives found.")
    else:
        print("Shared Drives:\n")
        for d in all_drives:
            print(f"  {d['name']}")
            print(f"    ID: {d['id']}")
            if d.get("createdTime"):
                print(f"    Created: {d['createdTime']}")
            print("")
        print(f"Total: {len(all_drives)} shared drive(s)")


@app.command()
def server(
    port: Annotated[
        int,
        typer.Option(
            "--port",
            "-p",
            help=f"Port to listen on (default: {DEFAULT_SERVER_PORT})"
        )
    ] = DEFAULT_SERVER_PORT,
    credentials_fpath: Annotated[
        Optional[str],
        typer.Option(
            "--credentials-fpath",
            "-c",
            help=f"Path to credentials JSON file. Can also be set via {CREDENTIALS_ENV_VAR} env var"
        )
    ] = None,
):
    """Start an OAuth token server for users without their own credentials.
    
    This command starts an HTTP server that handles OAuth authentication
    on behalf of users who don't have their own Google Cloud credentials.
    
    Users can visit the server URL, sign in with Google, and receive
    a token they can use with the CLI.
    
    Examples:
        python main.py server --port 8080
        python main.py server -c credentials.json
    """
    try:
        start_token_server(port, credentials_fpath)
    except Exception as e:
        print(f"Error: {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()

