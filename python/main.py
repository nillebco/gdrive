import asyncio
from datetime import datetime, timezone
import json
import os
from typing import Annotated, Optional

import typer
from asyncer import asyncify
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials as OAuthCredentials
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from pydantic import BaseModel

SCOPES = ["https://www.googleapis.com/auth/drive"]

CREDENTIALS_ENV_VAR = "GOOGLE_CREDENTIALS"
TOKEN_ENV_VAR = "GOOGLE_TOKEN"
DEFAULT_TOKEN_PATH = "token.json"
DEFAULT_MAPPING_PATH = "files-mapping.json"


class FileRecord(BaseModel):
    """Record of a file operation (upload or export)."""
    local_path: str
    drive_file_id: str
    last_operation: datetime


class FilesMapping(BaseModel):
    """Mapping of files between local filesystem and Google Drive."""
    uploads: dict[str, FileRecord] = {}  # keyed by local_path
    exports: dict[str, FileRecord] = {}  # keyed by drive_file_id


def _load_mapping(mapping_path: Optional[str] = None) -> FilesMapping:
    """Load the files mapping from disk."""
    path = mapping_path or DEFAULT_MAPPING_PATH
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
        return FilesMapping.model_validate(data)
    return FilesMapping()


def _save_mapping(mapping: FilesMapping, mapping_path: Optional[str] = None):
    """Save the files mapping to disk."""
    path = mapping_path or DEFAULT_MAPPING_PATH
    with open(path, "w") as f:
        f.write(mapping.model_dump_json(indent=2))


def _get_absolute_path(fpath: str) -> str:
    """Get the absolute path for consistent record-keeping."""
    return os.path.abspath(fpath)


def _load_token(token_path: Optional[str] = None) -> Optional[OAuthCredentials]:
    """Load saved OAuth token from file or environment variable."""
    # Try environment variable first
    token_json = os.environ.get(TOKEN_ENV_VAR)
    if token_json:
        token_data = json.loads(token_json)
        return OAuthCredentials.from_authorized_user_info(token_data, SCOPES)
    
    # Try file
    path = token_path or DEFAULT_TOKEN_PATH
    if os.path.exists(path):
        with open(path, "r") as f:
            token_data = json.load(f)
        return OAuthCredentials.from_authorized_user_info(token_data, SCOPES)
    
    return None


def _save_token(creds: OAuthCredentials, token_path: Optional[str] = None):
    """Save OAuth token to file for future use."""
    path = token_path or DEFAULT_TOKEN_PATH
    with open(path, "w") as f:
        f.write(creds.to_json())


def _get_credentials_client_secret_from_dict(
    data: dict, token_path: Optional[str] = None
) -> OAuthCredentials:
    """Get OAuth credentials, using cached token if available."""
    # Try to load existing token
    creds = _load_token(token_path)
    
    if creds and creds.valid:
        return creds
    
    # Try to refresh expired token
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            _save_token(creds, token_path)
            return creds
        except Exception:
            pass  # Fall through to new OAuth flow
    
    # Run OAuth flow
    flow = InstalledAppFlow.from_client_config(data, SCOPES)
    creds = flow.run_local_server(port=0)
    _save_token(creds, token_path)
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


def get_credentials(
    fpath: Optional[str] = None, token_path: Optional[str] = None
) -> OAuthCredentials | ServiceAccountCredentials:
    """Get credentials from file path or GOOGLE_CREDENTIALS environment variable."""
    # First, check environment variable
    credentials_json = os.environ.get(CREDENTIALS_ENV_VAR)
    if credentials_json:
        return _get_credentials_from_dict(json.loads(credentials_json), token_path)
    
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
    "mdgdoc": "application/vnd.google-apps.document",
}


def _get_upstream_modified_time(drive, file_id: str) -> Optional[datetime]:
    """Get the modification time of a file on Google Drive."""
    try:
        response = drive.files().get(fileId=file_id, fields="modifiedTime").execute()
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
):
    """Upload a file to Google Drive."""
    creds = get_credentials(credentials_fpath, token_path)
    drive = build("drive", "v3", credentials=creds)
    if source_mimetype is None:
        source_mimetype = MIME_TYPES.get(fpath.split(".")[-1])
    if source_mimetype is None:
        raise ValueError(f"Invalid source mimetype: {fpath}, source mimetype: {source_mimetype}")

    # Load existing mapping
    mapping = _load_mapping(mapping_path)
    abs_path = _get_absolute_path(fpath)
    
    metadata = {"name": os.path.basename(fpath), "mimeType": destination_mimetype}
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

        # Update existing file
        try:
            result = drive.files().update(
                fileId=existing_record.drive_file_id,
                body=metadata,
                media_body=media,
                fields="id"
            ).execute()
            # Update timestamp
            existing_record.last_operation = datetime.now(timezone.utc)
            _save_mapping(mapping, mapping_path)
        except Exception:
            # If update fails (e.g., file was deleted), create a new one
            result = drive.files().create(body=metadata, media_body=media, fields="id").execute()
            mapping.uploads[abs_path] = FileRecord(
                local_path=abs_path,
                drive_file_id=result["id"],
                last_operation=datetime.now(timezone.utc),
            )
            _save_mapping(mapping, mapping_path)
    else:
        # Create new file
        result = drive.files().create(body=metadata, media_body=media, fields="id").execute()
        mapping.uploads[abs_path] = FileRecord(
            local_path=abs_path,
            drive_file_id=result["id"],
            last_operation=datetime.now(timezone.utc),
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
) -> str:
    """Export a Google Workspace document to the specified format."""
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
    )
    _save_mapping(mapping, mapping_path)
    
    return output_path


app = typer.Typer(help="Google Drive file operations")

@app.command()
def upload(
    fpath: Annotated[str, typer.Argument(help="Path to the file to upload")],
    source_mimetype: Annotated[Optional[str], typer.Option(help="MIME type of the source file")] = None,
    destination_mimetype: Annotated[Optional[str], typer.Option(help="MIME type for the destination file in Drive")] = None,
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
):
    """Upload a file to Google Drive."""
    async def _upload():
        file = await asyncify(upload_file)(fpath, source_mimetype, destination_mimetype, credentials_fpath, token_path, mapping_path, overwrite)
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
):
    """Export a Google Workspace document to a local file.
    
    Exports Google Docs, Sheets, Slides, Drawings, or Apps Script files to various formats.
    The default format is Markdown (md).
    
    Examples:
        python main.py export 1abc123xyz output.md
        python main.py export 1abc123xyz document.docx --format docx
        python main.py export 1abc123xyz spreadsheet.csv --format csv
    """
    async def _export():
        result = await asyncify(export_file)(file_id, output_path, format, credentials_fpath, token_path, mapping_path)
        print(f"Exported to: {result}")
    
    asyncio.run(_export())


if __name__ == "__main__":
    app()

