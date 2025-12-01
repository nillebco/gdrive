import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import os
from typing import Annotated, Optional

import typer
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials as OAuthCredentials
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

executor = ThreadPoolExecutor()
SCOPES = ["https://www.googleapis.com/auth/drive"]

CREDENTIALS_ENV_VAR = "GOOGLE_CREDENTIALS"
TOKEN_ENV_VAR = "GOOGLE_TOKEN"
DEFAULT_TOKEN_PATH = "token.json"


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

def upload_sync(
    fpath: str,
    source_mimetype: Optional[str] = None,
    destination_mimetype: Optional[str] = None,
    credentials_fpath: Optional[str] = None,
    token_path: Optional[str] = None,
):
    creds = get_credentials(credentials_fpath, token_path)
    drive = build("drive", "v3", credentials=creds)
    if source_mimetype is None:
        source_mimetype = MIME_TYPES.get(fpath.split(".")[-1])
    if source_mimetype is None:
        raise ValueError(f"Invalid source mimetype: {fpath}, source mimetype: {source_mimetype}")

    metadata = {"name": os.path.basename(fpath), "mimeType": destination_mimetype}
    media = MediaFileUpload(fpath, mimetype=source_mimetype)
    return drive.files().create(body=metadata, media_body=media, fields="id").execute()


async def upload_async(
    fpath: str,
    source_mimetype: Optional[str] = None,
    destination_mimetype: Optional[str] = None,
    credentials_fpath: Optional[str] = None,
    token_path: Optional[str] = None,
):
    return await asyncio.get_running_loop().run_in_executor(
        executor, upload_sync, fpath, source_mimetype, destination_mimetype, credentials_fpath, token_path
    )

app = typer.Typer(help="Upload files to Google Drive")

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
):
    """Upload a file to Google Drive."""
    async def _upload():
        file = await upload_async(fpath, source_mimetype, destination_mimetype, credentials_fpath, token_path)
        print(file["id"])
    
    asyncio.run(_upload())

if __name__ == "__main__":
    app()
