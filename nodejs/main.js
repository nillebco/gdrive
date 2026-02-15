#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import http from 'http';
import crypto from 'crypto';
import { URL } from 'url';
import readline from 'readline';
import open from 'open';
import { google } from 'googleapis';
import { Command } from 'commander';

const SCOPES = ['https://www.googleapis.com/auth/drive'];
const CREDENTIALS_ENV_VAR = 'GOOGLE_CREDENTIALS';
const TOKEN_ENV_VAR = 'GOOGLE_TOKEN';
const TOKEN_SERVER_ENV_VAR = 'OAUTH_TOKEN_SERVER';
const DEFAULT_TOKEN_PATH = 'token.json';
const DEFAULT_MAPPING_PATH = 'files-mapping.json';
const DEFAULT_SERVER_PORT = 8080;

// Token server: in-memory store for pending OAuth sessions
const pendingSessions = new Map();

/**
 * Get token server URL from CLI option or environment variable.
 * @param {string|undefined} tokenServer - CLI option value
 * @returns {string|undefined} Token server URL
 */
function getTokenServer(tokenServer) {
  if (tokenServer) {
    return tokenServer;
  }
  return process.env[TOKEN_SERVER_ENV_VAR];
}

const MIME_TYPES = {
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  md: 'text/markdown',
  txt: 'text/plain',
  html: 'text/html',
  csv: 'text/csv',
  tsv: 'text/tab-separated-values',
  json: 'application/json',
  xml: 'application/xml',
  // Google Workspace types (for destination)
  gdoc: 'application/vnd.google-apps.document',
  gsheet: 'application/vnd.google-apps.spreadsheet',
  gslide: 'application/vnd.google-apps.presentation',
  gdraw: 'application/vnd.google-apps.drawing',
};

/**
 * Resolve a MIME type from a short alias or return as-is if it's a full MIME type.
 * @param {string|null} value - Short alias or full MIME type
 * @returns {string|null} Resolved MIME type
 */
function resolveMimetype(value) {
  if (!value) return null;
  // If it looks like a full MIME type (contains /), return as-is
  if (value.includes('/')) return value;
  // Otherwise, look up in the mapping
  return MIME_TYPES[value.toLowerCase()] || value;
}

// Export MIME types for Google Workspace documents
const EXPORT_MIME_TYPES = {
  // Documents
  md: 'text/markdown',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  odt: 'application/vnd.oasis.opendocument.text',
  rtf: 'application/rtf',
  pdf: 'application/pdf',
  txt: 'text/plain',
  html: 'application/zip',
  epub: 'application/epub+zip',
  // Spreadsheets
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ods: 'application/vnd.oasis.opendocument.spreadsheet',
  csv: 'text/csv',
  tsv: 'text/tab-separated-values',
  // Presentations
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  odp: 'application/vnd.oasis.opendocument.presentation',
  // Drawings
  jpg: 'image/jpeg',
  png: 'image/png',
  svg: 'image/svg+xml',
  // Apps Script
  json: 'application/vnd.google-apps.script+json',
  // Google Vids
  mp4: 'video/mp4',
};

// Text formats that should be written as UTF-8 text
const TEXT_FORMATS = new Set(['md', 'txt', 'csv', 'tsv', 'rtf', 'json', 'svg']);

/**
 * Prompt the user for yes/no confirmation.
 * @param {string} message - The message to display
 * @returns {Promise<boolean>} True if user confirms, false otherwise
 */
async function promptConfirmation(message) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  return new Promise((resolve) => {
    rl.question(`${message} [y/N]: `, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}

/**
 * Resolve a shared drive name to its ID.
 * @param {object} drive - Google Drive API client
 * @param {string} driveName - Name of the shared drive
 * @returns {Promise<string>} The drive ID
 * @throws {Error} If drive not found or multiple matches
 */
async function resolveDriveId(drive, driveName) {
  const escapedName = driveName.replace(/'/g, "\\'");
  const response = await drive.drives.list({
    q: `name = '${escapedName}'`,
    fields: 'drives(id, name)',
    pageSize: 10,
  });

  const drives = response.data.drives || [];

  if (drives.length === 0) {
    throw new Error(`Shared drive not found: "${driveName}"`);
  }
  if (drives.length > 1) {
    const names = drives.map(d => `  - ${d.name} (${d.id})`).join('\n');
    throw new Error(`Multiple shared drives match "${driveName}":\n${names}\nPlease use --drive-id instead.`);
  }

  return drives[0].id;
}

/**
 * Get drive ID from either --drive-id or --drive-name option.
 * @param {object} drive - Google Drive API client
 * @param {string|null} driveId - Explicit drive ID
 * @param {string|null} driveName - Drive name to resolve
 * @returns {Promise<string|null>} The drive ID or null
 */
async function getDriveIdFromOptions(drive, driveId, driveName) {
  if (driveId) return driveId;
  if (driveName) return await resolveDriveId(drive, driveName);
  return null;
}

/**
 * Get the modification time of a file on Google Drive.
 * @param {object} drive - Google Drive API client
 * @param {string} fileId - The file ID to check
 * @returns {Promise<Date|null>} The modification time or null if file doesn't exist
 */
async function getUpstreamModifiedTime(drive, fileId) {
  try {
    const response = await drive.files.get({
      fileId,
      fields: 'modifiedTime',
      supportsAllDrives: true,
    });
    return new Date(response.data.modifiedTime);
  } catch {
    return null;
  }
}

/**
 * Create a FileRecord object.
 * @param {string} localPath - Local file path
 * @param {string} driveFileId - Google Drive file ID
 * @param {Date} lastOperation - Timestamp of last operation
 * @param {string|null} sourceMimetype - MIME type of source file
 * @param {string|null} destinationMimetype - MIME type for destination file in Drive
 * @param {string|null} exportFormat - Export format (e.g., 'md', 'docx') for exports
 * @param {string|null} driveId - Shared drive ID (if file is in a shared drive)
 * @returns {object} FileRecord object
 */
function createFileRecord(localPath, driveFileId, lastOperation = new Date(), sourceMimetype = null, destinationMimetype = null, exportFormat = null, driveId = null) {
  const record = {
    local_path: localPath,
    drive_file_id: driveFileId,
    last_operation: lastOperation.toISOString(),
  };
  if (sourceMimetype) {
    record.source_mimetype = sourceMimetype;
  }
  if (destinationMimetype) {
    record.destination_mimetype = destinationMimetype;
  }
  if (exportFormat) {
    record.export_format = exportFormat;
  }
  if (driveId) {
    record.drive_id = driveId;
  }
  return record;
}

/**
 * Create an empty FilesMapping object.
 * @returns {object} FilesMapping object
 */
function createFilesMapping() {
  return {
    uploads: {},  // keyed by local_path
    exports: {},  // keyed by drive_file_id
  };
}

/**
 * Find the mapping file by searching current directory and parents.
 * @param {string} filename - The mapping filename to search for
 * @returns {string|null} The absolute path to the found mapping file, or null if not found
 */
function findMappingFile(filename = DEFAULT_MAPPING_PATH) {
  let current = path.resolve(process.cwd());
  
  while (true) {
    const candidate = path.join(current, filename);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
    
    const parent = path.dirname(current);
    if (parent === current) {
      // Reached filesystem root
      break;
    }
    current = parent;
  }
  
  return null;
}

/**
 * Load the files mapping from disk.
 * If no explicit path is provided, searches for the mapping file
 * in the current directory and parent directories.
 * @param {string|null} mappingPath - Optional path to mapping file
 * @returns {object} FilesMapping object
 */
function loadMapping(mappingPath = null) {
  let filePath;
  
  if (mappingPath) {
    // Explicit path provided, use it directly
    filePath = mappingPath;
  } else {
    // Search for existing mapping file in current and parent directories
    const foundPath = findMappingFile(DEFAULT_MAPPING_PATH);
    filePath = foundPath || DEFAULT_MAPPING_PATH;
  }
  
  if (fs.existsSync(filePath)) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(content);
      // Ensure the structure is correct
      return {
        uploads: data.uploads || {},
        exports: data.exports || {},
      };
    } catch {
      return createFilesMapping();
    }
  }
  return createFilesMapping();
}

/**
 * Get the path to use for the mapping file.
 * If no explicit path is provided, searches for an existing mapping file
 * in the current directory and parent directories. If not found,
 * returns the default path in the current directory.
 * @param {string|null} mappingPath - Optional explicit path
 * @returns {string} The path to use for the mapping file
 */
function getMappingPath(mappingPath = null) {
  if (mappingPath) {
    return mappingPath;
  }
  
  const foundPath = findMappingFile(DEFAULT_MAPPING_PATH);
  return foundPath || DEFAULT_MAPPING_PATH;
}

/**
 * Save the files mapping to disk.
 * If no explicit path is provided, saves to the found mapping file location
 * (from current or parent directories) or to the default path in the current directory.
 * @param {object} mapping - FilesMapping object
 * @param {string|null} mappingPath - Optional path to save mapping
 */
function saveMapping(mapping, mappingPath = null) {
  const filePath = getMappingPath(mappingPath);
  fs.writeFileSync(filePath, JSON.stringify(mapping, null, 2));
}

/**
 * Get the absolute path for consistent record-keeping.
 * @param {string} fpath - File path
 * @returns {string} Absolute path
 */
function getAbsolutePath(fpath) {
  return path.resolve(fpath);
}

/**
 * Load saved OAuth token from file or environment variable.
 * @param {string|null} tokenPath - Optional path to token file
 * @returns {object|null} Token data or null
 */
function loadToken(tokenPath = null) {
  // Try environment variable first
  const tokenJson = process.env[TOKEN_ENV_VAR];
  if (tokenJson) {
    try {
      const token = JSON.parse(tokenJson);
      return normalizeToken(token);
    } catch {
      return null;
    }
  }

  // Try file
  const filePath = tokenPath || DEFAULT_TOKEN_PATH;
  if (fs.existsSync(filePath)) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const token = JSON.parse(content);
      return normalizeToken(token);
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Normalize token format to ensure both 'expiry' and 'expiry_date' fields.
 * @param {object} token - Token data
 * @returns {object} Normalized token
 */
function normalizeToken(token) {
  if (!token) return null;
  
  // Ensure we have both expiry (ISO string) and expiry_date (timestamp)
  if (token.expiry && !token.expiry_date) {
    token.expiry_date = new Date(token.expiry).getTime();
  } else if (token.expiry_date && !token.expiry) {
    token.expiry = new Date(token.expiry_date).toISOString();
  }
  
  // Ensure we have both token and access_token for googleapis compatibility
  if (token.token && !token.access_token) {
    token.access_token = token.token;
  } else if (token.access_token && !token.token) {
    token.token = token.access_token;
  }
  
  return token;
}

/**
 * Save OAuth token to file for future use.
 * Includes client_id (public) but excludes client_secret (private) for security.
 * @param {object} tokens - Token data to save
 * @param {string|null} tokenPath - Optional path to save token
 * @param {string|null} accountEmail - Optional account email to store
 */
function saveToken(tokens, tokenPath = null, accountEmail = null) {
  const filePath = tokenPath || DEFAULT_TOKEN_PATH;
  // Include client_id (public) but exclude client_secret (private)
  const { client_secret, ...tokenData } = tokens;
  const dataToSave = { ...tokenData };
  if (accountEmail) {
    dataToSave.account_email = accountEmail;
  }
  fs.writeFileSync(filePath, JSON.stringify(dataToSave, null, 2));
}

/**
 * Fetch the authenticated user's email from Google's userinfo API.
 * @param {string} accessToken - OAuth access token
 * @returns {Promise<string|null>} The user's email or null if fetch fails
 */
async function fetchUserEmail(accessToken) {
  try {
    const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });
    if (response.ok) {
      const data = await response.json();
      return data.email || null;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Get the account email from the stored token.
 * @param {string|null} tokenPath - Optional path to token file
 * @returns {string|null} The stored account email or null
 */
function getStoredAccountEmail(tokenPath = null) {
  const tokenData = loadToken(tokenPath);
  return tokenData?.account_email || null;
}

/**
 * Run OAuth flow using a local server.
 * @param {google.auth.OAuth2} oauth2Client - OAuth2 client
 * @param {string|null} tokenPath - Optional path to save token
 * @returns {Promise<google.auth.OAuth2>} Authenticated OAuth2 client
 */
async function runOAuthFlow(oauth2Client, tokenPath = null) {
  return new Promise((resolve, reject) => {
    // Create a local server to handle the OAuth callback
    const server = http.createServer(async (req, res) => {
      try {
        const url = new URL(req.url, 'http://localhost');
        const code = url.searchParams.get('code');

        if (code) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><h1>Authentication successful!</h1><p>You can close this window.</p></body></html>');

          server.close();

          const { tokens } = await oauth2Client.getToken(code);
          oauth2Client.setCredentials(tokens);

          // Fetch user email and save with token
          const accountEmail = await fetchUserEmail(tokens.access_token);
          saveToken(tokens, tokenPath, accountEmail);
          resolve(oauth2Client);
        } else {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('No authorization code received');
        }
      } catch (error) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Authentication failed');
        server.close();
        reject(error);
      }
    });

    // Listen on a random port
    server.listen(0, async () => {
      const port = server.address().port;
      const redirectUri = `http://localhost:${port}`;

      // Update the redirect URI
      oauth2Client._redirectUri = redirectUri;

      const authUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
        redirect_uri: redirectUri,
      });

      console.log('Opening browser for authentication...');
      await open(authUrl);
    });

    // Timeout after 5 minutes
    setTimeout(() => {
      server.close();
      reject(new Error('OAuth flow timed out'));
    }, 5 * 60 * 1000);
  });
}

/**
 * Return OAuth client config from Desktop (installed) or Web application credentials.
 * Used by token server and credential loading; server supports both types.
 * @param {object} credentials - Full credentials JSON (has 'installed' or 'web' key)
 * @returns {object|null} Client config (client_id, client_secret, redirect_uris, ...) or null
 */
function getOAuthClientConfig(credentials) {
  return credentials?.installed || credentials?.web || null;
}

/**
 * Get OAuth credentials from client secret config.
 * @param {object} data - Client secret config (has 'installed' or 'web' key)
 * @param {string|null} tokenPath - Optional path to token file
 * @param {string|null} tokenServer - Optional token server URL for server-side refresh
 * @returns {Promise<google.auth.OAuth2>} Authenticated OAuth2 client
 */
async function getCredentialsClientSecretFromDict(data, tokenPath = null, tokenServer = null) {
  const clientConfig = getOAuthClientConfig(data);
  const { client_id, client_secret, redirect_uris } = clientConfig || {};

  const oauth2Client = new google.auth.OAuth2(
    client_id,
    client_secret,
    redirect_uris?.[0] || 'http://localhost'
  );

  // Try to load existing token
  const tokenData = loadToken(tokenPath);

  if (tokenData) {
    oauth2Client.setCredentials(tokenData);

    // Check if token is expired and needs refresh
    if (tokenData.expiry_date && Date.now() >= tokenData.expiry_date) {
      if (tokenData.refresh_token) {
        try {
          // Check if token has a saved token_server (if not provided explicitly)
          const detectedTokenServer = tokenServer || tokenData.token_server;
          
          // If using token server, refresh via server
          if (detectedTokenServer) {
            const refreshedToken = await refreshTokenViaServer(tokenPath, detectedTokenServer);
            if (refreshedToken) {
              oauth2Client.setCredentials(refreshedToken);
              return oauth2Client;
            }
            // If server refresh failed, fall through to OAuth flow
          } else {
            // Use local client credentials to refresh
            const { credentials } = await oauth2Client.refreshAccessToken();
            // Preserve the account email from the old token
            saveToken(credentials, tokenPath, tokenData.account_email);
            return oauth2Client;
          }
        } catch {
          // Fall through to new OAuth flow
        }
      }
    } else {
      return oauth2Client;
    }
  }

  // Run OAuth flow
  return runOAuthFlow(oauth2Client, tokenPath);
}

/**
 * Get service account credentials.
 * @param {object} data - Service account config
 * @returns {google.auth.JWT} JWT auth client
 */
function getCredentialsServiceAccountFromDict(data) {
  return new google.auth.JWT({
    email: data.client_email,
    key: data.private_key,
    scopes: SCOPES,
  });
}

/**
 * Detect credentials type from config.
 * @param {object} data - Credentials config
 * @returns {string} 'client_secret' or 'service_account'
 */
function detectCredentialsType(data) {
  if (getOAuthClientConfig(data)) {
    return 'client_secret';
  }
  return 'service_account';
}

/**
 * Get credentials from a config object.
 * @param {object} data - Credentials config
 * @param {string|null} tokenPath - Optional path to token file
 * @param {string|null} tokenServer - Optional token server URL for server-side refresh
 * @returns {Promise<google.auth.OAuth2|google.auth.JWT>} Auth client
 */
async function getCredentialsFromDict(data, tokenPath = null, tokenServer = null) {
  const credentialsType = detectCredentialsType(data);

  if (credentialsType === 'service_account') {
    return getCredentialsServiceAccountFromDict(data);
  } else if (credentialsType === 'client_secret') {
    return getCredentialsClientSecretFromDict(data, tokenPath, tokenServer);
  } else {
    throw new Error(`Invalid credentials type: ${credentialsType}`);
  }
}

/**
 * Get credentials from file path or environment variable.
 * @param {string|null} fpath - Optional path to credentials file
 * @param {string|null} tokenPath - Optional path to token file
 * @param {string|null} tokenServer - Optional token server URL for server-side refresh
 * @returns {Promise<google.auth.OAuth2|google.auth.JWT>} Auth client
 */
async function getCredentials(fpath = null, tokenPath = null, tokenServer = null) {
  // If using token server, try to load existing token first (no credentials file needed)
  const serverUrl = tokenServer || getTokenServer(null);
  if (serverUrl) {
    // Try to load existing token
    const tokenData = loadToken(tokenPath);
    if (tokenData) {
      // Check if token has saved server, prefer that
      const detectedTokenServer = tokenData.token_server || serverUrl;
      
      // Check if token needs refresh BEFORE creating OAuth2 client
      let activeToken = tokenData;
      if (tokenData.expiry_date && Date.now() >= tokenData.expiry_date) {
        console.log('Token expired, refreshing via token server...');
        if (tokenData.refresh_token) {
          // Refresh via token server
          const refreshedToken = await refreshTokenViaServer(tokenPath, detectedTokenServer);
          if (refreshedToken) {
            console.log('Token refreshed successfully');
            activeToken = refreshedToken;
          } else {
            throw new Error(
              `Token expired and refresh failed for server ${detectedTokenServer}. ` +
              `Please re-authenticate: ./cli login --token-server ${detectedTokenServer}`
            );
          }
        } else {
          throw new Error(
            `Token expired and no refresh token available. ` +
            `Please re-authenticate: ./cli login --token-server ${detectedTokenServer}`
          );
        }
      }
      
      // Create OAuth2 client with refreshed/valid token.
      // IMPORTANT: Do NOT pass fake client_id/client_secret and do NOT include
      // refresh_token in the credentials. If googleapis detects an expired token
      // or receives a 401, it will try to auto-refresh using client_id/client_secret
      // from the constructor. With token-server tokens we don't have the real
      // client_secret, so auto-refresh would fail with "invalid_client".
      // We handle all refresh logic ourselves before reaching this point.
      const oauth2Client = new google.auth.OAuth2();
      // Use saved expiry if in the future; otherwise default to 55 min from now
      // (Google access tokens last ~1 hour). This prevents googleapis from
      // attempting auto-refresh when the saved expiry is stale or missing.
      const expiryDate = (activeToken.expiry_date && activeToken.expiry_date > Date.now())
        ? activeToken.expiry_date
        : Date.now() + 55 * 60 * 1000;
      oauth2Client.setCredentials({
        access_token: activeToken.access_token || activeToken.token,
        expiry_date: expiryDate,
        token_type: 'Bearer',
      });
      
      // Token is valid
      return oauth2Client;
    }
    
    // No token found
    throw new Error(
      `No valid token found for token server ${serverUrl}. ` +
      `Please authenticate first: ./cli login --token-server ${serverUrl}`
    );
  }
  
  // Not using token server, need OAuth credentials file
  // First, check environment variable
  const credentialsJson = process.env[CREDENTIALS_ENV_VAR];
  if (credentialsJson) {
    return getCredentialsFromDict(JSON.parse(credentialsJson), tokenPath, tokenServer);
  }

  // Fall back to file path
  const filePath = fpath || 'service_account.json';

  if (!fs.existsSync(filePath)) {
    throw new Error(`Credentials file not found: ${filePath}`);
  }

  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  return getCredentialsFromDict(data, tokenPath, tokenServer);
}

/**
 * Upload a file to Google Drive.
 * @param {string} fpath - Path to file to upload
 * @param {string|null} sourceMimetype - MIME type of source file
 * @param {string|null} destinationMimetype - MIME type for destination file in Drive
 * @param {string|null} credentialsFpath - Path to credentials file
 * @param {string|null} tokenPath - Path to token file
 * @param {string|null} mappingPath - Path to files mapping file
 * @param {boolean} overwrite - Skip upstream modification check
 * @param {string|null} folderId - Parent folder ID (can be a shared drive ID or folder within)
 * @param {string|null} driveId - Shared drive ID (for tracking in mapping)
 * @param {string|null} tokenServer - Token server URL for server-side token refresh
 * @returns {Promise<object>} Uploaded file metadata
 */
async function uploadFile(fpath, sourceMimetype = null, destinationMimetype = null, credentialsFpath = null, tokenPath = null, mappingPath = null, overwrite = false, folderId = null, driveId = null, tokenServer = null) {
  const serverUrl = getTokenServer(tokenServer);
  const auth = await getCredentials(credentialsFpath, tokenPath, serverUrl);
  const drive = google.drive({ version: 'v3', auth });

  // Determine source MIME type
  let mimeType = sourceMimetype;
  if (!mimeType) {
    const ext = path.extname(fpath).slice(1).toLowerCase();
    mimeType = MIME_TYPES[ext];
  }

  if (!mimeType) {
    throw new Error(`Invalid source mimetype: ${fpath}, source mimetype: ${sourceMimetype}`);
  }

  // Load existing mapping
  const mapping = loadMapping(mappingPath);
  const absPath = getAbsolutePath(fpath);

  const fileMetadata = {
    name: path.basename(fpath),
  };

  if (destinationMimetype) {
    fileMetadata.mimeType = destinationMimetype;
  }

  // Set parent folder if provided (for shared drives or specific folders)
  if (folderId) {
    fileMetadata.parents = [folderId];
  }

  const media = {
    mimeType,
    body: fs.createReadStream(fpath),
  };

  // Check if this file was previously uploaded
  const existingRecord = mapping.uploads[absPath];

  let result;

  if (existingRecord) {
    // Check for upstream modifications before updating
    if (!overwrite) {
      const upstreamModifiedTime = await getUpstreamModifiedTime(drive, existingRecord.drive_file_id);
      if (upstreamModifiedTime) {
        const lastOperation = new Date(existingRecord.last_operation);
        if (upstreamModifiedTime > lastOperation) {
          console.error(`Warning: The file on Google Drive was modified after your last operation.`);
          console.error(`  Last local operation: ${lastOperation.toISOString()}`);
          console.error(`  Upstream modified:    ${upstreamModifiedTime.toISOString()}`);
          const proceed = await promptConfirmation('Do you want to overwrite the upstream changes?');
          if (!proceed) {
            throw new Error('Upload cancelled by user');
          }
          // Need to recreate the stream since time passed
          media.body = fs.createReadStream(fpath);
        }
      }
    }

    // Update existing file (don't change parents on update)
    const updateMetadata = { name: fileMetadata.name };
    if (fileMetadata.mimeType) {
      updateMetadata.mimeType = fileMetadata.mimeType;
    }
    try {
      const response = await drive.files.update({
        fileId: existingRecord.drive_file_id,
        requestBody: updateMetadata,
        media,
        fields: 'id',
        supportsAllDrives: true,
      });
      result = response.data;
      // Update timestamp and mimetypes
      existingRecord.last_operation = new Date().toISOString();
      existingRecord.source_mimetype = mimeType;
      existingRecord.destination_mimetype = destinationMimetype || null;
      saveMapping(mapping, mappingPath);
    } catch {
      // If update fails (e.g., file was deleted), create a new one
      // Need to recreate the stream since it was consumed
      media.body = fs.createReadStream(fpath);
      const response = await drive.files.create({
        requestBody: fileMetadata,
        media,
        fields: 'id',
        supportsAllDrives: true,
      });
      result = response.data;
      mapping.uploads[absPath] = createFileRecord(absPath, result.id, new Date(), mimeType, destinationMimetype, null, driveId);
      saveMapping(mapping, mappingPath);
    }
  } else {
    // Create new file
    const response = await drive.files.create({
      requestBody: fileMetadata,
      media,
      fields: 'id',
      supportsAllDrives: true,
    });
    result = response.data;
    mapping.uploads[absPath] = createFileRecord(absPath, result.id, new Date(), mimeType, destinationMimetype, null, driveId);
    saveMapping(mapping, mappingPath);
  }

  return result;
}

/**
 * Export a Google Workspace document to the specified format.
 * @param {string} fileId - Google Drive file ID
 * @param {string} outputPath - Path where the exported file will be saved
 * @param {string} exportFormat - Export format (default: 'md')
 * @param {string|null} credentialsFpath - Path to credentials file
 * @param {string|null} tokenPath - Path to token file
 * @param {string|null} mappingPath - Path to files mapping file
 * @param {string|null} driveId - Shared drive ID (for tracking in mapping)
 * @param {string|null} tokenServer - Token server URL for server-side token refresh
 * @returns {Promise<string>} Output path
 */
async function exportFile(fileId, outputPath, exportFormat = 'md', credentialsFpath = null, tokenPath = null, mappingPath = null, driveId = null, tokenServer = null) {
  const serverUrl = getTokenServer(tokenServer);
  const auth = await getCredentials(credentialsFpath, tokenPath, serverUrl);
  const drive = google.drive({ version: 'v3', auth });

  // Get the MIME type for the export format
  const mimeType = EXPORT_MIME_TYPES[exportFormat];
  if (!mimeType) {
    throw new Error(
      `Invalid export format: ${exportFormat}. ` +
      `Supported formats: ${Object.keys(EXPORT_MIME_TYPES).join(', ')}`
    );
  }

  // Export the file
  const response = await drive.files.export({
    fileId,
    mimeType,
  }, {
    responseType: TEXT_FORMATS.has(exportFormat) ? 'text' : 'arraybuffer',
  });

  const content = response.data;

  // Write to output file
  if (TEXT_FORMATS.has(exportFormat)) {
    fs.writeFileSync(outputPath, content, 'utf8');
  } else {
    fs.writeFileSync(outputPath, Buffer.from(content));
  }

  // Record the export in the mapping
  const absOutputPath = getAbsolutePath(outputPath);
  const mapping = loadMapping(mappingPath);
  mapping.exports[fileId] = createFileRecord(absOutputPath, fileId, new Date(), null, null, exportFormat, driveId);
  saveMapping(mapping, mappingPath);

  return outputPath;
}

/**
 * Re-export all documents that have been previously exported.
 * @param {string|null} credentialsFpath - Path to credentials file
 * @param {string|null} tokenPath - Path to token file
 * @param {string|null} mappingPath - Path to files mapping file
 * @param {string|null} tokenServer - Token server URL for server-side token refresh
 * @returns {Promise<string[]>} Array of paths to re-exported files
 */
async function pullAll(credentialsFpath = null, tokenPath = null, mappingPath = null, tokenServer = null) {
  const mapping = loadMapping(mappingPath);
  
  if (!mapping.exports || Object.keys(mapping.exports).length === 0) {
    return [];
  }
  
  const serverUrl = getTokenServer(tokenServer);
  const auth = await getCredentials(credentialsFpath, tokenPath, serverUrl);
  const drive = google.drive({ version: 'v3', auth });
  
  const results = [];
  
  for (const [fileId, record] of Object.entries(mapping.exports)) {
    const outputPath = record.local_path;
    
    // Use stored export format if available, otherwise determine from file extension
    let exportFormat = record.export_format;
    if (!exportFormat) {
      const ext = path.extname(outputPath).slice(1).toLowerCase();
      exportFormat = EXPORT_MIME_TYPES[ext] ? ext : 'md';
    }
    
    const mimeType = EXPORT_MIME_TYPES[exportFormat];
    if (!mimeType) {
      console.error(`Warning: Skipping ${outputPath} - unsupported format: ${exportFormat}`);
      continue;
    }
    
    try {
      // Export the file
      const response = await drive.files.export({
        fileId,
        mimeType,
        supportsAllDrives: true,
      }, {
        responseType: TEXT_FORMATS.has(exportFormat) ? 'text' : 'arraybuffer',
      });
      
      const content = response.data;
      
      // Write to output file
      if (TEXT_FORMATS.has(exportFormat)) {
        fs.writeFileSync(outputPath, content, 'utf8');
      } else {
        fs.writeFileSync(outputPath, Buffer.from(content));
      }
      
      // Update the timestamp in the mapping
      record.last_operation = new Date().toISOString();
      results.push(outputPath);
    } catch (error) {
      // Provide detailed error information
      console.error(`Warning: Failed to re-export ${outputPath}:`);
      console.error(`  File ID: ${fileId}`);
      console.error(`  Export format: ${exportFormat} (${mimeType})`);
      
      // Log error details
      if (error.response) {
        console.error(`  HTTP Status: ${error.response.status} ${error.response.statusText}`);
        console.error(`  Response data:`, JSON.stringify(error.response.data, null, 2));
      } else if (error.message) {
        console.error(`  Error message: ${error.message}`);
      }
      
      // Log full error for debugging
      if (error.code) {
        console.error(`  Error code: ${error.code}`);
      }
      
      // Check if it's an API error with structured details
      const errorDetails = error.response?.data?.error;
      if (errorDetails) {
        if (errorDetails.message) {
          console.error(`  API error message: ${errorDetails.message}`);
        }
        if (errorDetails.errors && Array.isArray(errorDetails.errors)) {
          console.error(`  API error details:`);
          errorDetails.errors.forEach(e => {
            console.error(`    - ${e.reason}: ${e.message}`);
            if (e.location) console.error(`      Location: ${e.location}`);
            if (e.domain) console.error(`      Domain: ${e.domain}`);
          });
        }
        if (errorDetails.status) {
          console.error(`  API status: ${errorDetails.status}`);
        }
      }
      
      continue;
    }
  }
  
  // Save updated mapping
  saveMapping(mapping, mappingPath);
  
  return results;
}

/**
 * Re-upload all files that have been previously uploaded.
 * @param {string|null} credentialsFpath - Path to credentials file
 * @param {string|null} tokenPath - Path to token file
 * @param {string|null} mappingPath - Path to files mapping file
 * @param {boolean} overwrite - Skip upstream modification check
 * @param {string|null} tokenServer - Token server URL for server-side token refresh
 * @returns {Promise<string[]>} Array of paths to re-uploaded files
 */
async function pushAll(credentialsFpath = null, tokenPath = null, mappingPath = null, overwrite = false, tokenServer = null) {
  const mapping = loadMapping(mappingPath);
  
  if (!mapping.uploads || Object.keys(mapping.uploads).length === 0) {
    return [];
  }
  
  const serverUrl = getTokenServer(tokenServer);
  const auth = await getCredentials(credentialsFpath, tokenPath, serverUrl);
  const drive = google.drive({ version: 'v3', auth });
  
  const results = [];
  
  for (const [localPath, record] of Object.entries(mapping.uploads)) {
    // Check if local file exists
    if (!fs.existsSync(localPath)) {
      console.error(`Warning: Skipping ${localPath} - file not found`);
      continue;
    }
    
    // Use stored MIME type if available, otherwise determine from extension
    let sourceMimetype = record.source_mimetype;
    if (!sourceMimetype) {
      const ext = path.extname(localPath).slice(1).toLowerCase();
      sourceMimetype = MIME_TYPES[ext];
    }
    if (!sourceMimetype) {
      const ext = path.extname(localPath).slice(1).toLowerCase();
      console.error(`Warning: Skipping ${localPath} - unsupported format: ${ext}`);
      continue;
    }
    
    // Use stored destination MIME type if available
    const destinationMimetype = record.destination_mimetype;
    
    try {
      // Check for upstream modifications before updating
      if (!overwrite) {
        const upstreamModifiedTime = await getUpstreamModifiedTime(drive, record.drive_file_id);
        if (upstreamModifiedTime) {
          const lastOperation = new Date(record.last_operation);
          if (upstreamModifiedTime > lastOperation) {
            console.error(`Warning: ${localPath} - upstream was modified after last operation.`);
            console.error(`  Last local operation: ${lastOperation.toISOString()}`);
            console.error(`  Upstream modified:    ${upstreamModifiedTime.toISOString()}`);
            const proceed = await promptConfirmation('Do you want to overwrite the upstream changes?');
            if (!proceed) {
              console.log(`Skipping: ${localPath}`);
              continue;
            }
          }
        }
      }
      
      // Prepare metadata and media
      const fileMetadata = { name: path.basename(localPath) };
      if (destinationMimetype) {
        fileMetadata.mimeType = destinationMimetype;
      }
      const media = {
        mimeType: sourceMimetype,
        body: fs.createReadStream(localPath),
      };
      
      // Update existing file
      await drive.files.update({
        fileId: record.drive_file_id,
        requestBody: fileMetadata,
        media,
        fields: 'id',
        supportsAllDrives: true,
      });
      
      // Update timestamp
      record.last_operation = new Date().toISOString();
      results.push(localPath);
      
    } catch (error) {
      console.error(`Warning: Failed to re-upload ${localPath}: ${error.message}`);
      continue;
    }
  }
  
  // Save updated mapping
  saveMapping(mapping, mappingPath);
  
  return results;
}

/**
 * Share a file on Google Drive with one or more email addresses.
 * @param {string} fpath - Local file path (must have been previously uploaded)
 * @param {string} emails - Email address(es) to share with (comma-separated for multiple)
 * @param {string} role - Permission role ('reader', 'writer', or 'commenter')
 * @param {boolean} notify - Whether to send notification email
 * @param {string|null} credentialsFpath - Path to credentials file
 * @param {string|null} tokenPath - Path to token file
 * @param {string|null} mappingPath - Path to files mapping file
 * @param {string|null} tokenServer - Token server URL for server-side token refresh
 * @returns {Promise<object[]>} Array of created permission metadata
 */
async function shareFile(fpath, emails, role = 'reader', notify = true, credentialsFpath = null, tokenPath = null, mappingPath = null, tokenServer = null) {
  // Load mapping and resolve file path to Drive ID
  const mapping = loadMapping(mappingPath);
  const absPath = getAbsolutePath(fpath);
  
  const existingRecord = mapping.uploads[absPath];
  if (!existingRecord) {
    throw new Error(`File not found in mapping: ${fpath}\nMake sure the file has been uploaded first using the 'upload' command.`);
  }
  
  const fileId = existingRecord.drive_file_id;
  
  const serverUrl = getTokenServer(tokenServer);
  const auth = await getCredentials(credentialsFpath, tokenPath, serverUrl);
  const drive = google.drive({ version: 'v3', auth });
  
  // Parse comma-separated email addresses
  const emailList = emails.split(',').map(e => e.trim()).filter(e => e.length > 0);
  
  if (emailList.length === 0) {
    throw new Error('No valid email addresses provided');
  }
  
  // Create permissions for each email address
  const results = [];
  for (const email of emailList) {
    const permission = {
      type: 'user',
      role: role,
      emailAddress: email,
    };
    
    const response = await drive.permissions.create({
      fileId: fileId,
      requestBody: permission,
      sendNotificationEmail: notify,
      fields: 'id,type,role,emailAddress',
      supportsAllDrives: true,
    });
    
    results.push(response.data);
  }
  
  return results;
}

// CLI setup
const program = new Command();

program
  .name('gdrive')
  .description('Google Drive file operations')
  .version('1.0.0');

// Upload command
program
  .command('upload')
  .description('Upload a file to Google Drive (supports shared drives)')
  .argument('<fpath>', 'Path to the file to upload')
  .option('-s, --source-mimetype <type>', 'MIME type of the source file. Accepts short aliases: md, txt, pdf, docx, xlsx, csv, etc.')
  .option('-d, --destination-mimetype <type>', 'MIME type for the destination file in Drive. Accepts short aliases: gdoc, gsheet, gslide, gdraw')
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .option('-t, --token-path <path>', `Path to save/load OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .option('-m, --mapping-path <path>', `Path to files mapping JSON. Default: ${DEFAULT_MAPPING_PATH}`)
  .option('--overwrite', 'Skip upstream modification check and overwrite without prompting')
  .option('--token-server <url>', `URL of token server to fetch OAuth token from. Can also be set via ${TOKEN_SERVER_ENV_VAR} env var`)
  .option('--folder-id <id>', 'Parent folder ID to upload into (can be a shared drive root or folder within)')
  .option('--drive-id <id>', 'Shared drive ID (for tracking; use --folder-id for the actual destination)')
  .option('--drive-name <name>', 'Shared drive name (resolved to ID; use --folder-id for the actual destination)')
  .action(async (fpath, options) => {
    try {
      // If token-server is provided (via CLI or env var), fetch token from server first
      const serverUrl = getTokenServer(options.tokenServer);
      if (serverUrl) {
        await fetchTokenFromServer(serverUrl, options.tokenPath);
      }

      // Resolve drive name to ID if provided
      let driveId = options.driveId;
      if (options.driveName && !driveId) {
        const auth = await getCredentials(options.credentialsFpath, options.tokenPath, serverUrl);
        const drive = google.drive({ version: 'v3', auth });
        driveId = await resolveDriveId(drive, options.driveName);
      }

      // If drive ID is provided but no folder ID, use drive ID as folder (upload to root of shared drive)
      const folderId = options.folderId || driveId;

      // Resolve short aliases to full MIME types
      const resolvedSource = resolveMimetype(options.sourceMimetype);
      const resolvedDest = resolveMimetype(options.destinationMimetype);
      const file = await uploadFile(
        fpath,
        resolvedSource,
        resolvedDest,
        options.credentialsFpath,
        options.tokenPath,
        options.mappingPath,
        options.overwrite || false,
        folderId,
        driveId,
        serverUrl
      );
      console.log(file.id);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Export command
program
  .command('export')
  .description('Export a Google Workspace document to a local file (supports shared drives)')
  .argument('<file-id>', 'The Google Drive file ID to export')
  .argument('<output-path>', 'Path where the exported file will be saved')
  .option('-f, --format <format>', `Export format. Supported: ${Object.keys(EXPORT_MIME_TYPES).join(', ')}`, 'md')
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .option('-t, --token-path <path>', `Path to save/load OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .option('-m, --mapping-path <path>', `Path to files mapping JSON. Default: ${DEFAULT_MAPPING_PATH}`)
  .option('--token-server <url>', `URL of token server to fetch OAuth token from. Can also be set via ${TOKEN_SERVER_ENV_VAR} env var`)
  .option('--drive-id <id>', 'Shared drive ID (for tracking in the mapping file)')
  .option('--drive-name <name>', 'Shared drive name (resolved to ID for tracking)')
  .action(async (fileId, outputPath, options) => {
    try {
      // If token-server is provided (via CLI or env var), fetch token from server first
      const serverUrl = getTokenServer(options.tokenServer);
      if (serverUrl) {
        await fetchTokenFromServer(serverUrl, options.tokenPath);
      }

      // Resolve drive name to ID if provided
      let driveId = options.driveId;
      if (options.driveName && !driveId) {
        const auth = await getCredentials(options.credentialsFpath, options.tokenPath, serverUrl);
        const drive = google.drive({ version: 'v3', auth });
        driveId = await resolveDriveId(drive, options.driveName);
      }

      const result = await exportFile(
        fileId,
        outputPath,
        options.format,
        options.credentialsFpath,
        options.tokenPath,
        options.mappingPath,
        driveId,
        serverUrl
      );
      console.log(`Exported to: ${result}`);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Share command
program
  .command('share')
  .description('Share an uploaded file with one or more email addresses')
  .argument('<fpath>', 'Path to the local file (must have been uploaded)')
  .argument('<emails>', 'Email address(es) to share with (comma-separated for multiple)')
  .option('-r, --role <role>', 'Permission role: reader, writer, or commenter', 'reader')
  .option('--no-notify', 'Do not send notification email to the recipient')
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .option('-t, --token-path <path>', `Path to save/load OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .option('-m, --mapping-path <path>', `Path to files mapping JSON. Default: ${DEFAULT_MAPPING_PATH}`)
  .option('--token-server <url>', `URL of token server to fetch OAuth token from. Can also be set via ${TOKEN_SERVER_ENV_VAR} env var`)
  .action(async (fpath, emails, options) => {
    try {
      // Validate role
      const validRoles = ['reader', 'writer', 'commenter'];
      if (!validRoles.includes(options.role)) {
        throw new Error(`Invalid role: ${options.role}. Must be one of: ${validRoles.join(', ')}`);
      }
      
      // If token-server is provided (via CLI or env var), fetch token from server first
      const serverUrl = getTokenServer(options.tokenServer);
      if (serverUrl) {
        await fetchTokenFromServer(serverUrl, options.tokenPath);
      }

      const permissions = await shareFile(
        fpath,
        emails,
        options.role,
        options.notify,
        options.credentialsFpath,
        options.tokenPath,
        options.mappingPath,
        serverUrl
      );
      
      for (const permission of permissions) {
        console.log(`Shared with ${permission.emailAddress} as ${permission.role}`);
      }
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Pull command
program
  .command('pull')
  .description('Re-export all documents that have been previously exported')
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .option('-t, --token-path <path>', `Path to save/load OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .option('-m, --mapping-path <path>', `Path to files mapping JSON. Default: ${DEFAULT_MAPPING_PATH}`)
  .option('--token-server <url>', `URL of token server to fetch OAuth token from. Can also be set via ${TOKEN_SERVER_ENV_VAR} env var`)
  .action(async (options) => {
    try {
      // If token-server is provided (via CLI or env var), fetch token from server first
      const serverUrl = getTokenServer(options.tokenServer);
      if (serverUrl) {
        await fetchTokenFromServer(serverUrl, options.tokenPath);
      }
      const results = await pullAll(
        options.credentialsFpath,
        options.tokenPath,
        options.mappingPath,
        serverUrl
      );
      if (results.length === 0) {
        console.log('No previously exported documents found.');
      } else {
        for (const filePath of results) {
          console.log(`Re-exported: ${filePath}`);
        }
        console.log(`\nTotal: ${results.length} document(s) re-exported.`);
      }
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Push command
program
  .command('push')
  .description('Re-upload all files that have been previously uploaded')
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .option('-t, --token-path <path>', `Path to save/load OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .option('-m, --mapping-path <path>', `Path to files mapping JSON. Default: ${DEFAULT_MAPPING_PATH}`)
  .option('--overwrite', 'Skip upstream modification check and overwrite without prompting')
  .option('--token-server <url>', `URL of token server to fetch OAuth token from. Can also be set via ${TOKEN_SERVER_ENV_VAR} env var`)
  .action(async (options) => {
    try {
      // If token-server is provided (via CLI or env var), fetch token from server first
      const serverUrl = getTokenServer(options.tokenServer);
      if (serverUrl) {
        await fetchTokenFromServer(serverUrl, options.tokenPath);
      }
      const results = await pushAll(
        options.credentialsFpath,
        options.tokenPath,
        options.mappingPath,
        options.overwrite || false,
        serverUrl
      );
      if (results.length === 0) {
        console.log('No previously uploaded files found.');
      } else {
        for (const filePath of results) {
          console.log(`Re-uploaded: ${filePath}`);
        }
        console.log(`\nTotal: ${results.length} file(s) re-uploaded.`);
      }
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Sync command (pull + push)
program
  .command('sync')
  .description('Sync all documents: first pull (re-export), then push (re-upload)')
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .option('-t, --token-path <path>', `Path to save/load OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .option('-m, --mapping-path <path>', `Path to files mapping JSON. Default: ${DEFAULT_MAPPING_PATH}`)
  .option('--overwrite', 'Skip upstream modification check and overwrite without prompting')
  .option('--token-server <url>', `URL of token server to fetch OAuth token from. Can also be set via ${TOKEN_SERVER_ENV_VAR} env var`)
  .action(async (options) => {
    try {
      // If token-server is provided (via CLI or env var), fetch token from server first
      const serverUrl = getTokenServer(options.tokenServer);
      if (serverUrl) {
        await fetchTokenFromServer(serverUrl, options.tokenPath);
      }

      // First, pull (re-export all documents)
      console.log('--- Pull (re-exporting documents) ---');
      const pullResults = await pullAll(
        options.credentialsFpath,
        options.tokenPath,
        options.mappingPath,
        serverUrl
      );
      if (pullResults.length === 0) {
        console.log('No previously exported documents found.');
      } else {
        for (const filePath of pullResults) {
          console.log(`Re-exported: ${filePath}`);
        }
        console.log(`Pull complete: ${pullResults.length} document(s) re-exported.\n`);
      }

      // Then, push (re-upload all files)
      console.log('--- Push (re-uploading files) ---');
      const pushResults = await pushAll(
        options.credentialsFpath,
        options.tokenPath,
        options.mappingPath,
        options.overwrite || false,
        serverUrl
      );
      if (pushResults.length === 0) {
        console.log('No previously uploaded files found.');
      } else {
        for (const filePath of pushResults) {
          console.log(`Re-uploaded: ${filePath}`);
        }
        console.log(`Push complete: ${pushResults.length} file(s) re-uploaded.\n`);
      }

      // Summary
      console.log('--- Sync Summary ---');
      console.log(`Documents pulled: ${pullResults.length}`);
      console.log(`Files pushed: ${pushResults.length}`);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// List shared drives command
program
  .command('list-drives')
  .description('List all shared drives accessible to the user')
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .option('-t, --token-path <path>', `Path to save/load OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .option('--token-server <url>', `URL of token server to fetch OAuth token from. Can also be set via ${TOKEN_SERVER_ENV_VAR} env var`)
  .option('-q, --query <query>', 'Search query (e.g., "name contains \'project\'")')
  .action(async (options) => {
    try {
      // If token-server is provided (via CLI or env var), fetch token from server first
      const serverUrl = getTokenServer(options.tokenServer);
      if (serverUrl) {
        await fetchTokenFromServer(serverUrl, options.tokenPath);
      }
      const auth = await getCredentials(options.credentialsFpath, options.tokenPath, serverUrl);
      const drive = google.drive({ version: 'v3', auth });

      const params = {
        pageSize: 100,
        fields: 'nextPageToken, drives(id, name, createdTime)',
      };
      if (options.query) {
        params.q = options.query;
      }

      let allDrives = [];
      let pageToken = null;

      do {
        if (pageToken) params.pageToken = pageToken;
        const response = await drive.drives.list(params);
        allDrives = allDrives.concat(response.data.drives || []);
        pageToken = response.data.nextPageToken;
      } while (pageToken);

      if (allDrives.length === 0) {
        console.log('No shared drives found.');
      } else {
        console.log('Shared Drives:\n');
        for (const d of allDrives) {
          console.log(`  ${d.name}`);
          console.log(`    ID: ${d.id}`);
          if (d.createdTime) {
            console.log(`    Created: ${d.createdTime}`);
          }
          console.log('');
        }
        console.log(`Total: ${allDrives.length} shared drive(s)`);
      }
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// ============================================================================
// Token Server Functionality
// ============================================================================

/**
 * Generate the landing page HTML.
 * @param {string} baseUrl - Base URL of the server
 * @param {string|null} error - Error message to display, if any
 * @returns {string} HTML content
 */
function generateLandingPage(baseUrl, error = null) {
  const errorHtml = error ? `<div class="error">${escapeHtml(error)}</div>` : '';
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>gdrive — Google Drive CLI Authentication</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Outfit:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0a0a0f;
      --bg-card: #12121a;
      --accent: #00d4aa;
      --accent-dim: #00a88a;
      --text-primary: #f0f0f5;
      --text-secondary: #8888a0;
      --border: #2a2a3a;
      --error: #ff4466;
      --success: #00d4aa;
    }
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body {
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
    }
    
    .container {
      max-width: 520px;
      width: 100%;
    }
    
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 3rem;
      text-align: center;
    }
    
    .logo {
      font-family: 'JetBrains Mono', monospace;
      font-size: 2.5rem;
      font-weight: 600;
      color: var(--accent);
      margin-bottom: 0.5rem;
      letter-spacing: -0.02em;
    }
    
    .tagline {
      color: var(--text-secondary);
      font-size: 1rem;
      margin-bottom: 2.5rem;
    }
    
    .steps {
      text-align: left;
      margin-bottom: 2.5rem;
      padding: 1.5rem;
      background: rgba(0, 212, 170, 0.04);
      border-radius: 12px;
      border: 1px solid rgba(0, 212, 170, 0.1);
    }
    
    .steps h3 {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--accent);
      margin-bottom: 1rem;
    }
    
    .step {
      display: flex;
      gap: 1rem;
      align-items: flex-start;
      padding: 0.75rem 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    .step:last-child { border-bottom: none; }
    
    .step-num {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: var(--accent);
      background: rgba(0, 212, 170, 0.15);
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      flex-shrink: 0;
    }
    
    .step-text {
      color: var(--text-secondary);
      font-size: 0.95rem;
      line-height: 1.5;
    }
    
    .google-btn {
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
    }
    
    .google-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
    }
    
    .google-btn svg {
      width: 20px;
      height: 20px;
    }
    
    .error {
      background: rgba(255, 68, 102, 0.1);
      border: 1px solid rgba(255, 68, 102, 0.3);
      color: var(--error);
      padding: 1rem;
      border-radius: 8px;
      margin-bottom: 1.5rem;
      font-size: 0.9rem;
    }
    
    .footer {
      margin-top: 2rem;
      font-size: 0.8rem;
      color: var(--text-secondary);
    }
    
    .footer a {
      color: var(--accent);
      text-decoration: none;
    }
    
    .footer a:hover { text-decoration: underline; }
    
    code {
      font-family: 'JetBrains Mono', monospace;
      background: rgba(255, 255, 255, 0.08);
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-size: 0.85em;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="logo">gdrive</div>
      <p class="tagline">Command-line Google Drive operations</p>
      
      ${errorHtml}
      
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
      
      <a href="${baseUrl}/auth/start" class="google-btn">
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
</html>`;
}

/**
 * Generate the success page HTML with the token.
 * @param {object} token - The OAuth token
 * @param {string} sessionId - The session ID for CLI retrieval
 * @returns {string} HTML content
 */
function generateSuccessPage(token, sessionId) {
  const tokenJson = JSON.stringify(token, null, 2);
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Success — gdrive Authentication</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Outfit:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0a0a0f;
      --bg-card: #12121a;
      --accent: #00d4aa;
      --accent-dim: #00a88a;
      --text-primary: #f0f0f5;
      --text-secondary: #8888a0;
      --border: #2a2a3a;
      --success: #00d4aa;
    }
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body {
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
    }
    
    .container {
      max-width: 700px;
      width: 100%;
    }
    
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 3rem;
      text-align: center;
    }
    
    .success-icon {
      width: 64px;
      height: 64px;
      background: rgba(0, 212, 170, 0.15);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 1.5rem;
    }
    
    .success-icon svg {
      width: 32px;
      height: 32px;
      color: var(--success);
    }
    
    h1 {
      font-size: 1.75rem;
      margin-bottom: 0.5rem;
    }
    
    .subtitle {
      color: var(--text-secondary);
      margin-bottom: 2rem;
    }
    
    .token-section {
      text-align: left;
      margin-bottom: 2rem;
    }
    
    .token-section h3 {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--accent);
      margin-bottom: 0.75rem;
    }
    
    .token-box {
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      position: relative;
    }
    
    .token-content {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      color: var(--text-secondary);
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 200px;
      overflow-y: auto;
    }
    
    .copy-btn {
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
    }
    
    .copy-btn:hover {
      background: var(--accent-dim);
    }
    
    .copy-btn.copied {
      background: var(--success);
    }
    
    .cli-section {
      background: rgba(0, 212, 170, 0.04);
      border: 1px solid rgba(0, 212, 170, 0.1);
      border-radius: 12px;
      padding: 1.5rem;
      text-align: left;
      margin-bottom: 1.5rem;
    }
    
    .cli-section h3 {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--accent);
      margin-bottom: 0.75rem;
    }
    
    .cli-section p {
      color: var(--text-secondary);
      font-size: 0.9rem;
      margin-bottom: 1rem;
    }
    
    .cli-section code {
      display: block;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      background: rgba(0, 0, 0, 0.3);
      padding: 1rem;
      border-radius: 6px;
      color: var(--text-primary);
      overflow-x: auto;
    }
    
    .done-btn {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-secondary);
      padding: 0.75rem 2rem;
      border-radius: 8px;
      font-family: 'Outfit', sans-serif;
      font-size: 0.95rem;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    
    .done-btn:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
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
          <div class="token-content" id="token">${escapeHtml(tokenJson)}</div>
        </div>
      </div>
      
      <button class="done-btn" onclick="window.close()">Close Window</button>
    </div>
  </div>
  
  <script>
    const token = ${JSON.stringify(tokenJson)};
    
    function copyToken() {
      navigator.clipboard.writeText(token).then(() => {
        const btn = document.querySelector('.copy-btn');
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = 'Copy';
          btn.classList.remove('copied');
        }, 2000);
      });
    }
  </script>
</body>
</html>`;
}

/**
 * Escape HTML special characters.
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
function escapeHtml(str) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return str.replace(/[&<>"']/g, m => map[m]);
}

/**
 * Refresh an access token using the token server.
 * @param {string} serverUrl - URL of the token server
 * @param {string} refreshToken - The refresh token to use
 * @returns {Promise<object|null>} Object with 'token' and 'expiry', or null if refresh failed
 */
async function refreshTokenFromServer(serverUrl, refreshToken) {
  // Use the TokenServerAdapter to support multiple server types
  const { createAdapter } = await import('./token-server-adapter.js');
  
  try {
    const adapter = createAdapter(serverUrl);
    return await adapter.refreshToken(refreshToken);
  } catch (error) {
    console.error('Token refresh failed:', error.message);
    return null;
  }
}

/**
 * Refresh token via server and update token file.
 * @param {string} tokenPath - Path to token file
 * @param {string} serverUrl - Token server URL
 * @returns {Promise<object|null>} Refreshed token data or null if refresh failed
 */
async function refreshTokenViaServer(tokenPath, serverUrl) {
  // Load current token to get refresh_token
  const filePath = tokenPath || DEFAULT_TOKEN_PATH;
  if (!fs.existsSync(filePath)) {
    return null;
  }
  
  try {
    const tokenData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const refreshToken = tokenData.refresh_token;
    
    if (!refreshToken) {
      return null;
    }
    
    // Call server to refresh
    const result = await refreshTokenFromServer(serverUrl, refreshToken);
    if (!result) {
      return null;
    }
    
    // Update token data with new access token
    // Support both 'token' and 'access_token' fields for compatibility
    tokenData.token = result.token;
    tokenData.access_token = result.token;
    if (result.expiry) {
      tokenData.expiry = result.expiry;
      tokenData.expiry_date = new Date(result.expiry).getTime();
    }
    
    // Ensure expiry_date is in the future after a successful refresh.
    // If the server didn't return an expiry (or it parsed to a past time),
    // default to 55 minutes from now (Google access tokens last ~1 hour).
    if (!tokenData.expiry_date || tokenData.expiry_date <= Date.now()) {
      const defaultExpiry = new Date(Date.now() + 55 * 60 * 1000);
      tokenData.expiry = defaultExpiry.toISOString();
      tokenData.expiry_date = defaultExpiry.getTime();
    }
    
    // Save updated token
    fs.writeFileSync(filePath, JSON.stringify(tokenData, null, 2));
    
    return tokenData;
  } catch (error) {
    console.error('Failed to refresh token via server:', error.message);
    return null;
  }
}

/**
 * Fetch token from a token server.
 * @param {string} serverUrl - URL of the token server
 * @param {string|null} tokenPath - Path to save the token
 * @returns {Promise<void>}
 */
async function fetchTokenFromServer(serverUrl, tokenPath = null) {
  // Check if we already have a valid token
  const existingToken = loadToken(tokenPath);
  if (existingToken) {
    // Token exists, check if it's still valid
    if (!existingToken.expiry_date || Date.now() < existingToken.expiry_date) {
      return; // Token is still valid
    }

    // Token is expired, try to refresh via token server before interactive auth
    if (existingToken.refresh_token) {
      const detectedServer = existingToken.token_server || serverUrl;
      const refreshedToken = await refreshTokenViaServer(tokenPath, detectedServer);
      if (refreshedToken) {
        console.log('Token refreshed successfully via token server.');
        return;
      }
    }
  }

  // No valid token and refresh failed (or no refresh_token) — interactive auth
  const { createAdapter } = await import('./token-server-adapter.js');
  
  const adapter = createAdapter(serverUrl);
  const tokenData = await adapter.fetchTokenInteractive(tokenPath);
  
  // Save the token
  saveToken(tokenData, tokenPath);
  console.log('Token saved successfully!');
}

/**
 * Start the OAuth token server.
 * @param {number} port - Port to listen on
 * @param {string|null} credentialsFpath - Path to credentials file
 * @returns {Promise<void>}
 */
async function startTokenServer(port, credentialsFpath = null) {
  // Load credentials
  let credentials;
  const credentialsJson = process.env[CREDENTIALS_ENV_VAR];
  
  if (credentialsJson) {
    credentials = JSON.parse(credentialsJson);
  } else if (credentialsFpath && fs.existsSync(credentialsFpath)) {
    credentials = JSON.parse(fs.readFileSync(credentialsFpath, 'utf8'));
  } else {
    throw new Error(
      `Credentials required. Set ${CREDENTIALS_ENV_VAR} env var or use --credentials-fpath`
    );
  }

  // Server supports both Desktop (installed) and Web application credentials
  const credsData = getOAuthClientConfig(credentials);
  if (!credsData?.client_id || !credsData?.client_secret) {
    throw new Error('Invalid credentials: missing client_id or client_secret');
  }
  const { client_id, client_secret } = credsData;

  const server = http.createServer(async (req, res) => {
    // Build base URL from request (Host / X-Forwarded-*) for redirect_uri and links
    const proto = (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim().toLowerCase() || 'http';
    const host = (req.headers['x-forwarded-host'] || req.headers.host || `localhost:${port}`).split(',')[0].trim();
    const baseUrl = `${proto}://${host}`;

    const url = new URL(req.url, baseUrl);

    try {
      // Landing page
      if (url.pathname === '/' || url.pathname === '') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(generateLandingPage(baseUrl));
        return;
      }

      // Start OAuth flow
      if (url.pathname === '/auth/start') {
        const callback = url.searchParams.get('callback');
        const sessionId = url.searchParams.get('session') || crypto.randomBytes(16).toString('hex');
        
        // Store callback URL for this session
        pendingSessions.set(sessionId, { callback, timestamp: Date.now() });
        
        // Clean up old sessions (older than 10 minutes)
        const now = Date.now();
        for (const [id, session] of pendingSessions.entries()) {
          if (now - session.timestamp > 10 * 60 * 1000) {
            pendingSessions.delete(id);
          }
        }

        const redirectUri = `${baseUrl}/auth/callback`;
        const oauth2Client = new google.auth.OAuth2(client_id, client_secret, redirectUri);
        
        const authUrl = oauth2Client.generateAuthUrl({
          access_type: 'offline',
          scope: SCOPES,
          state: sessionId,
          prompt: 'consent',
        });

        res.writeHead(302, { Location: authUrl });
        res.end();
        return;
      }

      // OAuth callback from Google
      if (url.pathname === '/auth/callback') {
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const error = url.searchParams.get('error');

        if (error) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(generateLandingPage(baseUrl, `Google authentication error: ${error}`));
          return;
        }

        if (!code) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(generateLandingPage(baseUrl, 'No authorization code received'));
          return;
        }

        const redirectUri = `${baseUrl}/auth/callback`;
        const oauth2Client = new google.auth.OAuth2(client_id, client_secret, redirectUri);
        
        try {
          const { tokens } = await oauth2Client.getToken(code);
          
          // Check if there's a CLI callback waiting
          const session = pendingSessions.get(state);
          if (session?.callback) {
            // Include client_id (public) but strip client_secret (private) for security
            const { client_secret, ...safeTokens } = tokens;
            // Redirect to CLI's local server with the token
            const tokenParam = encodeURIComponent(JSON.stringify(safeTokens));
            const callbackUrl = `${session.callback}?token=${tokenParam}`;
            pendingSessions.delete(state);
            
            res.writeHead(302, { Location: callbackUrl });
            res.end();
            return;
          }
          
          // No CLI callback, show the success page with token
          pendingSessions.delete(state);
          // Include client_id (public) but strip client_secret (private) for security
          const { client_secret, ...safeTokens } = tokens;
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(generateSuccessPage(safeTokens, state));
        } catch (err) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(generateLandingPage(baseUrl, `Failed to exchange code for token: ${err.message}`));
        }
        return;
      }

      // Token refresh endpoint
      if (req.method === 'POST' && url.pathname === '/auth/refresh') {
        let body = '';
        
        req.on('data', chunk => {
          body += chunk.toString();
        });
        
        req.on('end', async () => {
          try {
            // Parse request body
            if (!body) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Missing request body' }));
              return;
            }
            
            const data = JSON.parse(body);
            const refreshToken = data.refresh_token;
            
            if (!refreshToken) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Missing refresh_token in request body' }));
              return;
            }
            
            // Use server's client credentials to refresh the token
            const oauth2Client = new google.auth.OAuth2(client_id, client_secret);
            oauth2Client.setCredentials({ refresh_token: refreshToken });
            
            const { credentials: newCredentials } = await oauth2Client.refreshAccessToken();
            
            // Return new access token
            const response = {
              token: newCredentials.access_token,
              expiry: newCredentials.expiry_date ? new Date(newCredentials.expiry_date).toISOString() : null,
            };
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(response));
          } catch (err) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: `Failed to refresh token: ${err.message}` }));
          }
        });
        
        return;
      }

      // Health check endpoint
      if (url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
        return;
      }

      // 404 for everything else
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');

    } catch (err) {
      console.error('Server error:', err);
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal Server Error');
    }
  });

  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(port, () => {
      console.log(`\n🚀 gdrive token server running at http://localhost:${port}\n`);
      console.log('Share this URL with users who need to authenticate.');
      console.log('Press Ctrl+C to stop the server.\n');
      resolve();
    });
  });
}

// Login command
program
  .command('login')
  .description('Authenticate with Google and save the OAuth token')
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .option('-t, --token-path <path>', `Path to save/load OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .option('--token-server <url>', `URL of token server to fetch OAuth token from. Can also be set via ${TOKEN_SERVER_ENV_VAR} env var`)
  .option('-f, --force', 'Force re-authentication even if a valid token exists')
  .action(async (options) => {
    try {
      // If token-server is provided (via CLI or env var), fetch token from server
      const serverUrl = getTokenServer(options.tokenServer);
      if (serverUrl) {
        await fetchTokenFromServer(serverUrl, options.tokenPath);
        console.log('Authentication successful via token server.');
        return;
      }

      // Check for existing valid token
      if (!options.force) {
        const existingToken = loadToken(options.tokenPath);
        if (existingToken) {
          // Check if token is expired
          if (!existingToken.expiry_date || Date.now() < existingToken.expiry_date) {
            console.log('Already authenticated. Use --force to re-authenticate.');
            if (existingToken.account_email) {
              console.log(`Logged in as: ${existingToken.account_email}`);
            }
            return;
          }

          // Try to refresh expired token
          if (existingToken.refresh_token) {
            try {
              // Load credentials to get client info
              const credentialsJson = process.env[CREDENTIALS_ENV_VAR];
              let credentials;
              if (credentialsJson) {
                credentials = JSON.parse(credentialsJson);
              } else {
                const credPath = options.credentialsFpath || 'service_account.json';
                if (fs.existsSync(credPath)) {
                  credentials = JSON.parse(fs.readFileSync(credPath, 'utf8'));
                }
              }

              const clientConfig = credentials && getOAuthClientConfig(credentials);
              if (clientConfig) {
                const { client_id, client_secret } = clientConfig;
                const oauth2Client = new google.auth.OAuth2(client_id, client_secret);
                oauth2Client.setCredentials(existingToken);
                const { credentials: newCredentials } = await oauth2Client.refreshAccessToken();
                // Preserve account email from existing token
                saveToken(newCredentials, options.tokenPath, existingToken.account_email);
                console.log('Token refreshed successfully.');
                if (existingToken.account_email) {
                  console.log(`Logged in as: ${existingToken.account_email}`);
                }
                return;
              }
            } catch {
              // Fall through to new OAuth flow
            }
          }
        }
      }

      // Run OAuth flow
      await getCredentials(options.credentialsFpath, options.tokenPath);
      const tokenPath = options.tokenPath || DEFAULT_TOKEN_PATH;
      const savedToken = loadToken(tokenPath);
      console.log(`Authentication successful. Token saved to ${tokenPath}`);
      if (savedToken?.account_email) {
        console.log(`Logged in as: ${savedToken.account_email}`);
      }
    } catch (error) {
      console.error('Authentication failed:', error.message);
      process.exit(1);
    }
  });

// Whoami command
program
  .command('whoami')
  .description('Show the currently authenticated Google account')
  .option('-t, --token-path <path>', `Path to OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .action(async (options) => {
    try {
      const tokenData = loadToken(options.tokenPath);
      if (!tokenData) {
        console.log('Not logged in. Run "gdrive login" to authenticate.');
        process.exit(1);
      }

      // If we have a stored email, display it
      if (tokenData.account_email) {
        console.log(tokenData.account_email);
        return;
      }

      // Otherwise, try to fetch it from the API
      if (tokenData.access_token || tokenData.token) {
        const accessToken = tokenData.access_token || tokenData.token;
        const email = await fetchUserEmail(accessToken);
        if (email) {
          // Update the token file with the email
          saveToken(tokenData, options.tokenPath, email);
          console.log(email);
          return;
        }
      }

      console.log('Logged in (email not available)');
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Server command
program
  .command('server')
  .description('Start an OAuth token server for users without their own credentials')
  .option('-p, --port <port>', `Port to listen on (default: ${DEFAULT_SERVER_PORT})`, DEFAULT_SERVER_PORT.toString())
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .action(async (options) => {
    try {
      await startTokenServer(parseInt(options.port, 10), options.credentialsFpath);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program.parse();

// Export functions for programmatic use
export {
  uploadFile,
  exportFile,
  shareFile,
  pullAll,
  pushAll,
  getCredentials,
  loadToken,
  saveToken,
  loadMapping,
  saveMapping,
  findMappingFile,
  getMappingPath,
  createFileRecord,
  createFilesMapping,
  getAbsolutePath,
  promptConfirmation,
  getUpstreamModifiedTime,
  resolveMimetype,
  startTokenServer,
  fetchTokenFromServer,
  refreshTokenFromServer,
  refreshTokenViaServer,
  SCOPES,
  MIME_TYPES,
  EXPORT_MIME_TYPES,
  TEXT_FORMATS,
  CREDENTIALS_ENV_VAR,
  TOKEN_ENV_VAR,
  DEFAULT_TOKEN_PATH,
  DEFAULT_MAPPING_PATH,
  DEFAULT_SERVER_PORT,
};
