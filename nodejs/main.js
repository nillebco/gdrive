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
const DEFAULT_TOKEN_PATH = 'token.json';
const DEFAULT_MAPPING_PATH = 'files-mapping.json';
const DEFAULT_SERVER_PORT = 8080;

// Token server: in-memory store for pending OAuth sessions
const pendingSessions = new Map();

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
 * @returns {object} FileRecord object
 */
function createFileRecord(localPath, driveFileId, lastOperation = new Date(), sourceMimetype = null, destinationMimetype = null, exportFormat = null) {
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
      return JSON.parse(tokenJson);
    } catch {
      return null;
    }
  }

  // Try file
  const filePath = tokenPath || DEFAULT_TOKEN_PATH;
  if (fs.existsSync(filePath)) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(content);
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Save OAuth token to file for future use.
 * @param {object} tokens - Token data to save
 * @param {string|null} tokenPath - Optional path to save token
 */
function saveToken(tokens, tokenPath = null) {
  const filePath = tokenPath || DEFAULT_TOKEN_PATH;
  fs.writeFileSync(filePath, JSON.stringify(tokens, null, 2));
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
          saveToken(tokens, tokenPath);
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
 * Get OAuth credentials from client secret config.
 * @param {object} data - Client secret config
 * @param {string|null} tokenPath - Optional path to token file
 * @returns {Promise<google.auth.OAuth2>} Authenticated OAuth2 client
 */
async function getCredentialsClientSecretFromDict(data, tokenPath = null) {
  const { client_id, client_secret, redirect_uris } = data.installed || data.web;

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
          const { credentials } = await oauth2Client.refreshAccessToken();
          saveToken(credentials, tokenPath);
          return oauth2Client;
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
  if (data.installed || data.web) {
    return 'client_secret';
  }
  return 'service_account';
}

/**
 * Get credentials from a config object.
 * @param {object} data - Credentials config
 * @param {string|null} tokenPath - Optional path to token file
 * @returns {Promise<google.auth.OAuth2|google.auth.JWT>} Auth client
 */
async function getCredentialsFromDict(data, tokenPath = null) {
  const credentialsType = detectCredentialsType(data);

  if (credentialsType === 'service_account') {
    return getCredentialsServiceAccountFromDict(data);
  } else if (credentialsType === 'client_secret') {
    return getCredentialsClientSecretFromDict(data, tokenPath);
  } else {
    throw new Error(`Invalid credentials type: ${credentialsType}`);
  }
}

/**
 * Get credentials from file path or environment variable.
 * @param {string|null} fpath - Optional path to credentials file
 * @param {string|null} tokenPath - Optional path to token file
 * @returns {Promise<google.auth.OAuth2|google.auth.JWT>} Auth client
 */
async function getCredentials(fpath = null, tokenPath = null) {
  // First, check environment variable
  const credentialsJson = process.env[CREDENTIALS_ENV_VAR];
  if (credentialsJson) {
    return getCredentialsFromDict(JSON.parse(credentialsJson), tokenPath);
  }

  // Fall back to file path
  const filePath = fpath || 'service_account.json';

  if (!fs.existsSync(filePath)) {
    throw new Error(`Credentials file not found: ${filePath}`);
  }

  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  return getCredentialsFromDict(data, tokenPath);
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
 * @returns {Promise<object>} Uploaded file metadata
 */
async function uploadFile(fpath, sourceMimetype = null, destinationMimetype = null, credentialsFpath = null, tokenPath = null, mappingPath = null, overwrite = false) {
  const auth = await getCredentials(credentialsFpath, tokenPath);
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

    // Update existing file
    try {
      const response = await drive.files.update({
        fileId: existingRecord.drive_file_id,
        requestBody: fileMetadata,
        media,
        fields: 'id',
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
      });
      result = response.data;
      mapping.uploads[absPath] = createFileRecord(absPath, result.id, new Date(), mimeType, destinationMimetype);
      saveMapping(mapping, mappingPath);
    }
  } else {
    // Create new file
    const response = await drive.files.create({
      requestBody: fileMetadata,
      media,
      fields: 'id',
    });
    result = response.data;
    mapping.uploads[absPath] = createFileRecord(absPath, result.id, new Date(), mimeType, destinationMimetype);
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
 * @returns {Promise<string>} Output path
 */
async function exportFile(fileId, outputPath, exportFormat = 'md', credentialsFpath = null, tokenPath = null, mappingPath = null) {
  const auth = await getCredentials(credentialsFpath, tokenPath);
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
  mapping.exports[fileId] = createFileRecord(absOutputPath, fileId, new Date(), null, null, exportFormat);
  saveMapping(mapping, mappingPath);

  return outputPath;
}

/**
 * Re-export all documents that have been previously exported.
 * @param {string|null} credentialsFpath - Path to credentials file
 * @param {string|null} tokenPath - Path to token file
 * @param {string|null} mappingPath - Path to files mapping file
 * @returns {Promise<string[]>} Array of paths to re-exported files
 */
async function pullAll(credentialsFpath = null, tokenPath = null, mappingPath = null) {
  const mapping = loadMapping(mappingPath);
  
  if (!mapping.exports || Object.keys(mapping.exports).length === 0) {
    return [];
  }
  
  const auth = await getCredentials(credentialsFpath, tokenPath);
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
      console.error(`Warning: Failed to re-export ${outputPath}: ${error.message}`);
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
 * @returns {Promise<string[]>} Array of paths to re-uploaded files
 */
async function pushAll(credentialsFpath = null, tokenPath = null, mappingPath = null, overwrite = false) {
  const mapping = loadMapping(mappingPath);
  
  if (!mapping.uploads || Object.keys(mapping.uploads).length === 0) {
    return [];
  }
  
  const auth = await getCredentials(credentialsFpath, tokenPath);
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
 * @returns {Promise<object[]>} Array of created permission metadata
 */
async function shareFile(fpath, emails, role = 'reader', notify = true, credentialsFpath = null, tokenPath = null, mappingPath = null) {
  // Load mapping and resolve file path to Drive ID
  const mapping = loadMapping(mappingPath);
  const absPath = getAbsolutePath(fpath);
  
  const existingRecord = mapping.uploads[absPath];
  if (!existingRecord) {
    throw new Error(`File not found in mapping: ${fpath}\nMake sure the file has been uploaded first using the 'upload' command.`);
  }
  
  const fileId = existingRecord.drive_file_id;
  
  const auth = await getCredentials(credentialsFpath, tokenPath);
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
  .description('Upload a file to Google Drive')
  .argument('<fpath>', 'Path to the file to upload')
  .option('-s, --source-mimetype <type>', 'MIME type of the source file. Accepts short aliases: md, txt, pdf, docx, xlsx, csv, etc.')
  .option('-d, --destination-mimetype <type>', 'MIME type for the destination file in Drive. Accepts short aliases: gdoc, gsheet, gslide, gdraw')
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .option('-t, --token-path <path>', `Path to save/load OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .option('-m, --mapping-path <path>', `Path to files mapping JSON. Default: ${DEFAULT_MAPPING_PATH}`)
  .option('--overwrite', 'Skip upstream modification check and overwrite without prompting')
  .option('--token-server <url>', 'URL of token server to fetch OAuth token from')
  .action(async (fpath, options) => {
    try {
      // If token-server is provided, fetch token from server first
      if (options.tokenServer) {
        await fetchTokenFromServer(options.tokenServer, options.tokenPath);
      }
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
        options.overwrite || false
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
  .description('Export a Google Workspace document to a local file')
  .argument('<file-id>', 'The Google Drive file ID to export')
  .argument('<output-path>', 'Path where the exported file will be saved')
  .option('-f, --format <format>', `Export format. Supported: ${Object.keys(EXPORT_MIME_TYPES).join(', ')}`, 'md')
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .option('-t, --token-path <path>', `Path to save/load OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .option('-m, --mapping-path <path>', `Path to files mapping JSON. Default: ${DEFAULT_MAPPING_PATH}`)
  .option('--token-server <url>', 'URL of token server to fetch OAuth token from')
  .action(async (fileId, outputPath, options) => {
    try {
      // If token-server is provided, fetch token from server first
      if (options.tokenServer) {
        await fetchTokenFromServer(options.tokenServer, options.tokenPath);
      }
      const result = await exportFile(
        fileId,
        outputPath,
        options.format,
        options.credentialsFpath,
        options.tokenPath,
        options.mappingPath
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
  .option('--token-server <url>', 'URL of token server to fetch OAuth token from')
  .action(async (fpath, emails, options) => {
    try {
      // Validate role
      const validRoles = ['reader', 'writer', 'commenter'];
      if (!validRoles.includes(options.role)) {
        throw new Error(`Invalid role: ${options.role}. Must be one of: ${validRoles.join(', ')}`);
      }
      
      // If token-server is provided, fetch token from server first
      if (options.tokenServer) {
        await fetchTokenFromServer(options.tokenServer, options.tokenPath);
      }
      
      const permissions = await shareFile(
        fpath,
        emails,
        options.role,
        options.notify,
        options.credentialsFpath,
        options.tokenPath,
        options.mappingPath
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
  .option('--token-server <url>', 'URL of token server to fetch OAuth token from')
  .action(async (options) => {
    try {
      // If token-server is provided, fetch token from server first
      if (options.tokenServer) {
        await fetchTokenFromServer(options.tokenServer, options.tokenPath);
      }
      const results = await pullAll(
        options.credentialsFpath,
        options.tokenPath,
        options.mappingPath
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
  .option('--token-server <url>', 'URL of token server to fetch OAuth token from')
  .action(async (options) => {
    try {
      // If token-server is provided, fetch token from server first
      if (options.tokenServer) {
        await fetchTokenFromServer(options.tokenServer, options.tokenPath);
      }
      const results = await pushAll(
        options.credentialsFpath,
        options.tokenPath,
        options.mappingPath,
        options.overwrite || false
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
  }

  console.log(`Opening browser to authenticate via ${serverUrl}...`);
  
  // Generate a session ID for this CLI instance
  const sessionId = crypto.randomBytes(16).toString('hex');
  
  // Start a local server to receive the token
  return new Promise((resolve, reject) => {
    const localServer = http.createServer(async (req, res) => {
      try {
        const url = new URL(req.url, 'http://localhost');
        
        if (url.pathname === '/callback') {
          const tokenParam = url.searchParams.get('token');
          
          if (tokenParam) {
            const token = JSON.parse(decodeURIComponent(tokenParam));
            saveToken(token, tokenPath);
            
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`
              <html>
                <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                  <h1>✓ Token received!</h1>
                  <p>You can close this window and return to the terminal.</p>
                </body>
              </html>
            `);
            
            localServer.close();
            resolve();
          } else {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('No token received');
            localServer.close();
            reject(new Error('No token received from server'));
          }
        }
      } catch (error) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Error processing callback');
        localServer.close();
        reject(error);
      }
    });

    localServer.listen(0, async () => {
      const port = localServer.address().port;
      const callbackUrl = encodeURIComponent(`http://localhost:${port}/callback`);
      const authUrl = `${serverUrl}/auth/start?callback=${callbackUrl}&session=${sessionId}`;
      
      await open(authUrl);
    });

    // Timeout after 5 minutes
    setTimeout(() => {
      localServer.close();
      reject(new Error('Authentication timed out'));
    }, 5 * 60 * 1000);
  });
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

  const { client_id, client_secret } = credentials.installed || credentials.web;
  if (!client_id || !client_secret) {
    throw new Error('Invalid credentials: missing client_id or client_secret');
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${port}`);
    const baseUrl = `http://localhost:${port}`;

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
            // Redirect to CLI's local server with the token
            const tokenParam = encodeURIComponent(JSON.stringify(tokens));
            const callbackUrl = `${session.callback}?token=${tokenParam}`;
            pendingSessions.delete(state);
            
            res.writeHead(302, { Location: callbackUrl });
            res.end();
            return;
          }
          
          // No CLI callback, show the success page with token
          pendingSessions.delete(state);
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(generateSuccessPage(tokens, state));
        } catch (err) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(generateLandingPage(baseUrl, `Failed to exchange code for token: ${err.message}`));
        }
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
  .option('--token-server <url>', 'URL of token server to fetch OAuth token from')
  .option('-f, --force', 'Force re-authentication even if a valid token exists')
  .action(async (options) => {
    try {
      // If token-server is provided, fetch token from server
      if (options.tokenServer) {
        await fetchTokenFromServer(options.tokenServer, options.tokenPath);
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

              if (credentials && (credentials.installed || credentials.web)) {
                const { client_id, client_secret } = credentials.installed || credentials.web;
                const oauth2Client = new google.auth.OAuth2(client_id, client_secret);
                oauth2Client.setCredentials(existingToken);
                const { credentials: newCredentials } = await oauth2Client.refreshAccessToken();
                saveToken(newCredentials, options.tokenPath);
                console.log('Token refreshed successfully.');
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
      console.log(`Authentication successful. Token saved to ${tokenPath}`);
    } catch (error) {
      console.error('Authentication failed:', error.message);
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
