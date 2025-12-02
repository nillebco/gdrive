#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import http from 'http';
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

const MIME_TYPES = {
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  md: 'text/markdown',
  mdgdoc: 'application/vnd.google-apps.document',
};

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
 * @returns {object} FileRecord object
 */
function createFileRecord(localPath, driveFileId, lastOperation = new Date()) {
  return {
    local_path: localPath,
    drive_file_id: driveFileId,
    last_operation: lastOperation.toISOString(),
  };
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
 * Load the files mapping from disk.
 * @param {string|null} mappingPath - Optional path to mapping file
 * @returns {object} FilesMapping object
 */
function loadMapping(mappingPath = null) {
  const filePath = mappingPath || DEFAULT_MAPPING_PATH;
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
 * Save the files mapping to disk.
 * @param {object} mapping - FilesMapping object
 * @param {string|null} mappingPath - Optional path to save mapping
 */
function saveMapping(mapping, mappingPath = null) {
  const filePath = mappingPath || DEFAULT_MAPPING_PATH;
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
      // Update timestamp
      existingRecord.last_operation = new Date().toISOString();
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
      mapping.uploads[absPath] = createFileRecord(absPath, result.id);
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
    mapping.uploads[absPath] = createFileRecord(absPath, result.id);
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
  mapping.exports[fileId] = createFileRecord(absOutputPath, fileId);
  saveMapping(mapping, mappingPath);

  return outputPath;
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
  .option('--source-mimetype <type>', 'MIME type of the source file')
  .option('--destination-mimetype <type>', 'MIME type for the destination file in Drive')
  .option('-c, --credentials-fpath <path>', `Path to credentials JSON file. Can also be set via ${CREDENTIALS_ENV_VAR} env var`)
  .option('-t, --token-path <path>', `Path to save/load OAuth token. Can also be set via ${TOKEN_ENV_VAR} env var. Default: ${DEFAULT_TOKEN_PATH}`)
  .option('-m, --mapping-path <path>', `Path to files mapping JSON. Default: ${DEFAULT_MAPPING_PATH}`)
  .option('--overwrite', 'Skip upstream modification check and overwrite without prompting')
  .action(async (fpath, options) => {
    try {
      const file = await uploadFile(
        fpath,
        options.sourceMimetype,
        options.destinationMimetype,
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
  .action(async (fileId, outputPath, options) => {
    try {
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

program.parse();

// Export functions for programmatic use
export {
  uploadFile,
  exportFile,
  getCredentials,
  loadToken,
  saveToken,
  loadMapping,
  saveMapping,
  createFileRecord,
  createFilesMapping,
  getAbsolutePath,
  promptConfirmation,
  getUpstreamModifiedTime,
  SCOPES,
  MIME_TYPES,
  EXPORT_MIME_TYPES,
  TEXT_FORMATS,
  CREDENTIALS_ENV_VAR,
  TOKEN_ENV_VAR,
  DEFAULT_TOKEN_PATH,
  DEFAULT_MAPPING_PATH,
};
