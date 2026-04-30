'use strict';

const { app, BrowserWindow, ipcMain, safeStorage } = require('electron');
const path   = require('path');
const fs     = require('fs');
const http   = require('http');
const crypto = require('crypto');

// ── File store ────────────────────────────────────────────────────────────────
function credsPath() { return path.join(app.getPath('userData'), 'credentials.json'); }
function tokenPath()  { return path.join(app.getPath('userData'), 'token.json'); }

function readJSON(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}
function writeJSON(p, obj) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj), 'utf8');
}

// ── Encryption helpers ────────────────────────────────────────────────────────
function enc(s) {
  return safeStorage.isEncryptionAvailable()
    ? safeStorage.encryptString(s).toString('base64')
    : s;
}
function dec(s) {
  return safeStorage.isEncryptionAvailable()
    ? safeStorage.decryptString(Buffer.from(s, 'base64'))
    : s;
}

// ── IPC: credentials ──────────────────────────────────────────────────────────
ipcMain.handle('get-credentials', () => {
  const raw = readJSON(credsPath());
  if (!raw) return null;
  try {
    return {
      apiKey:       dec(raw.apiKey),
      clientId:     dec(raw.clientId),
      clientSecret: raw.clientSecret ? dec(raw.clientSecret) : '',
    };
  } catch { return null; }
});

ipcMain.handle('save-credentials', (_e, { apiKey, clientId, clientSecret }) => {
  writeJSON(credsPath(), {
    apiKey:       enc(apiKey),
    clientId:     enc(clientId),
    clientSecret: enc(clientSecret || ''),
  });
});

// ── Token storage ─────────────────────────────────────────────────────────────
function saveTokens({ access_token, refresh_token, expires_in }) {
  const existing = readTokens();
  writeJSON(tokenPath(), {
    accessToken:  enc(access_token),
    refreshToken: enc(refresh_token || (existing && existing.refreshToken) || ''),
    expiresAt:    Date.now() + (expires_in || 3599) * 1000,
  });
}

function readTokens() {
  const raw = readJSON(tokenPath());
  if (!raw) return null;
  try {
    return {
      accessToken:  raw.accessToken  ? dec(raw.accessToken)  : null,
      refreshToken: raw.refreshToken ? dec(raw.refreshToken) : null,
      expiresAt:    raw.expiresAt    || 0,
    };
  } catch { return null; }
}

ipcMain.handle('sign-out', () => {
  try { fs.unlinkSync(tokenPath()); } catch { /* already gone */ }
});

// ── IPC: get-access-token ─────────────────────────────────────────────────────
ipcMain.handle('get-access-token', async (_e, clientId) => {
  console.log('[gtd] get-access-token called, clientId:', clientId ? clientId.slice(0, 20) + '…' : '(empty)');
  if (!clientId) return { error: 'No Client ID configured — enter it in Settings' };

  const creds = (() => { try { return readJSON(credsPath()); } catch { return null; } })();
  const clientSecret = (creds?.clientSecret ? dec(creds.clientSecret) : '') || '';
  console.log('[gtd] clientSecret present:', !!clientSecret);

  const stored = readTokens();

  // Return cached access token if still valid (1-min safety buffer)
  if (stored?.accessToken && stored.expiresAt > Date.now() + 60_000) {
    console.log('[gtd] returning cached token');
    return { token: stored.accessToken };
  }

  // Silently refresh using stored refresh token
  if (stored?.refreshToken) {
    console.log('[gtd] attempting silent refresh');
    try {
      const refreshParams = { grant_type: 'refresh_token', refresh_token: stored.refreshToken, client_id: clientId };
      if (clientSecret) refreshParams.client_secret = clientSecret;
      const data = await tokenRequest(refreshParams);
      if (data.access_token) {
        saveTokens(data);
        console.log('[gtd] silent refresh succeeded');
        return { token: data.access_token };
      }
    } catch (e) {
      console.log('[gtd] silent refresh failed:', e.message);
    }
  }

  // Full OAuth flow (Authorization Code + PKCE)
  console.log('[gtd] starting full OAuth flow');
  try {
    const tokens = await doOAuthFlow(clientId, clientSecret);
    console.log('[gtd] OAuth flow succeeded');
    return { token: tokens.access_token };
  } catch (e) {
    console.log('[gtd] OAuth flow failed:', e.message);
    return { error: e.message };
  }
});

// ── PKCE helpers ──────────────────────────────────────────────────────────────
function pkce() {
  const verifier  = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// ── Token endpoint request ────────────────────────────────────────────────────
async function tokenRequest(params) {
  const body = new URLSearchParams(params);
  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const data = await resp.json();
  if (data.error) throw new Error(data.error_description || data.error);
  return data;
}

// ── OAuth Authorization Code + PKCE flow ──────────────────────────────────────
// Uses a loopback HTTP server on a random port. Requires a Desktop app type
// OAuth 2.0 Client ID — Desktop app clients allow any loopback port without
// pre-registering redirect URIs.
function doOAuthFlow(clientId, clientSecret) {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.on('error', reject);

    const { verifier, challenge } = pkce();

    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const redirectUri = `http://127.0.0.1:${port}/oauth2callback`;

      const authUrl =
        'https://accounts.google.com/o/oauth2/v2/auth' +
        '?response_type=code' +
        '&code_challenge_method=S256' +
        '&code_challenge=' + challenge +
        '&access_type=offline' +
        '&prompt=consent' +
        '&scope=' + encodeURIComponent('https://www.googleapis.com/auth/spreadsheets') +
        '&client_id=' + encodeURIComponent(clientId) +
        '&redirect_uri=' + encodeURIComponent(redirectUri);

      let settled = false;
      let authWin;

      function done(result, err) {
        if (settled) return;
        settled = true;
        try { server.close(); } catch { /* ignore */ }
        try { if (authWin && !authWin.isDestroyed()) authWin.destroy(); } catch { /* ignore */ }
        if (result) resolve(result);
        else reject(err || new Error('Auth failed'));
      }

      server.on('request', async (req, res) => {
        if (!req.url.startsWith('/oauth2callback')) { res.writeHead(404); res.end(); return; }

        const url    = new URL(req.url, redirectUri);
        const code   = url.searchParams.get('code');
        const errMsg = url.searchParams.get('error');

        if (errMsg) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`<p style="font-family:sans-serif;padding:1.5rem;color:red">Sign-in error: ${errMsg}</p>`);
          done(null, new Error(errMsg));
          return;
        }

        if (!code) { res.writeHead(400); res.end(); return; }

        // Respond to the browser while token exchange runs in the background.
        // Don't tell user to close — the window closes automatically on success.
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<p style="font-family:sans-serif;padding:1.5rem">Completing sign-in&hellip;</p>');

        // Exchange the code for tokens
        console.log('[gtd] exchanging auth code for tokens');
        try {
          const exchangeParams = {
            grant_type:    'authorization_code',
            code,
            code_verifier: verifier,
            client_id:     clientId,
            redirect_uri:  redirectUri,
          };
          if (clientSecret) exchangeParams.client_secret = clientSecret;
          const tokens = await tokenRequest(exchangeParams);
          console.log('[gtd] token exchange succeeded, has refresh_token:', !!tokens.refresh_token);
          saveTokens(tokens);
          done(tokens);
        } catch (e) {
          console.log('[gtd] token exchange failed:', e.message);
          done(null, e);
        }
      });

      authWin = new BrowserWindow({
        width: 500,
        height: 650,
        webPreferences: { nodeIntegration: false, contextIsolation: true },
        autoHideMenuBar: true,
        title: 'Sign in to Google',
      });
      authWin.loadURL(authUrl);
      authWin.on('closed', () => done(null, new Error('Sign-in cancelled')));
    });
  });
}

// ── Main window ───────────────────────────────────────────────────────────────
let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 800,
    minWidth: 400,
    minHeight: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    title: 'GTD — Getting Things Done',
  });
  mainWindow.loadFile(path.join(__dirname, '..', 'index.html'));
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
