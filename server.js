const express = require('express');
const fs      = require('fs');
const path    = require('path');
const https   = require('https');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 8000;

// ─── Storage paths ────────────────────────────────────────────────────────────
// Prefer a Railway volume (or STORAGE_DIR / STORAGE_PATH). App-local ./storage is
// wiped on every redeploy — that is why SaaS cards can disappear after deploy.
function resolveStorageDir() {
  if (process.env.STORAGE_DIR) return process.env.STORAGE_DIR;
  if (process.env.STORAGE_PATH) return path.dirname(process.env.STORAGE_PATH);
  if (process.env.RAILWAY_VOLUME_MOUNT_PATH) return process.env.RAILWAY_VOLUME_MOUNT_PATH;
  for (const candidate of ['/storage', '/data']) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch (_) { /* ignore */ }
  }
  return path.join(__dirname, 'storage');
}

const storageDir = resolveStorageDir();
const storageIsEphemeral = path.resolve(storageDir).startsWith(path.resolve(__dirname));

if (!fs.existsSync(storageDir)) {
  fs.mkdirSync(storageDir, { recursive: true });
}

const storageFile  = path.join(storageDir, 'vault.json');
const slotsFile    = path.join(storageDir, 'slots.json');
const accountsFile = path.join(storageDir, 'accounts_meta.json'); // stores email+password per accountId
const saasFile     = path.join(storageDir, 'saas.json');         // SaaS subscription cards
const saasImagesDir = path.join(storageDir, 'saas-images');      // SaaS guide images (persistent volume)

// ─── Config ───────────────────────────────────────────────────────────────────
const ADMIN_PASSWORD  = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  console.error('FATAL: ADMIN_PASSWORD environment variable is not set.');
  process.exit(1);
}
const MAX_SLOTS       = 3;
const WA_SESSION_ID   = 'eternalgy-auth';

// ─── File helpers ─────────────────────────────────────────────────────────────
function readJSON(file, fallback = {}) {
  if (!fs.existsSync(file)) return fallback;
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return fallback; }
}

function writeJSON(file, data) {
  const dir = path.dirname(file);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}

const readSlots        = () => readJSON(slotsFile, {});
const writeSlots       = (d) => writeJSON(slotsFile, d);
const readAccountsMeta = () => readJSON(accountsFile, {});
const writeAccountsMeta= (d) => writeJSON(accountsFile, d);
const withImageDefaults = (c) => ({
  ...c,
  loginImages: Array.isArray(c.loginImages) ? c.loginImages : [],
  billImages:  Array.isArray(c.billImages)  ? c.billImages  : [],
  billGuide:   typeof c.billGuide === 'string' ? c.billGuide : ''
});
const readSaas          = () => {
  const list = readJSON(saasFile, []);
  return Array.isArray(list) ? list.map(withImageDefaults) : list;
};
const writeSaas         = (d) => writeJSON(saasFile, d);

function normalizeSaasCard(body, existing = null) {
  const name = (body.name || '').trim();
  if (!name) return { error: 'SaaS name is required.' };
  return {
    id: existing?.id || crypto.randomUUID(),
    name,
    url: (body.url || '').trim(),
    description: (body.description || '').trim(),
    username: (body.username || '').trim(),
    credential: (body.credential || '').trim(),
    accessGuide: (body.accessGuide || '').trim(),
    billGuide: (body.billGuide || '').trim(),
    // Images are managed only via the /images endpoints; edits never wipe them.
    loginImages: Array.isArray(existing?.loginImages) ? existing.loginImages : [],
    billImages: Array.isArray(existing?.billImages) ? existing.billImages : [],
    createdAt: existing?.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
}

// ─── Health check (public) ───────────────────────────────────────────────────
app.get('/health', (req, res) => {
  let writable = false;
  let saasReadable = false;
  let saasCount = 0;
  let error = null;
  try {
    const probe = path.join(storageDir, '.healthwrite');
    fs.writeFileSync(probe, String(Date.now()), 'utf8');
    fs.unlinkSync(probe);
    writable = true;
  } catch (e) {
    error = e.message;
  }
  try {
    const list = readSaas();
    saasReadable = true;
    saasCount = Array.isArray(list) ? list.length : 0;
  } catch (e) {
    error = error || e.message;
  }
  const ready = Boolean(writable && !storageIsEphemeral);
  const body = {
    status: ready ? 'ok' : 'degraded',
    ready,
    ephemeral: storageIsEphemeral,
    storageDir,
    writable,
    saasReadable,
    saasCount,
    uptimeSec: Math.round(process.uptime()),
    ...(error ? { error } : {})
  };
  return res.status(ready ? 200 : 503).json(body);
});



// ─── Vault decryption (mirrors Web Crypto logic in app.js) ───────────────────
// Layout: 16 bytes salt | 12 bytes IV | ciphertext (AES-256-GCM)
function decryptVault(encryptedBase64, password) {
  try {
    const combined = Buffer.from(encryptedBase64, 'base64');
    const salt       = combined.slice(0, 16);
    const iv         = combined.slice(16, 28);
    const ciphertext = combined.slice(28);

    // Derive key: PBKDF2-SHA256, 100000 iterations, 32 bytes
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');

    // AES-256-GCM: last 16 bytes of ciphertext are the auth tag
    const authTag    = ciphertext.slice(ciphertext.length - 16);
    const encrypted  = ciphertext.slice(0, ciphertext.length - 16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
  } catch (e) {
    return null;
  }
}

// ─── Helper: get plain accounts (handles both plain and encrypted vault) ──────
function getPlainAccounts(adminPw) {
  const vault = readJSON(storageFile, {});
  if (vault.plainAccounts) return vault.plainAccounts;
  if (vault.encryptedData) return decryptVault(vault.encryptedData, adminPw) || [];
  return [];
}


// Accepts: 0123456789 / 60123456789 / +60123456789
// Returns: 60123456789  (no + prefix, digits only — Baileys format)
function normaliseMY(raw) {
  let digits = raw.replace(/\D/g, '');           // strip everything non-digit
  if (digits.startsWith('60')) return digits;    // already has country code
  if (digits.startsWith('0'))  return '6' + digits; // 0xx → 60xx
  // bare 8-9 digit number (no leading 0, no country code) → prepend 60
  return '60' + digits;
}

// Validate after normalisation: 60 + 8–10 digits (covers 010–019 prefixes)
function isValidMYNumber(normalised) {
  return /^60\d{8,10}$/.test(normalised);
}

// ─── WhatsApp sender ──────────────────────────────────────────────────────────
function sendWhatsApp(to, text) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ sessionId: WA_SESSION_ID, to, text });
    const options = {
      hostname: 'ee-baileys-production.up.railway.app',
      path: '/messages/send',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { resolve({ raw: data }); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── SaaS image helpers ──────────────────────────────────────────────────────
const IMAGE_MIME_EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif' };
const IMAGE_EXT_MIME = { '.jpg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.gif': 'image/gif' };
const IMAGE_FILE_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(jpg|png|webp|gif)$/;
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

function sniffImageMime(buf) {
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.length >= 8 && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buf.length >= 6 && /^GIF8[79]a$/.test(buf.slice(0, 6).toString('latin1'))) return 'image/gif';
  if (buf.length >= 12 && buf.slice(0, 4).toString('latin1') === 'RIFF' && buf.slice(8, 12).toString('latin1') === 'WEBP') return 'image/webp';
  return null;
}

// Returns { buffer, mime, ext } or { error, status }
function parseImageDataUrl(dataUrl) {
  if (typeof dataUrl !== 'string') return { error: 'dataUrl is required.', status: 400 };
  const m = /^data:(image\/(?:jpeg|png|webp|gif));base64,([A-Za-z0-9+/=\s]+)$/.exec(dataUrl);
  if (!m) return { error: 'Only jpg, png, webp or gif data URLs are allowed.', status: 400 };
  const buffer = Buffer.from(m[2], 'base64');
  if (!buffer.length) return { error: 'Empty image.', status: 400 };
  if (buffer.length > MAX_IMAGE_BYTES) return { error: 'Image too large (max 8MB).', status: 413 };
  if (sniffImageMime(buffer) !== m[1]) return { error: 'Image content does not match its type.', status: 400 };
  return { buffer, mime: m[1], ext: IMAGE_MIME_EXT[m[1]] };
}

function removeImageFile(file) {
  if (typeof file !== 'string' || !IMAGE_FILE_RE.test(file)) return;
  try { fs.unlinkSync(path.join(saasImagesDir, file)); } catch (_) { /* already gone */ }
}

function cleanImageName(name, fallback) {
  const n = String(name || '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 120);
  return n || fallback;
}

// ─── Middleware ───────────────────────────────────────────────────────────────
// Only the image-upload route gets the larger JSON limit (8MB image ≈ 10.7MB base64).
// Auth is checked before the big body is parsed.
const jsonDefault = express.json();
const jsonUpload  = express.json({ limit: '12mb' });
app.use((req, res, next) => {
  if (req.method === 'POST' && /^\/api\/saas\/[^/]+\/images\/?$/.test(req.path)) {
    if (req.headers['x-admin-password'] !== ADMIN_PASSWORD)
      return res.status(401).json({ error: 'Unauthorized.' });
    return jsonUpload(req, res, next);
  }
  return jsonDefault(req, res, next);
});
app.use(express.static(__dirname));

// ─── Admin middleware ─────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.headers['x-admin-password'] !== ADMIN_PASSWORD)
    return res.status(401).json({ error: 'Unauthorized.' });
  next();
}

// ─── Vault API (shared plain vault; same ADMIN_PASSWORD as /admin and /saas) ──
app.get('/api/vault', requireAdmin, (req, res) => {
  try {
    const vault = readJSON(storageFile, {});
    // Migrate legacy encrypted vault → plain shared accounts
    if (vault.encryptedData) {
      const accounts = decryptVault(vault.encryptedData, ADMIN_PASSWORD);
      if (accounts) {
        writeJSON(storageFile, { plainAccounts: accounts, encryptedData: null });
        return res.json({ plainAccounts: accounts });
      }
      return res.status(500).json({ error: 'Failed to decrypt vault.' });
    }
    const accounts = Array.isArray(vault.plainAccounts) ? vault.plainAccounts : [];
    return res.json({ plainAccounts: accounts });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to read vault.' });
  }
});

app.post('/api/vault', requireAdmin, (req, res) => {
  try {
    const plainAccounts = req.body && req.body.plainAccounts;
    if (!Array.isArray(plainAccounts))
      return res.status(400).json({ error: 'Invalid payload structure.' });
    writeJSON(storageFile, { plainAccounts, encryptedData: null });
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to write vault.' });
  }
});

// ─── Account meta API (email + login password per account) ───────────────────

// GET /api/accounts-meta  — admin only, returns full meta
app.get('/api/accounts-meta', requireAdmin, (req, res) => {
  return res.json(readAccountsMeta());
});

// POST /api/accounts-meta  — admin sets/updates login info for an account
// Body: { accountId, loginEmail, loginPassword }
app.post('/api/accounts-meta', requireAdmin, (req, res) => {
  const { accountId, loginEmail, loginPassword } = req.body;
  if (!accountId) return res.status(400).json({ error: 'accountId required.' });
  const meta = readAccountsMeta();
  meta[accountId] = { loginEmail: loginEmail || '', loginPassword: loginPassword || '' };
  writeAccountsMeta(meta);
  return res.json({ success: true });
});

// ─── Slots API ────────────────────────────────────────────────────────────────

// GET /api/slots  — public slot counts (no personal data exposed)
app.get('/api/slots', (req, res) => {
  // Return only counts per account, not the actual WA numbers
  const slots = readSlots();
  const safe = {};
  for (const [id, list] of Object.entries(slots)) {
    safe[id] = list.length;
  }
  return res.json(safe);
});

// POST /api/slots/claim
// Body: { accountId, whatsapp }
// Server sends WA message with login info, then records the claim.
app.post('/api/slots/claim', async (req, res) => {
  const { accountId, whatsapp } = req.body;
  if (!accountId || !whatsapp) {
    return res.status(400).json({ error: 'accountId and whatsapp are required.' });
  }

  const wa = normaliseMY(whatsapp);
  if (!isValidMYNumber(wa)) {
    return res.status(400).json({ error: 'Invalid Malaysian phone number. Example: 0123456789' });
  }

  const slots = readSlots();
  if (!slots[accountId]) slots[accountId] = [];

  // One number = one account max
  for (const [aid, list] of Object.entries(slots)) {
    if (list.some(s => s.whatsapp === wa)) {
      return res.status(409).json({ error: 'This number has already claimed an account.' });
    }
  }

  // Check capacity
  if (slots[accountId].length >= MAX_SLOTS) {
    return res.status(409).json({ error: `All ${MAX_SLOTS} slots for this account are taken.` });
  }

  // Get login info for this account
  const meta = readAccountsMeta();
  const info = meta[accountId];
  if (!info || !info.loginEmail || !info.loginPassword) {
    return res.status(503).json({ error: 'Login info not configured for this account yet. Contact admin.' });
  }

  // Send WhatsApp message
  const message =
    `✅ *Eternalgy Digital Asset — Slot Claimed*\n\n` +
    `You have successfully claimed access to a Google account.\n\n` +
    `📧 *Email:* ${info.loginEmail}\n` +
    `🔑 *Password:* ${info.loginPassword}\n\n` +
    `📱 *How to use:*\n` +
    `1. Download *Gemini* app on your phone\n` +
    `2. Sign in with the email & password above\n` +
    `3. When asked for 2FA, use the OTP code from the Eternalgy Digital Asset vault\n\n` +
    `⚠️ Do not share this message. Your number is registered to this slot.`;

  try {
    await sendWhatsApp(wa, message);
  } catch (e) {
    console.error('WA send failed:', e);
    // Still record the claim even if WA fails — don't block the user
  }

  // Record claim
  slots[accountId].push({ whatsapp: wa, claimedAt: new Date().toISOString() });
  writeSlots(slots);

  return res.json({ success: true, slotsUsed: slots[accountId].length, maxSlots: MAX_SLOTS });
});

// DELETE /api/slots/unclaim
// Body: { accountId, whatsapp }
app.delete('/api/slots/unclaim', (req, res) => {
  const { accountId, whatsapp } = req.body;
  if (!accountId || !whatsapp) return res.status(400).json({ error: 'accountId and whatsapp are required.' });

  const wa = normaliseMY(whatsapp);
  const slots = readSlots();
  if (!slots[accountId]) return res.status(404).json({ error: 'No slots found for this account.' });

  const before = slots[accountId].length;
  slots[accountId] = slots[accountId].filter(s => s.whatsapp !== wa);

  if (slots[accountId].length === before)
    return res.status(404).json({ error: 'Slot not found for this number.' });

  writeSlots(slots);
  return res.json({ success: true });
});

// ─── Admin API ────────────────────────────────────────────────────────────────

// GET /api/admin/slots  — full slot list with WA numbers
app.get('/api/admin/slots', requireAdmin, (req, res) => {
  return res.json(readSlots());
});

// GET /api/admin/accounts  — returns plain accounts (decrypts if needed)
app.get('/api/admin/accounts', requireAdmin, (req, res) => {
  const accounts = getPlainAccounts(req.headers['x-admin-password']);
  return res.json(accounts);
});

// DELETE /api/admin/slots/revoke
// Body: { accountId, whatsapp }
app.delete('/api/admin/slots/revoke', requireAdmin, (req, res) => {
  const { accountId, whatsapp } = req.body;
  if (!accountId || !whatsapp) return res.status(400).json({ error: 'accountId and whatsapp are required.' });

  const slots = readSlots();
  if (!slots[accountId]) return res.status(404).json({ error: 'Account not found.' });

  const before = slots[accountId].length;
  slots[accountId] = slots[accountId].filter(s => s.whatsapp !== whatsapp);

  if (slots[accountId].length === before) return res.status(404).json({ error: 'Slot not found.' });

  writeSlots(slots);
  return res.json({ success: true });
});

// DELETE /api/admin/slots/clear/:accountId
app.delete('/api/admin/slots/clear/:accountId', requireAdmin, (req, res) => {
  const slots = readSlots();
  slots[req.params.accountId] = [];
  writeSlots(slots);
  return res.json({ success: true });
});


// ─── Storage status (admin only) ─────────────────────────────────────────────
app.get('/api/storage-status', requireAdmin, (req, res) => {
  let saasCount = 0;
  try {
    const list = readSaas();
    saasCount = Array.isArray(list) ? list.length : 0;
  } catch (_) {}
  return res.json({
    storageDir,
    ephemeral: storageIsEphemeral,
    saasFile,
    saasCount,
    vaultExists: fs.existsSync(storageFile),
    saasExists: fs.existsSync(saasFile),
    hint: storageIsEphemeral
      ? 'Storage is inside the app image and is wiped on redeploy. On Railway: add a Volume, mount it (e.g. /storage), and set STORAGE_DIR=/storage (or STORAGE_PATH=/storage/vault.json).'
      : 'Storage is on a mounted/persistent path.'
  });
});

// ─── SaaS subscription cards API (admin only) ────────────────────────────────

app.get('/api/saas', requireAdmin, (req, res) => {
  return res.json(readSaas());
});

app.post('/api/saas', requireAdmin, (req, res) => {
  const card = normalizeSaasCard(req.body);
  if (card.error) return res.status(400).json({ error: card.error });
  const list = readSaas();
  list.push(card);
  writeSaas(list);
  return res.json(card);
});

app.put('/api/saas/:id', requireAdmin, (req, res) => {
  const list = readSaas();
  const idx = list.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Card not found.' });
  const card = normalizeSaasCard(req.body, list[idx]);
  if (card.error) return res.status(400).json({ error: card.error });
  list[idx] = card;
  writeSaas(list);
  return res.json(card);
});

app.delete('/api/saas/:id', requireAdmin, (req, res) => {
  const list = readSaas();
  const removed = list.find(c => c.id === req.params.id);
  const next = list.filter(c => c.id !== req.params.id);
  if (next.length === list.length) return res.status(404).json({ error: 'Card not found.' });
  writeSaas(next);
  for (const img of [...(removed.loginImages || []), ...(removed.billImages || [])]) removeImageFile(img && img.file);
  return res.json({ success: true });
});

// POST /api/saas/:id/images  { kind: 'login'|'bill', name, dataUrl }
app.post('/api/saas/:id/images', requireAdmin, (req, res) => {
  const { kind, name, dataUrl } = req.body || {};
  if (kind !== 'login' && kind !== 'bill')
    return res.status(400).json({ error: "kind must be 'login' or 'bill'." });
  const list = readSaas();
  const idx = list.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Card not found.' });
  const img = parseImageDataUrl(dataUrl);
  if (img.error) return res.status(img.status).json({ error: img.error });

  const file = crypto.randomUUID() + img.ext;
  try {
    fs.mkdirSync(saasImagesDir, { recursive: true });
    fs.writeFileSync(path.join(saasImagesDir, file), img.buffer);
  } catch (e) {
    return res.status(500).json({ error: 'Failed to store image.' });
  }
  const field = kind === 'login' ? 'loginImages' : 'billImages';
  list[idx][field].push({ file, name: cleanImageName(name, file) });
  list[idx].updatedAt = new Date().toISOString();
  writeSaas(list);
  return res.json(list[idx]);
});

// DELETE /api/saas/:id/images/:file?kind=login|bill
app.delete('/api/saas/:id/images/:file', requireAdmin, (req, res) => {
  const kind = req.query.kind;
  if (kind !== 'login' && kind !== 'bill')
    return res.status(400).json({ error: "kind must be 'login' or 'bill'." });
  const list = readSaas();
  const idx = list.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Card not found.' });
  const field = kind === 'login' ? 'loginImages' : 'billImages';
  const before = list[idx][field].length;
  list[idx][field] = list[idx][field].filter(i => i.file !== req.params.file);
  if (list[idx][field].length === before) return res.status(404).json({ error: 'Image not found.' });
  list[idx].updatedAt = new Date().toISOString();
  writeSaas(list);
  removeImageFile(req.params.file);
  return res.json(list[idx]);
});

// GET /api/saas-images/:file  (admin header required)
app.get('/api/saas-images/:file', requireAdmin, (req, res) => {
  const file = req.params.file;
  if (!IMAGE_FILE_RE.test(file)) return res.status(400).json({ error: 'Invalid file name.' });
  const full = path.join(saasImagesDir, file);
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'Image not found.' });
  res.setHeader('Content-Type', IMAGE_EXT_MIME[path.extname(file)]);
  res.setHeader('Cache-Control', 'private, max-age=3600');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  return fs.createReadStream(full).on('error', () => res.destroy()).pipe(res);
});

// ─── Page routes ─────────────────────────────────────────────────────────────
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/learn', (req, res) => {
  res.sendFile(path.join(__dirname, 'learn.html'));
});

app.get('/saas', (req, res) => {
  res.sendFile(path.join(__dirname, 'saas.html'));
});

// Body-parser errors (e.g. oversize upload) → JSON instead of an HTML stack trace
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large.' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON.' });
  return next(err);
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Eternalgy Digital Asset Server running on port ${PORT}`);
  console.log(`Storage dir:   ${storageDir}${storageIsEphemeral ? '  ⚠ EPHEMERAL (wiped on redeploy)' : '  ✓ persistent path'}`);
  console.log(`Vault:         ${storageFile}`);
  console.log(`Slots:         ${slotsFile}`);
  console.log(`Accounts meta: ${accountsFile}`);
  console.log(`SaaS cards:    ${saasFile}`);
  if (storageIsEphemeral) {
    console.warn('WARNING: No persistent volume detected. SaaS cards, slots, and vault files will be lost on redeploy.');
    console.warn('Set STORAGE_DIR to your Railway volume mount path (example: /storage).');
  }
});
