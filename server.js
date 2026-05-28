const express = require('express');
const fs      = require('fs');
const path    = require('path');
const https   = require('https');

const app  = express();
const PORT = process.env.PORT || 8000;

// ─── Storage paths ────────────────────────────────────────────────────────────
let storageDir;

if (fs.existsSync('/storage') || process.env.STORAGE_PATH) {
  storageDir = path.dirname(process.env.STORAGE_PATH || '/storage/vault.json');
} else {
  storageDir = path.join(__dirname, 'storage');
}

if (!fs.existsSync(storageDir)) {
  fs.mkdirSync(storageDir, { recursive: true });
}

const storageFile  = path.join(storageDir, 'vault.json');
const slotsFile    = path.join(storageDir, 'slots.json');
const accountsFile = path.join(storageDir, 'accounts_meta.json'); // stores email+password per accountId

// ─── Config ───────────────────────────────────────────────────────────────────
const ADMIN_PASSWORD  = '@eternalgy9999';
const MAX_SLOTS       = 3;
const WA_SESSION_ID   = 'eternalgy-auth';

// ─── File helpers ─────────────────────────────────────────────────────────────
function readJSON(file, fallback = {}) {
  if (!fs.existsSync(file)) return fallback;
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return fallback; }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

const readSlots        = () => readJSON(slotsFile, {});
const writeSlots       = (d) => writeJSON(slotsFile, d);
const readAccountsMeta = () => readJSON(accountsFile, {});
const writeAccountsMeta= (d) => writeJSON(accountsFile, d);

// ─── Phone normalisation ──────────────────────────────────────────────────────
// Accepts: 0123456789 / 60123456789 / +60123456789
// Returns: 60123456789  (no + prefix, digits only — Baileys format)
function normaliseMY(raw) {
  let digits = raw.replace(/\D/g, '');           // strip everything non-digit
  if (digits.startsWith('60')) return digits;    // already has country code
  if (digits.startsWith('0'))  return '6' + digits; // 0xx → 60xx
  // bare 8-9 digit number (no leading 0, no country code) → prepend 60
  return '60' + digits;
}

// Validate after normalisation: must be 60 + 8 or 9 digits = 10 or 11 digits total
function isValidMYNumber(normalised) {
  return /^60\d{8,9}$/.test(normalised);
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

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(__dirname));

// ─── Vault API ────────────────────────────────────────────────────────────────
app.get('/api/vault', (req, res) => {
  if (!fs.existsSync(storageFile)) return res.json({ encryptedData: null, plainAccounts: null });
  try {
    return res.json(JSON.parse(fs.readFileSync(storageFile, 'utf8')));
  } catch (e) {
    return res.status(500).json({ error: 'Failed to read vault.' });
  }
});

app.post('/api/vault', (req, res) => {
  try {
    const payload = req.body;
    if (payload.encryptedData === undefined && payload.plainAccounts === undefined)
      return res.status(400).json({ error: 'Invalid payload structure.' });
    fs.writeFileSync(storageFile, JSON.stringify(payload, null, 2), 'utf8');
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to write vault.' });
  }
});

// ─── Admin middleware ─────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.headers['x-admin-password'] !== ADMIN_PASSWORD)
    return res.status(401).json({ error: 'Unauthorized.' });
  next();
}

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
    `✅ *Sentinel 2FA — Slot Claimed*\n\n` +
    `You have successfully claimed access to a Google account.\n\n` +
    `📧 *Email:* ${info.loginEmail}\n` +
    `🔑 *Password:* ${info.loginPassword}\n\n` +
    `📱 *How to use:*\n` +
    `1. Download *Gemini* app on your phone\n` +
    `2. Sign in with the email & password above\n` +
    `3. When asked for 2FA, use the OTP code from the Sentinel 2FA vault\n\n` +
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

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Sentinel 2FA Server running on port ${PORT}`);
  console.log(`Vault:         ${storageFile}`);
  console.log(`Slots:         ${slotsFile}`);
  console.log(`Accounts meta: ${accountsFile}`);
});
