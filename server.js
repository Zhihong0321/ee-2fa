const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8000;

// Determine storage path (Railway perma storage is mounted at /storage)
let storageFile = process.env.STORAGE_PATH || '/storage/vault.json';

// Local fallback if /storage doesn't exist and no env variable overrides it
if (!fs.existsSync('/storage') && !process.env.STORAGE_PATH) {
  const localDir = path.join(__dirname, 'storage');
  if (!fs.existsSync(localDir)) {
    fs.mkdirSync(localDir);
  }
  storageFile = path.join(localDir, 'vault.json');
} else {
  // Ensure target folder exists
  const dir = path.dirname(storageFile);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

app.use(express.json());
app.use(express.static(__dirname));

// API routes
app.get('/api/vault', (req, res) => {
  if (!fs.existsSync(storageFile)) {
    return res.json({ encryptedData: null, plainAccounts: null });
  }
  try {
    const raw = fs.readFileSync(storageFile, 'utf8');
    return res.json(JSON.parse(raw));
  } catch (e) {
    console.error('Failed to read vault file:', e);
    return res.status(500).json({ error: 'Failed to read vault.' });
  }
});

app.post('/api/vault', (req, res) => {
  try {
    const payload = req.body;
    // Basic verification of structure
    if (payload.encryptedData === undefined && payload.plainAccounts === undefined) {
      return res.status(400).json({ error: 'Invalid payload structure.' });
    }
    fs.writeFileSync(storageFile, JSON.stringify(payload, null, 2), 'utf8');
    return res.json({ success: true });
  } catch (e) {
    console.error('Failed to write vault file:', e);
    return res.status(500).json({ error: 'Failed to write vault.' });
  }
});

app.listen(PORT, () => {
  console.log(`Sentinel 2FA Server running on port ${PORT}`);
  console.log(`Vault storage file: ${storageFile}`);
});
