/**
 * 2FA OTP Authenticator App Logic
 * Designed with modern ES6, Web Crypto API, and local-only security.
 */

// --- UTILITY FUNCTIONS ---

/**
 * Decodes a Base32 string into a Uint8Array.
 * Alphabet: A-Z, 2-7
 */
function base32ToBytes(str) {
  const cleanStr = str.replace(/=+$/, "").toUpperCase().replace(/[\s-]/g, "");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = [];
  let buffer = 0;
  let bitsLeft = 0;

  for (let i = 0; i < cleanStr.length; i++) {
    const val = alphabet.indexOf(cleanStr[i]);
    if (val === -1) {
      throw new Error(`Invalid Base32 character: ${cleanStr[i]}`);
    }
    buffer = (buffer << 5) | val;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bytes.push((buffer >> (bitsLeft - 8)) & 0xff);
      bitsLeft -= 8;
      buffer &= (1 << bitsLeft) - 1;
    }
  }
  return new Uint8Array(bytes);
}

/**
 * Encodes an ArrayBuffer as a Base64 string.
 */
function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Decodes a Base64 string into an ArrayBuffer.
 */
function base64ToArrayBuffer(base64) {
  const binaryStr = atob(base64);
  const len = binaryStr.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryStr.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Parses an otpauth:// URI (often generated for 2FA setup).
 */
function parseOtpauthURI(uri) {
  try {
    if (!uri.startsWith("otpauth://")) return null;
    const url = new URL(uri);
    if (url.host !== "totp") {
      throw new Error("Only time-based (TOTP) keys are supported by this client.");
    }

    let label = decodeURIComponent(url.pathname.substring(1));
    let issuer = "";
    let email = "";

    if (label.includes(":")) {
      const parts = label.split(":");
      issuer = parts[0].trim();
      email = parts.slice(1).join(":").trim();
    } else {
      email = label.trim();
    }

    const params = new URLSearchParams(url.search);
    const secret = params.get("secret");
    if (!secret) {
      throw new Error("Secret key is missing in URI.");
    }

    // Try getting issuer from parameter (preferred)
    const paramIssuer = params.get("issuer");
    if (paramIssuer) {
      issuer = paramIssuer;
    }

    const algorithm = params.get("algorithm") || "SHA-1";
    const digits = parseInt(params.get("digits") || "6", 10);
    const period = parseInt(params.get("period") || "30", 10);

    return {
      issuer: issuer || "Authenticator",
      email: email,
      secret: secret,
      algorithm: algorithm.replace(/SHA(\d+)/, "SHA-$1"), // normalizes SHA256 -> SHA-256
      digits: digits,
      period: period
    };
  } catch (e) {
    console.error("Failed to parse OTP URI", e);
    return null;
  }
}

// --- VAULT ENCRYPTION ENGINE (Web Crypto API) ---

/**
 * Derives an encryption key from a master password.
 */
async function deriveKey(password, salt, iterations = 100000) {
  const encoder = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: iterations,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts data using AES-GCM 256-bit with derived master password.
 */
async function encryptData(plaintext, password) {
  const encoder = new TextEncoder();
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    encoder.encode(plaintext)
  );

  // Layout: 16 bytes salt + 12 bytes IV + ciphertext
  const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ciphertext), salt.length + iv.length);
  
  return arrayBufferToBase64(combined);
}

/**
 * Decrypts data using AES-GCM 256-bit with derived master password.
 */
async function decryptData(combinedBase64, password) {
  const combined = new Uint8Array(base64ToArrayBuffer(combinedBase64));
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);
  
  const key = await deriveKey(password, salt);
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    ciphertext
  );
  
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

// --- TOTP GENERATOR ENGINE ---

/**
 * Generates the time-based OTP token for a base32 secret.
 */
async function generateTOTP(secret, algorithm = "SHA-1", digits = 6, period = 30) {
  try {
    const cleanSecret = secret.replace(/\s+/g, "").toUpperCase();
    const keyBytes = base32ToBytes(cleanSecret);
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / period);
    const secondsRemaining = period - (epoch % period);

    // Convert counter to 8-byte big-endian representation
    const counterBytes = new Uint8Array(8);
    let temp = counter;
    for (let i = 7; i >= 0; i--) {
      counterBytes[i] = temp & 0xff;
      temp = Math.floor(temp / 256);
    }

    // Import the secret as raw HMAC key
    const webCryptoAlg = { name: "HMAC", hash: { name: algorithm } };
    const hmacKey = await window.crypto.subtle.importKey(
      "raw",
      keyBytes,
      webCryptoAlg,
      false,
      ["sign"]
    );

    // Run HMAC
    const signatureBuffer = await window.crypto.subtle.sign(
      "HMAC",
      hmacKey,
      counterBytes
    );
    const signatureBytes = new Uint8Array(signatureBuffer);

    // Dynamic Truncation
    const offset = signatureBytes[signatureBytes.length - 1] & 0x0f;
    const binary =
      ((signatureBytes[offset] & 0x7f) << 24) |
      ((signatureBytes[offset + 1] & 0xff) << 16) |
      ((signatureBytes[offset + 2] & 0xff) << 8) |
      (signatureBytes[offset + 3] & 0xff);

    const otp = (binary % Math.pow(10, digits)).toString().padStart(digits, "0");
    return { token: otp, secondsRemaining };
  } catch (error) {
    console.error("TOTP generation error", error);
    return { token: "ERROR", secondsRemaining: 30 };
  }
}

// --- STATE MANAGEMENT ---

const state = {
  accounts: [],
  masterPassword: "",
  isLocked: false,
  searchQuery: "",
  activeCardMenuId: null,
  editingAccountId: null,
  remoteEncryptedData: null,
  slots: {},           // { accountId: count }
  myWhatsApp: localStorage.getItem("my_whatsapp") || "",
  myClaims: {}         // { accountId: waNumber } — which accounts this device claimed
};

// LocalStorage Keys
const STORAGE_KEYS = {
  ENCRYPTED_VAULT: "vault_encrypted_data",
  PLAIN_VAULT: "vault_plain_accounts"
};

/**
 * Initializes state. Loads accounts from LocalStorage, prompts for master password if encrypted.
 */
/**
 * Initializes state. Loads accounts from Server API with LocalStorage fallback.
 */
async function initVault() {
  try {
    const response = await fetch('/api/vault');
    if (!response.ok) throw new Error('API server returned error status');
    
    const payload = await response.json();
    
    if (payload.encryptedData) {
      state.isLocked = true;
      state.remoteEncryptedData = payload.encryptedData;
      
      // Mirror to local storage as backup
      localStorage.setItem(STORAGE_KEYS.ENCRYPTED_VAULT, payload.encryptedData);
      localStorage.removeItem(STORAGE_KEYS.PLAIN_VAULT);
      
      showLockScreen(true, "Unlock Vault", "Please enter your master password to unlock your 2FA accounts.");
    } else if (payload.plainAccounts) {
      state.isLocked = false;
      state.remoteEncryptedData = null;
      state.accounts = payload.plainAccounts;
      
      // Mirror to local storage as backup
      localStorage.setItem(STORAGE_KEYS.PLAIN_VAULT, JSON.stringify(payload.plainAccounts));
      localStorage.removeItem(STORAGE_KEYS.ENCRYPTED_VAULT);
      
      await loadSlots();
      renderAccounts();
      showLockScreen(false);
    } else {
      // Empty server vault - check if we can migrate from localStorage
      const localEncrypted = localStorage.getItem(STORAGE_KEYS.ENCRYPTED_VAULT);
      const localPlain = localStorage.getItem(STORAGE_KEYS.PLAIN_VAULT);
      
      if (localEncrypted) {
        state.isLocked = true;
        state.remoteEncryptedData = localEncrypted;
        showLockScreen(true, "Unlock Vault", "Please enter your master password to unlock your 2FA accounts.");
      } else if (localPlain) {
        state.isLocked = false;
        state.accounts = JSON.parse(localPlain);
        renderAccounts();
        showLockScreen(false);
        // Sync the local plain accounts back to server
        await saveVault();
      } else {
        // Entirely empty
        state.isLocked = false;
        state.accounts = [];
        renderAccounts();
        showLockScreen(false);
      }
    }
  } catch (error) {
    console.warn("Could not connect to API server. Falling back to local browser storage.", error);
    showToast("Offline: Using local browser storage.", "error");
    
    // Offline / Standalone HTML fallback
    const encryptedData = localStorage.getItem(STORAGE_KEYS.ENCRYPTED_VAULT);
    const plainData = localStorage.getItem(STORAGE_KEYS.PLAIN_VAULT);

    if (encryptedData) {
      state.isLocked = true;
      showLockScreen(true, "Unlock Vault", "Please enter your master password to unlock your 2FA accounts.");
    } else if (plainData) {
      state.isLocked = false;
      try {
        state.accounts = JSON.parse(plainData);
        renderAccounts();
        showLockScreen(false);
      } catch (e) {
        showToast("Corrupted plain vault data. Resetting.", "error");
        state.accounts = [];
        renderAccounts();
      }
    } else {
      state.isLocked = false;
      state.accounts = [];
      renderAccounts();
      showLockScreen(false);
    }
  }
}

/**
 * Saves current accounts state to server storage with LocalStorage backup mirror.
 */
async function saveVault() {
  let payload = {
    encryptedData: null,
    plainAccounts: null
  };

  if (state.masterPassword) {
    try {
      const plaintext = JSON.stringify(state.accounts);
      const ciphertext = await encryptData(plaintext, state.masterPassword);
      payload.encryptedData = ciphertext;
      state.remoteEncryptedData = ciphertext;
      
      // Update local storage backup
      localStorage.setItem(STORAGE_KEYS.ENCRYPTED_VAULT, ciphertext);
      localStorage.removeItem(STORAGE_KEYS.PLAIN_VAULT);
    } catch (e) {
      console.error("Failed to encrypt vault:", e);
      showToast("Error encrypting vault.", "error");
      return;
    }
  } else {
    payload.plainAccounts = state.accounts;
    state.remoteEncryptedData = null;
    
    // Update local storage backup
    localStorage.setItem(STORAGE_KEYS.PLAIN_VAULT, JSON.stringify(state.accounts));
    localStorage.removeItem(STORAGE_KEYS.ENCRYPTED_VAULT);
  }

  try {
    const response = await fetch('/api/vault', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    
    if (!response.ok) throw new Error('API server failed to save data');
    // Silent success — no toast needed for routine saves
  } catch (error) {
    console.warn("Could not sync vault with server. Saved locally in browser.", error);
    showToast("Offline: Saved locally to browser.", "error");
  }
}

// --- UI AND ROUTING ---

/**
 * Renders the full list of accounts on the front page.
 */
function renderAccounts() {
  const container = document.getElementById("accounts-container");
  const emptyState = document.getElementById("empty-state");
  
  // Filter accounts
  const filtered = state.accounts.filter(acc => {
    const q = state.searchQuery.toLowerCase();
    const issuerMatch = (acc.issuer || "").toLowerCase().includes(q);
    const emailMatch = (acc.email || "").toLowerCase().includes(q);
    return issuerMatch || emailMatch;
  });

  if (filtered.length === 0) {
    container.style.display = "none";
    emptyState.style.display = "flex";
    return;
  }

  container.style.display = "grid";
  emptyState.style.display = "none";

  // Build the list map while preserving nodes where possible,
  // but since standard SPA uses render, we'll build the template and insert.
  let html = "";
  filtered.forEach(acc => {
    // Generate initial/avatar color based on issuer
    const initial = (acc.issuer || "A").substring(0, 1).toUpperCase();
    const avatarColor = getAvatarColor(acc.issuer || "Authenticator");

    html += `
      <div class="account-card" data-id="${acc.id}">
        <div class="card-header">
          <div class="account-info">
            <div class="account-avatar" style="color: ${avatarColor}; border-color: ${avatarColor}33; background: ${avatarColor}10">
              ${initial}
            </div>
            <div class="account-details">
              <span class="issuer-name">${escapeHtml(acc.issuer || "Authenticator")}</span>
              <span class="account-email">${escapeHtml(acc.email || "")}</span>
            </div>
          </div>
          <button class="card-menu-btn" onclick="toggleCardMenu(event, '${acc.id}')">
            <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z"></path>
            </svg>
          </button>
          <div class="card-menu-dropdown" id="dropdown-${acc.id}">
            <button class="dropdown-item" onclick="editAccount('${acc.id}')">
              <svg width="14" height="14" fill="none" stroke="currentColor" stroke-dasharray="" stroke-width="2" viewBox="0 0 24 24" style="margin-right: 4px;">
                <path stroke-linecap="round" stroke-linejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
              </svg>Edit
            </button>
            <button class="dropdown-item delete-item" onclick="confirmDeleteAccount('${acc.id}')">
              <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="margin-right: 4px;">
                <path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
              </svg>Delete
            </button>
          </div>
        </div>
        
        <div class="otp-display-container" onclick="copyTokenToClipboard('${acc.id}')">
          <span class="otp-token" id="token-${acc.id}">------</span>
          <svg class="copy-icon" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path>
          </svg>
        </div>

        <div class="card-footer">
          <div class="timer-indicator">
            <svg class="timer-svg">
              <circle class="timer-bg-circle" cx="12" cy="12" r="10"></circle>
              <circle class="timer-fill-circle" id="circle-${acc.id}" cx="12" cy="12" r="10"></circle>
            </svg>
            <span class="timer-seconds" id="sec-${acc.id}">30s</span>
          </div>
          <span style="font-size: 0.75rem; opacity: 0.7;">Click token to copy</span>
        </div>

        ${renderSlotBar(acc.id)}
      </div>
    `;
  });

  container.innerHTML = html;
  
  // Instantly compute first OTP codes
  updateAllTokens();
}

/**
 * Updates all displayed OTP values, timers, and animations.
 * Called automatically every second.
 */
async function updateAllTokens() {
  if (state.isLocked) return;

  for (const acc of state.accounts) {
    const tokenEl = document.getElementById(`token-${acc.id}`);
    const circleEl = document.getElementById(`circle-${acc.id}`);
    const secEl = document.getElementById(`sec-${acc.id}`);
    
    if (!tokenEl || !circleEl || !secEl) continue;

    const period = acc.period || 30;
    const digits = acc.digits || 6;
    const algorithm = acc.algorithm || "SHA-1";

    const { token, secondsRemaining } = await generateTOTP(acc.secret, algorithm, digits, period);
    
    // Formatting standard token like "123 456" for 6 digit and "1234 5678" for 8 digit
    let formattedToken = token;
    if (token !== "ERROR" && token.length === 6) {
      formattedToken = token.slice(0, 3) + " " + token.slice(3);
    } else if (token !== "ERROR" && token.length === 8) {
      formattedToken = token.slice(0, 4) + " " + token.slice(4);
    }

    tokenEl.textContent = formattedToken;
    secEl.textContent = `${secondsRemaining}s`;

    // Circular progress stroke-dashoffset logic
    // Circumference = 2 * PI * r = 2 * 3.14159 * 10 = 62.83
    const maxCircumference = 62.83;
    const progress = secondsRemaining / period;
    const dashOffset = maxCircumference * (1 - progress);
    circleEl.style.strokeDashoffset = dashOffset;

    // Visual Alerting Color & Pulse
    if (secondsRemaining <= 5) {
      circleEl.style.stroke = "var(--danger-color)";
      tokenEl.classList.add("expiring");
    } else {
      circleEl.style.stroke = "var(--accent-cyan)";
      tokenEl.classList.remove("expiring");
    }
  }
}

/**
 * Lock Screen control
 */
function showLockScreen(show, title = "Enter Master Password", desc = "") {
  const lockScreen = document.getElementById("lock-screen");
  const mainApp = document.getElementById("main-app");
  
  if (show) {
    lockScreen.style.display = "flex";
    mainApp.style.display = "none";
    document.getElementById("lock-title").textContent = title;
    document.getElementById("lock-desc").textContent = desc;
    document.getElementById("master-password-input").focus();
  } else {
    lockScreen.style.display = "none";
    mainApp.style.display = "flex";
  }
}

/**
 * Copy to Clipboard Handler
 */
function copyTokenToClipboard(accountId) {
  const tokenText = document.getElementById(`token-${accountId}`);
  if (!tokenText || tokenText.textContent.includes("---")) return;

  const code = tokenText.textContent.replace(/\s+/g, ""); // strip space for pasting
  navigator.clipboard.writeText(code).then(() => {
    showToast("Token copied to clipboard!");
  }).catch(() => {
    showToast("Failed to copy. Please copy manually.", "error");
  });
}

/**
 * Toast Notifications
 */
function showToast(message, type = "success") {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast ${type === "error" ? "toast-error" : ""}`;
  
  const icon = type === "success" ? "✓" : "✕";
  
  toast.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <span>${message}</span>
  `;
  
  container.appendChild(toast);
  
  // Remove after 3 seconds
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(20px)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Modal control helpers
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add("active");
    // Focus first input if any
    const firstInput = modal.querySelector("input");
    if (firstInput) setTimeout(() => firstInput.focus(), 100);
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.remove("active");
}

// Close active menus when clicking outside
window.addEventListener("click", () => {
  if (state.activeCardMenuId) {
    const dropdown = document.getElementById(`dropdown-${state.activeCardMenuId}`);
    if (dropdown) dropdown.classList.remove("active");
    state.activeCardMenuId = null;
  }
});

function toggleCardMenu(event, id) {
  event.stopPropagation();
  
  // Close currently active menu
  if (state.activeCardMenuId && state.activeCardMenuId !== id) {
    const prev = document.getElementById(`dropdown-${state.activeCardMenuId}`);
    if (prev) prev.classList.remove("active");
  }

  const dropdown = document.getElementById(`dropdown-${id}`);
  if (dropdown) {
    dropdown.classList.toggle("active");
    state.activeCardMenuId = dropdown.classList.contains("active") ? id : null;
  }
}

// Generate brand colors based on Issuer name
function getAvatarColor(issuer) {
  const name = issuer.toLowerCase();
  if (name.includes("google")) return "#4285F4";
  if (name.includes("github")) return "#6e5494";
  if (name.includes("discord")) return "#7289DA";
  if (name.includes("slack")) return "#4A154B";
  if (name.includes("microsoft")) return "#00A4EF";
  if (name.includes("aws") || name.includes("amazon")) return "#FF9900";
  if (name.includes("facebook") || name.includes("meta")) return "#1877F2";
  if (name.includes("dropbox")) return "#0061FF";
  
  // Simple hash for custom issuers
  let hash = 0;
  for (let i = 0; i < issuer.length; i++) {
    hash = issuer.charCodeAt(i) + ((hash << 5) - hash);
  }
  const h = Math.abs(hash) % 360;
  return `hsl(${h}, 75%, 60%)`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// --- FORM AND ACCOUNT ACTIONS ---

/**
 * Handle new / edited account submit
 */
async function handleAccountSubmit(event) {
  event.preventDefault();
  
  const issuer = document.getElementById("acc-issuer").value.trim();
  const email = document.getElementById("acc-email").value.trim();
  const secretRaw = document.getElementById("acc-secret").value.trim();
  const algorithm = document.getElementById("acc-algorithm").value;
  const digits = parseInt(document.getElementById("acc-digits").value, 10);
  const period = parseInt(document.getElementById("acc-period").value, 10);

  if (!secretRaw) {
    showToast("Secret key is required.", "error");
    return;
  }

  // Basic Base32 format verification (A-Z, 2-7, spaces, equals, dashes allowed)
  const cleanSecret = secretRaw.replace(/[\s-]/g, "").replace(/=+$/, "");
  if (!/^[A-Z2-7]+$/i.test(cleanSecret)) {
    showToast("Invalid secret. Must be a valid Base32 key.", "error");
    return;
  }

  try {
    // Validate Base32 decoding compiles correctly
    base32ToBytes(cleanSecret);
  } catch (e) {
    showToast("Decoding failed. Double-check your secret key.", "error");
    return;
  }

  if (state.editingAccountId) {
    // Update existing account
    const acc = state.accounts.find(a => a.id === state.editingAccountId);
    if (acc) {
      acc.issuer = issuer;
      acc.email = email;
      acc.secret = cleanSecret;
      acc.algorithm = algorithm;
      acc.digits = digits;
      acc.period = period;
      showToast("Account updated successfully");
    }
  } else {
    // Add new account
    const newAcc = {
      id: Date.now().toString(),
      issuer,
      email,
      secret: cleanSecret,
      algorithm,
      digits,
      period
    };
    state.accounts.push(newAcc);
    showToast("Account added successfully");
  }

  state.editingAccountId = null;
  document.getElementById("account-form").reset();
  closeModal("add-account-modal");
  renderAccounts();
  await saveVault();
}

/**
 * Sets editing form fields
 */
function editAccount(id) {
  const acc = state.accounts.find(a => a.id === id);
  if (!acc) return;

  state.editingAccountId = id;
  document.getElementById("modal-form-title").textContent = "Edit 2FA Account";
  document.getElementById("acc-issuer").value = acc.issuer || "";
  document.getElementById("acc-email").value = acc.email || "";
  document.getElementById("acc-secret").value = acc.secret || "";
  document.getElementById("acc-algorithm").value = acc.algorithm || "SHA-1";
  document.getElementById("acc-digits").value = acc.digits || 6;
  document.getElementById("acc-period").value = acc.period || 30;

  openModal("add-account-modal");
}

/**
 * Prompt account deletion
 */
function confirmDeleteAccount(id) {
  const acc = state.accounts.find(a => a.id === id);
  if (!acc) return;

  if (confirm(`Are you sure you want to delete ${acc.issuer || "Authenticator"} (${acc.email || "no email"})? This cannot be undone.`)) {
    state.accounts = state.accounts.filter(a => a.id !== id);
    renderAccounts();
    saveVault();
    showToast("Account deleted successfully");
  }
}

/**
 * Handle secret URI paste parsing
 */
function handleSecretInput(event) {
  const val = event.target.value.trim();
  if (val.startsWith("otpauth://")) {
    const parsed = parseOtpauthURI(val);
    if (parsed) {
      document.getElementById("acc-issuer").value = parsed.issuer;
      document.getElementById("acc-email").value = parsed.email;
      document.getElementById("acc-secret").value = parsed.secret;
      document.getElementById("acc-algorithm").value = parsed.algorithm;
      document.getElementById("acc-digits").value = parsed.digits;
      document.getElementById("acc-period").value = parsed.period;
      showToast("OTP URI parsed successfully!");
    } else {
      showToast("Could not parse OTP URL.", "error");
    }
  }
}

// --- MASTER PASSWORD & SECURITY ---

/**
 * Set master password or change it
 */
async function handleMasterPasswordSetup(event) {
  event.preventDefault();
  const currentPass = document.getElementById("setup-current-pw").value;
  const newPass = document.getElementById("setup-new-pw").value;
  const confirmPass = document.getElementById("setup-confirm-pw").value;

  // If already encrypted, verify current password
  const hasEncrypted = !!localStorage.getItem(STORAGE_KEYS.ENCRYPTED_VAULT);
  if (hasEncrypted && state.masterPassword && currentPass !== state.masterPassword) {
    showToast("Incorrect current password.", "error");
    return;
  }

  if (newPass !== confirmPass) {
    showToast("New passwords do not match.", "error");
    return;
  }

  if (newPass.length < 6) {
    showToast("Password must be at least 6 characters.", "error");
    return;
  }

  // Update in-memory password
  state.masterPassword = newPass;
  await saveVault();
  
  // Clean inputs
  document.getElementById("password-setup-form").reset();
  closeModal("settings-modal");
  updateSecurityTabInfo();
  showToast("Master password set up successfully!");
}

/**
 * Disable Master Password (decrypt to plaintext storage)
 */
async function handleDisableMasterPassword() {
  const currentPass = prompt("Please enter your current Master Password to disable encryption:");
  if (currentPass === null) return; // cancel

  if (currentPass !== state.masterPassword) {
    showToast("Incorrect password.", "error");
    return;
  }

  // Clear master password state
  state.masterPassword = "";
  // Save plain vault
  await saveVault();
  // Clear encrypted record
  localStorage.removeItem(STORAGE_KEYS.ENCRYPTED_VAULT);
  
  updateSecurityTabInfo();
  showToast("Encryption disabled. Data stored in plaintext.");
}

/**
 * Submit Unlock Password
 */
async function handleUnlockSubmit(event) {
  event.preventDefault();
  const inputEl = document.getElementById("master-password-input");
  const password = inputEl.value;

  const encryptedData = state.remoteEncryptedData || localStorage.getItem(STORAGE_KEYS.ENCRYPTED_VAULT);
  if (!encryptedData) {
    showToast("No encrypted database found.", "error");
    return;
  }

  try {
    const decryptedText = await decryptData(encryptedData, password);
    state.accounts = JSON.parse(decryptedText);
    state.masterPassword = password;
    state.isLocked = false;

    showLockScreen(false);
    await loadSlots();
    renderAccounts();
    updateSecurityTabInfo();
    showToast("Vault unlocked successfully!");
  } catch (err) {
    console.error(err);
    showToast("Incorrect password.", "error");
    inputEl.value = "";
    inputEl.focus();
  }
}

/**
 * Lock the App manually
 */
function lockVault() {
  if (!state.masterPassword) {
    showToast("No master password is set. Enable it in Settings first.", "error");
    return;
  }
  state.accounts = [];
  state.masterPassword = "";
  state.isLocked = true;
  renderAccounts();
  showLockScreen(true, "Vault Locked", "Unlock with your Master Password to access your accounts.");
  showToast("Vault locked.");
}

/**
 * Sync Security Tab Settings view
 */
function updateSecurityTabInfo() {
  const statusText = document.getElementById("security-status-text");
  const lockBtn = document.getElementById("header-lock-btn");
  const disableBtn = document.getElementById("disable-pw-btn");
  const currentPwGroup = document.getElementById("setup-current-pw-group");
  const currentPwInput = document.getElementById("setup-current-pw");
  const hasPassword = !!state.masterPassword;

  if (hasPassword) {
    statusText.textContent = "Enabled (Encrypted vault)";
    statusText.style.color = "var(--success-color)";
    lockBtn.style.display = "flex";
    disableBtn.style.display = "block";
    if (currentPwGroup) currentPwGroup.style.display = "flex";
    if (currentPwInput) currentPwInput.required = true;
  } else {
    statusText.textContent = "Disabled (Plaintext storage)";
    statusText.style.color = "var(--danger-color)";
    lockBtn.style.display = "none";
    disableBtn.style.display = "none";
    if (currentPwGroup) currentPwGroup.style.display = "none";
    if (currentPwInput) {
      currentPwInput.required = false;
      currentPwInput.value = "";
    }
  }
}

// --- IMPORT & EXPORT ---

/**
 * Export Accounts as JSON file
 */
function handleExport() {
  if (state.accounts.length === 0) {
    showToast("No accounts to export.", "error");
    return;
  }

  const exportPlain = confirm("Export accounts as an unencrypted JSON backup? Warning: Anyone with access to this file can view your secret 2FA keys!");
  if (!exportPlain) return;

  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.accounts, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `antigravity_2fa_backup_${Date.now()}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
  showToast("Backup exported!");
}

/**
 * Import Accounts from JSON File
 */
function handleImport(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async function(e) {
    try {
      const imported = JSON.parse(e.target.result);
      if (!Array.isArray(imported)) {
        throw new Error("Invalid file structure. Must be an array.");
      }

      // Quick sanity check on imported items
      let importCount = 0;
      imported.forEach(acc => {
        if (acc.secret) {
          // Normalize values
          const newAcc = {
            id: acc.id || (Date.now() + importCount).toString(),
            issuer: acc.issuer || "Imported",
            email: acc.email || "",
            secret: acc.secret.replace(/[\s-]/g, "").toUpperCase(),
            algorithm: acc.algorithm || "SHA-1",
            digits: parseInt(acc.digits, 10) || 6,
            period: parseInt(acc.period, 10) || 30
          };
          
          // Avoid duplicate keys
          const exists = state.accounts.some(a => a.secret === newAcc.secret);
          if (!exists) {
            state.accounts.push(newAcc);
            importCount++;
          }
        }
      });

      if (importCount > 0) {
        showToast(`Successfully imported ${importCount} accounts!`);
        renderAccounts();
        await saveVault();
        closeModal("settings-modal");
      } else {
        showToast("No new unique accounts found in the file.", "error");
      }
    } catch (err) {
      console.error(err);
      showToast("Failed to parse backup file.", "error");
    }
  };
  reader.readAsText(file);
  event.target.value = ""; // Reset input
}

// --- SETUP INITIAL EVENT BINDINGS ---

document.addEventListener("DOMContentLoaded", () => {
  // Vault decryption password submit
  document.getElementById("lock-screen-form").addEventListener("submit", handleUnlockSubmit);
  
  // Search account binding
  document.getElementById("search-input").addEventListener("input", (e) => {
    state.searchQuery = e.target.value;
    renderAccounts();
  });

  // Account add form submit
  document.getElementById("account-form").addEventListener("submit", handleAccountSubmit);
  
  // Secret URL input watcher
  document.getElementById("acc-secret").addEventListener("input", handleSecretInput);

  // Master password setup form submit
  document.getElementById("password-setup-form").addEventListener("submit", handleMasterPasswordSetup);

  // Export binding
  document.getElementById("export-btn").addEventListener("click", handleExport);
  
  // Import file change listener
  document.getElementById("import-file-input").addEventListener("change", handleImport);

  // Open "Add Account" Modal button
  document.getElementById("header-add-btn").addEventListener("click", () => {
    state.editingAccountId = null;
    document.getElementById("modal-form-title").textContent = "Add 2FA Account";
    document.getElementById("account-form").reset();
    openModal("add-account-modal");
  });

  // Open "Add Account" from empty state
  document.getElementById("empty-add-btn").addEventListener("click", () => {
    state.editingAccountId = null;
    document.getElementById("modal-form-title").textContent = "Add 2FA Account";
    document.getElementById("account-form").reset();
    openModal("add-account-modal");
  });

  // Open settings button
  document.getElementById("header-settings-btn").addEventListener("click", () => {
    openModal("settings-modal");
    updateSecurityTabInfo();
  });

  // Master Password Lock button
  document.getElementById("header-lock-btn").addEventListener("click", lockVault);
  
  // Master Password setup disable action
  document.getElementById("disable-pw-btn").addEventListener("click", handleDisableMasterPassword);

  // Modals closing triggers
  document.querySelectorAll(".modal-close").forEach(btn => {
    btn.addEventListener("click", (e) => {
      const modal = e.target.closest(".modal-overlay");
      if (modal) closeModal(modal.id);
    });
  });

  document.querySelectorAll(".modal-cancel-btn").forEach(btn => {
    btn.addEventListener("click", (e) => {
      const modal = e.target.closest(".modal-overlay");
      if (modal) closeModal(modal.id);
    });
  });

  // Settings Tabs Switcher
  const tabs = document.querySelectorAll(".settings-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      
      const paneId = tab.getAttribute("data-tab");
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      document.getElementById(paneId).classList.add("active");
    });
  });

  // Initialize data — load claims first so renderAccounts has them ready
  loadMyClaims();
  initVault();

  // Initialize slot modal listeners
  _initClaimListeners();
  _initUnclaimListeners();

  // Run OTP timers update loop (every 1000ms)
  setInterval(updateAllTokens, 1000);
});

// ─── SLOT SYSTEM ──────────────────────────────────────────────────────────────

const MAX_SLOTS_CLIENT = 3;

/**
 * Convert Malaysian phone input to normalised form for display/storage.
 * 0123456789  → 60123456789
 * 60123456789 → 60123456789
 * +60123456789→ 60123456789
 */
function normaliseMYPhone(raw) {
  let digits = raw.replace(/\D/g, '');
  if (digits.startsWith('60')) return digits;
  if (digits.startsWith('0'))  return '6' + digits;
  return '60' + digits;
}

/**
 * Validate Malaysian mobile number (after normalisation should be 10-11 digits starting with 60)
 */
function isValidMYPhone(normalised) {
  return /^60\d{8,9}$/.test(normalised);
}

/**
 * Fetch current slot counts from server and store in state.slots
 * Server returns { accountId: count } — no WA numbers exposed to client
 */
async function loadSlots() {
  try {
    const res = await fetch('/api/slots');
    if (res.ok) {
      state.slots = await res.json(); // { accountId: number }
    }
  } catch (e) {
    console.warn('Could not load slots:', e);
  }
}

/**
 * Build the slot bar HTML for a given accountId.
 * Shows 3 slot pips + a claim/release button.
 */
function renderSlotBar(accountId) {
  const taken    = state.slots[accountId] || 0;
  const myWA     = state.myWhatsApp;
  // We track locally which accounts this device claimed
  const claimed  = state.myClaims || {};
  const iClaimed = myWA && claimed[accountId] === myWA;

  // Build 3 pip indicators
  let pips = '';
  for (let i = 0; i < MAX_SLOTS_CLIENT; i++) {
    const filled = i < taken;
    // We can't know which exact slot index is ours (server only returns count),
    // so highlight all filled pips with a softer "mine" style when we claimed this account
    const isMe = iClaimed && filled;
    pips += `<span class="slot-pip ${filled ? 'slot-pip-filled' : ''} ${isMe ? 'slot-pip-mine' : ''}"
      title="${filled ? (iClaimed && i === 0 ? 'You (and others)' : 'Taken') : 'Available'}"></span>`;
  }

  let actionBtn = '';
  if (iClaimed) {
    actionBtn = `<button class="slot-btn slot-btn-release" onclick="openUnclaimModal('${accountId}')">Release</button>`;
  } else if (taken < MAX_SLOTS_CLIENT) {
    actionBtn = `<button class="slot-btn slot-btn-claim" onclick="openClaimModal('${accountId}')">Claim</button>`;
  } else {
    actionBtn = `<span class="slot-full-label">Full</span>`;
  }

  return `
    <div class="slot-bar">
      <div class="slot-pips">${pips}</div>
      <div class="slot-bar-right">
        <span class="slot-count">${taken}/${MAX_SLOTS_CLIENT} slots</span>
        ${actionBtn}
      </div>
    </div>
  `;
}

// Load which accounts this device has claimed (stored locally)
function loadMyClaims() {
  try {
    state.myClaims = JSON.parse(localStorage.getItem('my_claims') || '{}');
  } catch (e) {
    state.myClaims = {};
  }
}

function saveMyClaims() {
  localStorage.setItem('my_claims', JSON.stringify(state.myClaims || {}));
}

// ─── Claim Modal ──────────────────────────────────────────────────────────────

let _claimTargetId = null;

function openClaimModal(accountId) {
  _claimTargetId = accountId;
  const input = document.getElementById('claim-wa-input');
  // Pre-fill with previously used number (show in local format if starts with 60)
  let prefill = state.myWhatsApp || '';
  if (prefill.startsWith('60')) prefill = '0' + prefill.slice(2);
  input.value = prefill;
  // Clear any previous preview/error
  document.getElementById('claim-wa-preview').textContent = '';
  document.getElementById('claim-error').textContent = '';
  openModal('claim-modal');
}

function _initClaimListeners() {
  // Live preview: show converted number as user types
  document.getElementById('claim-wa-input').addEventListener('input', (e) => {
    const raw     = e.target.value.trim();
    const preview = document.getElementById('claim-wa-preview');
    const errEl   = document.getElementById('claim-error');
    if (!raw) { preview.textContent = ''; errEl.textContent = ''; return; }
    const norm = normaliseMYPhone(raw);
    if (isValidMYPhone(norm)) {
      preview.textContent = `Will send to: +${norm}`;
      preview.style.color = 'var(--success-color)';
      errEl.textContent = '';
    } else {
      preview.textContent = '';
      errEl.textContent = 'Invalid number. Enter 10–11 digit Malaysian number e.g. 0123456789';
    }
  });

  document.getElementById('claim-confirm-btn').addEventListener('click', async () => {
    const raw   = document.getElementById('claim-wa-input').value.trim();
    const errEl = document.getElementById('claim-error');

    if (!raw) { errEl.textContent = 'Please enter your WhatsApp number.'; return; }

    const norm = normaliseMYPhone(raw);
    if (!isValidMYPhone(norm)) {
      errEl.textContent = 'Invalid number. Enter 10–11 digit Malaysian number e.g. 0123456789';
      return;
    }

    const btn = document.getElementById('claim-confirm-btn');
    btn.disabled = true;
    btn.textContent = 'Sending…';

    try {
      const res  = await fetch('/api/slots/claim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accountId: _claimTargetId, whatsapp: norm })
      });
      const data = await res.json();
      if (!res.ok) {
        errEl.textContent = data.error || 'Failed to claim slot.';
      } else {
        // Save locally
        state.myWhatsApp = norm;
        localStorage.setItem('my_whatsapp', norm);
        if (!state.myClaims) state.myClaims = {};
        state.myClaims[_claimTargetId] = norm;
        saveMyClaims();

        await loadSlots();
        renderAccounts();
        closeModal('claim-modal');
        showToast('Slot claimed! Login info sent to your WhatsApp.');
      }
    } catch (e) {
      errEl.textContent = 'Network error. Try again.';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Claim Slot';
    }
  });
}

// ─── Unclaim Modal ────────────────────────────────────────────────────────────

let _unclaimTargetId = null;

function openUnclaimModal(accountId) {
  _unclaimTargetId = accountId;
  // Show in local format
  let display = state.myWhatsApp || '';
  if (display.startsWith('60')) display = '0' + display.slice(2);
  document.getElementById('unclaim-wa-display').textContent = display;
  openModal('unclaim-modal');
}

function _initUnclaimListeners() {
  document.getElementById('unclaim-confirm-btn').addEventListener('click', async () => {
    const btn = document.getElementById('unclaim-confirm-btn');
    btn.disabled = true;
    btn.textContent = 'Releasing…';

    try {
      const res  = await fetch('/api/slots/unclaim', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accountId: _unclaimTargetId, whatsapp: state.myWhatsApp })
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || 'Failed to release slot.', 'error');
      } else {
        // Remove local record
        if (state.myClaims) delete state.myClaims[_unclaimTargetId];
        saveMyClaims();

        await loadSlots();
        renderAccounts();
        closeModal('unclaim-modal');
        showToast('Slot released.');
      }
    } catch (e) {
      showToast('Network error. Try again.', 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Release Slot';
    }
  });
}
