// chat.js

// ---------------------------
// Config & Global State
// ---------------------------
const API_BASE = "http://localhost:5000";
const WS_URL = "ws://localhost:5001/ws";

let username = null;
let token = null;
let encryptedPrivateKey = null;
let userPassword = null;

let rsaPrivateKey = null; // WebCrypto PrivateKey
let currentChatUser = null;
let ws = null;

const publicKeyCache = {}; // { username: CryptoKey }

// Track "pending" file bubbles so we can attach DB id later 
const pendingFileBubbles = new Map(); // key -> { div, btn, meta }

// ---------------------------
// DOM Elements
// ---------------------------
const currentUserEl = document.getElementById("current-user");
const logoutButton = document.getElementById("logout-button");

const bannerEl = document.getElementById("message-banner");

const userSearchInput = document.getElementById("user-search-input");
const userSearchButton = document.getElementById("user-search-button");
const userListEl = document.getElementById("user-list");

const messagesEl = document.getElementById("messages");
const messageForm = document.getElementById("message-form");
const messageInput = document.getElementById("message-input");

// FILE SHARING
const fileInput = document.getElementById("file-input");
const attachFileButton = document.getElementById("attach-file-button");
const sendButton = document.getElementById("send-button");

let selectedFile = null;

// ---------------------------
// Helpers
// ---------------------------
function showBanner(text, isError = false) {
    if (!bannerEl) return;
    bannerEl.textContent = text;
    bannerEl.style.display = "block";
    bannerEl.className = "banner " + (isError ? "banner-error" : "banner-success");
    setTimeout(() => {
        bannerEl.style.display = "none";
    }, 2500);
}

function b64ToBytes(b64) {
    const bin = atob(b64);
    const len = bin.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
}

function bytesToB64(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

function arrayBufferToB64(ab) {
    return bytesToB64(new Uint8Array(ab));
}

function b64ToArrayBuffer(b64) {
    return b64ToBytes(b64).buffer;
}

// correct timestamp parsing for SQLite "YYYY-MM-DD HH:MM:SS"
function parseTimestamp(ts) {
    if (!ts) return Date.now();

    if (typeof ts === "string") {
        let s = ts.trim();

        // Convert "YYYY-MM-DD HH:MM:SS" -> "YYYY-MM-DDTHH:MM:SSZ"
        if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$/.test(s)) {
            s = s.replace(" ", "T") + "Z";
        }

        // If already ISO-like without timezone: "YYYY-MM-DDTHH:MM:SS"
        if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(s)) {
            s = s + "Z";
        }

        const t = Date.parse(s);
        return Number.isNaN(t) ? Date.now() : t;
    }

    if (typeof ts === "number") return ts;

    return Date.now();
}

// format timestamp for UI (HH:MM or HH:MM:SS depending on your preference)
function formatTime(t) {
    try {
        return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    } catch {
        return "";
    }
}

// Small helper for unique ids (for pending bubbles)
function makeClientId() {
    if (crypto && crypto.randomUUID) return crypto.randomUUID();
    return "cid_" + Math.random().toString(16).slice(2) + "_" + Date.now();
}

// ---------------------------
// LocalStorage helpers 
// ---------------------------
function lsKeyForConversation(me, other) {
    return `securechat:v1:${me}::${other}`;
}

function getLocalMessages(me, other) {
    const key = lsKeyForConversation(me, other);
    try {
        const raw = localStorage.getItem(key);
        if (!raw) return [];
        const arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr : [];
    } catch (err) {
        console.error("Failed to read local messages:", err);
        return [];
    }
}

function saveLocalMessages(me, other, list) {
    const key = lsKeyForConversation(me, other);
    try {
        localStorage.setItem(key, JSON.stringify(list));
    } catch (err) {
        console.error("Failed to save local messages:", err);
    }
}

function addLocalOutgoingMessage(me, other, text) {
    const list = getLocalMessages(me, other);
    list.push({
        sender: me,
        text,
        time: Date.now()
    });
    saveLocalMessages(me, other, list);
}

// ---------------------------
// Private Key Decryption 
// ---------------------------
async function decryptPrivateKey(encryptedBlobB64, password) {
    try {
        const raw = b64ToBytes(encryptedBlobB64);
        const salt = raw.slice(0, 16);
        const iv = raw.slice(16, 28);
        const ciphertext = raw.slice(28);

        const enc = new TextEncoder();
        const baseKey = await crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        const aesKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 390000,
                hash: "SHA-256"
            },
            baseKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );
        const plain = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            aesKey,
            ciphertext
        );
        const pem = new TextDecoder().decode(plain);
        return pem;
    } catch (err) {
        console.error("Failed to decrypt private key:", err);
        return null;
    }
}
async function importPrivateKeyFromPem(pem) {
    const clean = pem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace(/\s+/g, "");
    const keyData = b64ToBytes(clean);
    return crypto.subtle.importKey(
        "pkcs8",
        keyData,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
    );
}

async function importPublicKeyFromPem(pem) {
    const clean = pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(/\s+/g, "");
    const keyData = b64ToBytes(clean);

    return crypto.subtle.importKey(
        "spki",
        keyData,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );
}

// ---------------------------
// Load Session & Init
// ---------------------------
async function initSessionAndKeys() {
    username = sessionStorage.getItem("username");
    token = sessionStorage.getItem("token");
    encryptedPrivateKey = sessionStorage.getItem("encrypted_private_key");
    userPassword = sessionStorage.getItem("user_password");

    if (!username || !encryptedPrivateKey || !userPassword) {
        window.location.href = "login.html";
        return false;
    }

    if (currentUserEl) {
        currentUserEl.textContent = `Logged in as: ${username}`;
    }

    const pem = await decryptPrivateKey(encryptedPrivateKey, userPassword);
    if (!pem) {
        showBanner("Failed to unlock your encryption keys. Try logging in again.", true);
        return false;
    }

    rsaPrivateKey = await importPrivateKeyFromPem(pem);
    return true;
}

// ---------------------------
// Fetch & Cache Public Keys
// ---------------------------
async function getPublicKeyForUser(user) {
    if (publicKeyCache[user]) return publicKeyCache[user];

    const resp = await fetch(`${API_BASE}/public_key/${encodeURIComponent(user)}`);
    if (!resp.ok) throw new Error("Failed to fetch public key");

    const data = await resp.json();
    const key = await importPublicKeyFromPem(data.public_key);
    publicKeyCache[user] = key;
    return key;
}

// ---------------------------
// Sidebar
// ---------------------------
function addUserToSidebar(user) {
    const existing = Array.from(userListEl.querySelectorAll(".user-item")).find(
        el => el.dataset.username === user
    );
    if (existing) return;

    const div = document.createElement("div");
    div.className = "user-item";
    div.dataset.username = user;
    div.textContent = user;

    div.addEventListener("click", () => {
        setActiveChatUser(user);
    });

    userListEl.appendChild(div);
}

// ---------------------------
// Search User
// ---------------------------
async function handleUserSearch() {
    const query = userSearchInput.value.trim();
    if (!query) return;

    if (query === username) {
        showBanner("You cannot chat with yourself.", true);
        return;
    }

    if (query === "admin") {
        showBanner("You cannot chat with the admin account.", true);
        return;
    }

    try {
        const resp = await fetch(`${API_BASE}/search_user?username=${encodeURIComponent(query)}`);
        const data = await resp.json();

        userListEl.innerHTML = "";

        if (!data.exists) {
            userListEl.innerHTML = `<p class="empty-state">User not found.</p>`;
            return;
        }

        addUserToSidebar(query);
        showBanner(`User "${query}" found. Click on the name to start chatting.`, false);
    } catch (err) {
        console.error("Search error:", err);
        showBanner("Error searching for user.", true);
    }
}

// ---------------------------
// WebSocket
// ---------------------------
function initWebSocket() {
    ws = new WebSocket(`${WS_URL}?username=${encodeURIComponent(username)}`);

    ws.onopen = () => {
        console.log("[WS] Connected");
    };

    ws.onmessage = async (event) => {
        try {
            const msg = JSON.parse(event.data);

            // TEXT MESSAGE
            if (msg.type === "message") {
                const otherUser = msg.sender === username ? msg.receiver : msg.sender;
                addUserToSidebar(otherUser);

                if (msg.sender === username) return;
                if (!currentChatUser || currentChatUser !== otherUser) return;

                const text = await decryptMessage(msg);
                const t = parseTimestamp(msg.timestamp) || Date.now();
                appendMessage(text, false, t);
                return;
            }

            // FILE MESSAGE
            if (msg.type === "file") {
                const otherUser = msg.sender === username ? msg.receiver : msg.sender;

                if (msg.sender === username) return;

                addUserToSidebar(otherUser);
                if (!currentChatUser || currentChatUser !== otherUser) return;

                // Create bubble (may not yet have DB id)
                const t = parseTimestamp(msg.timestamp) || Date.now();
                appendFileBubble(msg, false, t);

                // Try to resolve ID immediately if missing
                if (!msg.id && msg.sha256) {
                    await resolveFileIdAndEnableDownload({
                        sender: msg.sender,
                        receiver: msg.receiver,
                        filename: msg.filename,
                        size_bytes: msg.size_bytes,
                        sha256: msg.sha256
                    });
                }

                return;
            }

        } catch (err) {
            console.error("Error handling WS message:", err);
        }
    };

    ws.onclose = () => {
        console.log("[WS] Disconnected. Reconnecting...");
        setTimeout(initWebSocket, 1500);
    };

    ws.onerror = (err) => {
        console.error("[WS] Error:", err);
    };
}

// ---------------------------
// Message Encryption/Decryption
// ---------------------------
async function encryptForReceiver(plainText, receiver) {
    const publicKey = await getPublicKeyForUser(receiver);

    const aesKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedText = new TextEncoder().encode(plainText);

    const cipherBuf = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        encodedText
    );

    const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
    const encryptedAesKeyBuf = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        rawAesKey
    );

    return {
        encrypted_message: bytesToB64(cipherBuf),
        encrypted_aes_key: bytesToB64(encryptedAesKeyBuf),
        iv: bytesToB64(iv)
    };
}

async function decryptMessage(msg) {
    try {
        if (!rsaPrivateKey) return "[Decryption failed]";

        const encKeyBytes = b64ToBytes(msg.encrypted_aes_key);
        const ivBytes = b64ToBytes(msg.iv);
        const cipherBytes = b64ToBytes(msg.encrypted_message);

        const rawAesKey = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            rsaPrivateKey,
            encKeyBytes
        );

        const aesKey = await crypto.subtle.importKey(
            "raw",
            rawAesKey,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        const plainBuf = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBytes },
            aesKey,
            cipherBytes
        );

        return new TextDecoder().decode(plainBuf);
    } catch (err) {
        console.error("Decrypt error:", err, msg);
        return "[Decryption failed]";
    }
}

// =====================================================
// FILE SHARING (Encrypt / Decrypt)
// =====================================================
async function sha256HexOfArrayBuffer(ab) {
    const hashBuf = await crypto.subtle.digest("SHA-256", ab);
    const hashArr = Array.from(new Uint8Array(hashBuf));
    return hashArr.map(b => b.toString(16).padStart(2, "0")).join("");
}

async function encryptFileForChat(file, receiver) {
    const receiverPub = await getPublicKeyForUser(receiver);
    const senderPub = await getPublicKeyForUser(username);

    const fileBuf = await file.arrayBuffer();
    const sha256 = await sha256HexOfArrayBuffer(fileBuf);

    const aesKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const cipherBuf = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        fileBuf
    );

    const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);

    const encKeyReceiver = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, receiverPub, rawAesKey);
    const encKeySender = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, senderPub, rawAesKey);

    return {
        filename: file.name,
        mime_type: file.type || "application/octet-stream",
        size_bytes: file.size,
        sha256,
        encrypted_file: arrayBufferToB64(cipherBuf),
        encrypted_aes_key_receiver: arrayBufferToB64(encKeyReceiver),
        encrypted_aes_key_sender: arrayBufferToB64(encKeySender),
        iv: bytesToB64(iv)
    };
}

async function decryptFileRecord(rec) {
    const ivBytes = b64ToBytes(rec.iv);
    const cipherAb = b64ToArrayBuffer(rec.encrypted_file);

    const encKeyB64 =
        rec.receiver === username
            ? rec.encrypted_aes_key_receiver
            : rec.encrypted_aes_key_sender;

    const encKeyBytes = b64ToBytes(encKeyB64);

    const rawAesKey = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        rsaPrivateKey,
        encKeyBytes
    );

    const aesKey = await crypto.subtle.importKey(
        "raw",
        rawAesKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    const plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes },
        aesKey,
        cipherAb
    );

    const hex = await sha256HexOfArrayBuffer(plainBuf);
    if (hex !== rec.sha256) {
        throw new Error("SHA256 mismatch (file tampered or corrupted).");
    }

    return plainBuf;
}

// ---------------------------
// UI: Messages & Conversation
// ---------------------------
function appendMessage(text, isOwn, time = Date.now()) {
    const div = document.createElement("div");
    div.className = "message-bubble " + (isOwn ? "sent" : "received");

    const msgText = document.createElement("div");
    msgText.textContent = text;

    const ts = document.createElement("div");
    ts.className = "message-timestamp";
    ts.textContent = formatTime(time);

    div.appendChild(msgText);
    div.appendChild(ts);

    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

function appendFileBubble(fileMeta, isOwn, time = Date.now()) {
    const div = document.createElement("div");
    div.className = "message-bubble " + (isOwn ? "sent" : "received");

    const title = document.createElement("div");
    title.style.fontWeight = "600";
    title.textContent = `📎 File: ${fileMeta.filename}`;

    const info = document.createElement("div");
    info.style.fontSize = "12px";
    info.style.opacity = "0.9";
    info.textContent = `${fileMeta.mime_type} • ${Math.round((fileMeta.size_bytes || 0) / 1024)} KB`;

    const ts = document.createElement("div");
    ts.className = "message-timestamp";
    ts.textContent = formatTime(time);

    const btn = document.createElement("button");
    btn.className = "button button-small";
    btn.type = "button";

    // If there is no id yet, disable download until we resolve it
    const hasId = !!fileMeta.id;
    btn.textContent = hasId ? "Download File" : "Saving...";
    btn.disabled = !hasId;

    // Store meta on the div for later update
    if (fileMeta.sha256) div.dataset.sha256 = fileMeta.sha256;
    if (fileMeta.filename) div.dataset.filename = fileMeta.filename;
    if (fileMeta.size_bytes) div.dataset.size = String(fileMeta.size_bytes);
    if (fileMeta.sender) div.dataset.sender = fileMeta.sender;
    if (fileMeta.receiver) div.dataset.receiver = fileMeta.receiver;

    btn.addEventListener("click", async () => {
        try {
            const id = fileMeta.id || div.dataset.fileId;
            if (!id) {
                showBanner("This file is still syncing. Wait 1 sec and try again.", true);
                return;
            }

            const resp = await fetch(`${API_BASE}/files/${id}`);
            const rec = await resp.json();

            if (!resp.ok) {
                showBanner(rec.error || "Failed to download file.", true);
                return;
            }

            if (rec.sender !== username && rec.receiver !== username) {
                showBanner("Not allowed to decrypt this file.", true);
                return;
            }

            const plainBuf = await decryptFileRecord(rec);
            const blob = new Blob([plainBuf], { type: rec.mime_type || "application/octet-stream" });

            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = rec.filename || "download.bin";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            showBanner("File decrypted and downloaded.");
        } catch (e) {
            console.error(e);
            showBanner("File decryption failed.", true);
        }
    });

    div.appendChild(title);
    div.appendChild(info);
    div.appendChild(ts);
    div.appendChild(btn);

    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;

    // Track pending bubble if it lacks id (so we can enable it later)
    if (!fileMeta.id && fileMeta.sha256) {
        const key = `${fileMeta.sender || ""}|${fileMeta.receiver || ""}|${fileMeta.sha256}|${fileMeta.filename || ""}|${fileMeta.size_bytes || ""}`;
        pendingFileBubbles.set(key, { div, btn, meta: fileMeta });
    }
}

// After a file is sent/received, resolve its DB id and enable download 
async function resolveFileIdAndEnableDownload({ sender, receiver, sha256, filename, size_bytes }) {
    if (!currentChatUser) return;

    try {
        // Pull latest file history and find best match
        const fResp = await fetch(
            `${API_BASE}/files?user1=${encodeURIComponent(username)}&user2=${encodeURIComponent(currentChatUser)}`
        );
        const fData = fResp.ok ? await fResp.json() : { files: [] };
        const files = fData.files || [];

        // Find matching file record
        const matches = files
            .filter(f =>
                f &&
                f.sha256 === sha256 &&
                f.filename === filename &&
                Number(f.size_bytes || 0) === Number(size_bytes || 0) &&
                f.sender === sender &&
                f.receiver === receiver
            )
            .sort((a, b) => parseTimestamp(b.timestamp) - parseTimestamp(a.timestamp));

        const best = matches[0];
        if (!best || !best.id) return;

        const key = `${sender}|${receiver}|${sha256}|${filename}|${size_bytes}`;
        const entry = pendingFileBubbles.get(key);
        if (!entry) return;

        // Update bubble with id + enable button
        entry.div.dataset.fileId = String(best.id);
        entry.btn.textContent = "Download File";
        entry.btn.disabled = false;

        // Also update in-memory meta (so click handler uses it)
        entry.meta.id = best.id;

        pendingFileBubbles.delete(key);
    } catch (e) {
        console.warn("Could not resolve file id yet:", e);
    }
}

async function setActiveChatUser(otherUser) {
    currentChatUser = otherUser;

    userListEl.querySelectorAll(".user-item").forEach(el => {
        el.classList.toggle("active", el.dataset.username === otherUser);
    });

    messagesEl.innerHTML = "";
    await loadConversationHistory(otherUser);

    messageForm.style.display = "flex";
}

async function loadConversationHistory(otherUser) {
    try {
        const resp = await fetch(
            `${API_BASE}/messages?user1=${encodeURIComponent(username)}&user2=${encodeURIComponent(otherUser)}`
        );
        if (!resp.ok) return;

        const data = await resp.json();
        const msgs = data.messages || [];

        const remoteMessages = [];
        for (const msg of msgs) {
            // only decrypt messages NOT sent by me (because my AES key is encrypted for receiver)
            if (msg.sender === username) continue;
            const text = await decryptMessage(msg);
            const t = parseTimestamp(msg.timestamp);
            remoteMessages.push({ kind: "text", sender: msg.sender, text, time: t });
        }

        const localMessages = getLocalMessages(username, otherUser).map(m => ({
            kind: "text",
            sender: username,
            text: m.text,
            time: m.time || Date.now()
        }));

        // FILE history (REST)
        const fResp = await fetch(
            `${API_BASE}/files?user1=${encodeURIComponent(username)}&user2=${encodeURIComponent(otherUser)}`
        );
        const fData = fResp.ok ? await fResp.json() : { files: [] };
        const files = (fData.files || []).map(f => ({
            kind: "file",
            sender: f.sender,
            file: f,
            time: parseTimestamp(f.timestamp)
        }));

        const merged = remoteMessages.concat(localMessages).concat(files);
        merged.sort((a, b) => (a.time || 0) - (b.time || 0));

        for (const item of merged) {
            if (item.kind === "text") {
                appendMessage(item.text, item.sender === username, item.time);
            } else if (item.kind === "file") {
                appendFileBubble(item.file, item.sender === username, item.time);
            }
        }
    } catch (err) {
        console.error("History error:", err);
    }
}

// ---------------------------
// SINGLE Send Button: sends text OR file
// ---------------------------
async function handleSendMessage(evt) {
    evt.preventDefault();

    if (!currentChatUser) {
        showBanner("Select or search a user to chat with first.", true);
        return;
    }

    const text = (messageInput.value || "").trim();

    // If nothing to send, show feedback
    if (!text && !selectedFile) {
        showBanner("Type a message or attach a file.", true);
        return;
    }

    try {
        // 1) Send text (if any)
        if (text) {
            const payload = await encryptForReceiver(text, currentChatUser);

            ws.send(JSON.stringify({
                type: "message",
                sender: username,
                receiver: currentChatUser,
                encrypted_message: payload.encrypted_message,
                encrypted_aes_key: payload.encrypted_aes_key,
                iv: payload.iv
            }));

            appendMessage(text, true, Date.now()); // show local time instantly
            addLocalOutgoingMessage(username, currentChatUser, text);
            messageInput.value = "";
        }

        // 2) Send file (if selected)
        if (selectedFile) {
            const payload = await encryptFileForChat(selectedFile, currentChatUser);

            ws.send(JSON.stringify({
                type: "file",
                sender: username,
                receiver: currentChatUser,
                ...payload
            }));

            // show bubble immediately (id resolves automatically without refresh)
            appendFileBubble({
                id: null,
                sender: username,
                receiver: currentChatUser,
                filename: payload.filename,
                mime_type: payload.mime_type,
                size_bytes: payload.size_bytes,
                sha256: payload.sha256
            }, true, Date.now()); // show local time instantly

            // Try to resolve DB id shortly after sending (so download works immediately)
            setTimeout(() => {
                resolveFileIdAndEnableDownload({
                    sender: username,
                    receiver: currentChatUser,
                    filename: payload.filename,
                    size_bytes: payload.size_bytes,
                    sha256: payload.sha256
                });
            }, 400);

            showBanner("Sent (encrypted).");

            selectedFile = null;
            fileInput.value = "";
        }

    } catch (err) {
        console.error("Send error:", err);
        showBanner("Failed to send.", true);
    }
}

// ---------------------------
// FILE attach handlers
// ---------------------------
function handleAttachClick() {
    if (!currentChatUser) {
        showBanner("Select a user first, then attach a file.", true);
        return;
    }
    fileInput.click();
}

function handleFileSelected() {
    selectedFile = fileInput.files && fileInput.files[0] ? fileInput.files[0] : null;
    if (!selectedFile) return;

    const maxBytes = 5 * 1024 * 1024;
    if (selectedFile.size > maxBytes) {
        showBanner("File too large (max 5MB for demo).", true);
        selectedFile = null;
        fileInput.value = "";
        return;
    }

    showBanner(`Selected: ${selectedFile.name}`);
}

// ---------------------------
// Logout
// ---------------------------
function handleLogout() {
    sessionStorage.clear();
    window.location.href = "login.html";
}

// ---------------------------
// Init Everything
// ---------------------------
document.addEventListener("DOMContentLoaded", async () => {
    // allow sending file-only even if HTML has required attribute
    if (messageInput) messageInput.required = false;

    const ok = await initSessionAndKeys();
    if (!ok) return;

    // Sidebar populates only via Search or incoming WS traffic
    initWebSocket();

    if (logoutButton) logoutButton.addEventListener("click", handleLogout);
    if (userSearchButton) userSearchButton.addEventListener("click", handleUserSearch);
    if (messageForm) messageForm.addEventListener("submit", handleSendMessage);

    if (attachFileButton) attachFileButton.addEventListener("click", handleAttachClick);
    if (fileInput) fileInput.addEventListener("change", handleFileSelected);
});
