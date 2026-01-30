// admin.js - Admin Dashboard Logic
// Handles viewing encrypted message logs, filtering, and CSV export

const API_URL = 'http://localhost:5000';

let allLogs = [];      // message logs
let allFileLogs = [];  // file logs
let currentFilter = { sender: '', receiver: '' };

// ---------------------------
// LocalStorage auto-clear when DB is reset
// (Detects "was non-empty before, now empty" => likely DB deleted)
// ---------------------------
const DB_STATE_KEY = "securechat:db_state"; // "nonempty" | "empty"

function clearSecureChatLocalStorage() {
    // Remove ONLY SecureChat local message cache keys
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (!k) continue;
        if (k.startsWith("securechat:v1:")) keysToRemove.push(k);
    }
    keysToRemove.forEach(k => localStorage.removeItem(k));
}

function detectAndMaybeClearLocalStorage(combinedCount) {
    const prevState = localStorage.getItem(DB_STATE_KEY); // null | "nonempty" | "empty"
    const nowState = combinedCount > 0 ? "nonempty" : "empty";

    // If it used to have logs and now it's empty, DB likely got deleted/recreated.
    if (prevState === "nonempty" && nowState === "empty") {
        clearSecureChatLocalStorage();
        showBanner("Detected fresh database. Cleared cached local messages.", "success");
    }

    localStorage.setItem(DB_STATE_KEY, nowState);
}

document.addEventListener('DOMContentLoaded', async function() {
    const token = sessionStorage.getItem('token');
    const role = sessionStorage.getItem('role');

    if (!token) {
        window.location.href = 'login.html';
        return;
    }

    if (role !== 'admin') {
        showBanner('Admin access required', 'error');
        setTimeout(() => {
            window.location.href = 'chat.html';
        }, 2000);
        return;
    }

    await loadLogs();
    await loadFileLogs();

    populateFilters();
    updateStatistics();
    setupEventListeners();
});

async function loadLogs(senderFilter = '', receiverFilter = '') {
    try {
        const token = sessionStorage.getItem('token');

        let url = `${API_URL}/admin/logs`;
        const params = new URLSearchParams();

        if (senderFilter) params.append('sender', senderFilter);
        if (receiverFilter) params.append('receiver', receiverFilter);

        if (params.toString()) url += '?' + params.toString();

        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) throw new Error('Failed to load logs');

        const data = await response.json();
        allLogs = data.logs || [];

        displayCombinedLogs();
        updateStatistics();

    } catch (error) {
        console.error('Error loading logs:', error);
        showBanner('Failed to load logs', 'error');
    }
}

async function loadFileLogs(senderFilter = '', receiverFilter = '') {
    try {
        const token = sessionStorage.getItem('token');

        let url = `${API_URL}/admin/file-logs`;
        const params = new URLSearchParams();

        if (senderFilter) params.append('sender', senderFilter);
        if (receiverFilter) params.append('receiver', receiverFilter);

        if (params.toString()) url += '?' + params.toString();

        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) throw new Error('Failed to load file logs');

        const data = await response.json();
        allFileLogs = data.logs || [];

        displayCombinedLogs();
        updateStatistics();

    } catch (error) {
        console.error('Error loading file logs:', error);
        showBanner('Failed to load file logs', 'error');
    }
}

function displayCombinedLogs() {
    const tbody = document.getElementById('logs-tbody');
    tbody.innerHTML = '';

    const combined = [];

    // Normalize message rows
    (allLogs || []).forEach(m => {
        combined.push({
            type: "message",
            id: m.id,
            sender: m.sender,
            receiver: m.receiver,
            filename: "",
            filesize: "",
            encrypted_payload: m.encrypted_message,
            encrypted_aes_key: m.encrypted_aes_key,
            iv: m.iv || "",
            timestamp: m.timestamp
        });
    });

    // Normalize file rows
    (allFileLogs || []).forEach(f => {
        const sizeBytes =
            (typeof f.size_bytes === "number" ? f.size_bytes : null) ??
            (typeof f.filesize === "number" ? f.filesize : null) ??
            0;

        combined.push({
            type: "file",
            id: f.id,
            sender: f.sender,
            receiver: f.receiver,
            filename: f.filename || "",
            filesize: `${Math.round((sizeBytes || 0) / 1024)} KB`,
            encrypted_payload: f.encrypted_file,
            //  backend stores split keys; show receiver key (or fallback)
            encrypted_aes_key:
                f.encrypted_aes_key_receiver ||
                f.encrypted_aes_key_sender ||
                f.encrypted_aes_key ||
                "",
            iv: f.iv,
            timestamp: f.timestamp
        });
    });

    // Sort newest first (admin view)
    combined.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // detect DB reset and clear cached local messages
    detectAndMaybeClearLocalStorage(combined.length);

    if (combined.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" class="empty-state">No logs found</td></tr>';
        return;
    }

    combined.forEach(log => {
        const row = document.createElement('tr');

        const cells = [
            log.id,
            log.sender,
            log.receiver,
            log.type,
            log.filename,
            log.filesize,
            log.encrypted_payload,
            log.encrypted_aes_key,
            log.iv,
            new Date(log.timestamp).toLocaleString()
        ];

        cells.forEach((val, idx) => {
            const td = document.createElement('td');
            td.textContent = val || "";
            if (idx === 6 || idx === 7 || idx === 8) td.title = val || "";
            row.appendChild(td);
        });

        tbody.appendChild(row);
    });
}

function populateFilters() {
    const combined = (allLogs || []).concat(allFileLogs || []);

    const senders = [...new Set(combined.map(log => log.sender))].sort();
    const receivers = [...new Set(combined.map(log => log.receiver))].sort();

    const senderFilter = document.getElementById('sender-filter');
    senderFilter.innerHTML = '<option value="">All Senders</option>';
    senders.forEach(sender => {
        const option = document.createElement('option');
        option.value = sender;
        option.textContent = sender;
        senderFilter.appendChild(option);
    });

    const receiverFilter = document.getElementById('receiver-filter');
    receiverFilter.innerHTML = '<option value="">All Receivers</option>';
    receivers.forEach(receiver => {
        const option = document.createElement('option');
        option.value = receiver;
        option.textContent = receiver;
        receiverFilter.appendChild(option);
    });
}

function updateStatistics() {
    const combined = (allLogs || []).concat(allFileLogs || []);

    document.getElementById('total-messages').textContent = combined.length;

    const uniqueSenders = new Set(combined.map(log => log.sender));
    document.getElementById('unique-senders').textContent = uniqueSenders.size;

    const uniqueReceivers = new Set(combined.map(log => log.receiver));
    document.getElementById('unique-receivers').textContent = uniqueReceivers.size;
}

function downloadCSV() {
    const combined = [];

    (allLogs || []).forEach(m => {
        combined.push([
            "message",
            m.id, m.sender, m.receiver,
            `"${m.encrypted_message}"`,
            `"${m.encrypted_aes_key}"`,
            `"${m.iv || ""}"`,
            "", "", "",
            new Date(m.timestamp).toISOString()
        ]);
    });

    (allFileLogs || []).forEach(f => {
        const aesKey =
            f.encrypted_aes_key_receiver ||
            f.encrypted_aes_key_sender ||
            f.encrypted_aes_key ||
            "";

        combined.push([
            "file",
            f.id, f.sender, f.receiver,
            `"${f.encrypted_file}"`,
            `"${aesKey}"`,
            `"${f.iv}"`,
            `"${f.filename}"`,
            `"${f.mime_type}"`,
            f.size_bytes,
            new Date(f.timestamp).toISOString()
        ]);
    });

    if (combined.length === 0) {
        showBanner('No logs to download', 'error');
        return;
    }

    let csv = 'TYPE,ID,Sender,Receiver,Encrypted Payload,Encrypted AES Key,IV,Filename,MIME,Filesize,Timestamp\n';
    combined.forEach(r => { csv += r.join(',') + '\n'; });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = `secure_logs_${new Date().toISOString()}.csv`;

    document.body.appendChild(link);
    link.click();

    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);

    showBanner('CSV downloaded successfully', 'success');
}

function setupEventListeners() {
    document.getElementById('apply-filter').addEventListener('click', async function() {
        const sender = document.getElementById('sender-filter').value;
        const receiver = document.getElementById('receiver-filter').value;

        currentFilter = { sender, receiver };

        document.getElementById('logs-tbody').innerHTML =
            '<tr><td colspan="10" class="loading">Loading filtered logs...</td></tr>';

        await loadLogs(sender, receiver);
        await loadFileLogs(sender, receiver);

        populateFilters();
        showBanner('Filter applied', 'success');
    });

    document.getElementById('clear-filter').addEventListener('click', async function() {
        document.getElementById('sender-filter').value = '';
        document.getElementById('receiver-filter').value = '';

        currentFilter = { sender: '', receiver: '' };

        document.getElementById('logs-tbody').innerHTML =
            '<tr><td colspan="10" class="loading">Loading all logs...</td></tr>';

        await loadLogs();
        await loadFileLogs();

        populateFilters();
        showBanner('Filter cleared', 'success');
    });

    document.getElementById('download-csv').addEventListener('click', function() {
        downloadCSV();
    });

    document.getElementById('logout-button').addEventListener('click', function() {
        sessionStorage.clear();
        window.location.href = 'login.html';
    });
}

function showBanner(message, type) {
    const banner = document.getElementById('message-banner');
    banner.textContent = message;
    banner.className = `banner banner-${type}`;
    banner.style.display = 'block';

    setTimeout(() => {
        banner.style.display = 'none';
    }, 5000);
}
