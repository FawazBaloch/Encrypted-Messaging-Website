🔐 Secure SMS Encryption Messaging System

This project implements a secure web-based real-time messaging system with end-to-end encryption (E2EE) using modern cryptographic techniques. Messages and files are encrypted on the client side, transmitted securely, and stored only in encrypted form on the server.

📄 Important:
Please refer to Secure_SMS_Installation_Guide.docx for full installation, configuration, and execution instructions.

📌 Project Overview

The Secure SMS system is a full-stack web application designed to ensure confidentiality, integrity, and privacy of user communications. The system combines RSA-2048 and AES-256-GCM encryption, real-time WebSocket communication, and a Flask REST API backend.

This project was developed for academic and educational purposes to demonstrate applied cryptography, secure system design, and real-time communication.

✨ Key Features

🔒 Security Features

End-to-End Encryption (E2EE)
AES-256-GCM for message & file encryption
RSA-2048 for secure key exchange
Password-protected private keys
Bcrypt password hashing
JWT-based authentication
Message integrity verification (SHA-256)

💬 Messaging Features

Real-time messaging using WebSockets
Encrypted file sharing
Timestamps to prove real-time communication
No plaintext storage (messages or files)
Automatic key generation during registration

👨‍💼 Admin Capabilities

View encrypted logs (messages & files)
Filter by sender and receiver
Monitor timestamps
Admin cannot decrypt messages

🛠 Technology Stack

Backend
Python 3.8+
Flask (REST API)
WebSockets (Real-time communication)
SQLite (Local database)
bcrypt (Password hashing)
PyJWT (Authentication)
PyCryptodome (Cryptography)

Frontend
HTML5
CSS3
Vanilla JavaScript
Web Crypto API (Browser-native encryption)
Database
SQLite (secure_chat.db)
Encrypted storage of messages and files
Indexed for performance

📁 Project Structure
PROJECT_FILE/
│
├── backend/
│   ├── app.py                  # Flask REST API
│   ├── websocket_server.py     # WebSocket server
│   ├── crypto_utils.py         # RSA & AES utilities
│   ├── database.py             # SQLite DB logic
│   ├── requirements.txt        # Dependencies
│   └── database/
│       └── secure_chat.db      # SQLite database
│
├── frontend/
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── chat.html
│   ├── admin.html
│   ├── styles.css
│   ├── index.js
│   ├── register.js
│   ├── login.js
│   ├── chat.js
│   └── admin.js
│
├── README.md
└── Secure_SMS_Installation_Guide.docx

🚀 Running the Application (Summary)

Backend Servers (Two Terminals Required)

Terminal 1 – Flask API

cd backend
python app.py

Terminal 2 – WebSocket Server
cd backend
python websocket_server.py

Access the Application
Open a browser and navigate to:
http://localhost:5000

🔐 Encryption Architecture

Hybrid Encryption Model
AES-256-GCM encrypts message and file content
RSA-2048 encrypts the AES key per recipient
Each message/file uses a new AES session key
Private keys are encrypted using the user’s password
Client-Side Encryption
Encryption and decryption occur in the browser
Server never sees plaintext
Database stores encrypted payloads only

🗄 Database Notes

Database: secure_chat.db
Location: backend/database/
Contains:
Encrypted messages
Encrypted files
Public keys
Encrypted private keys
Timestamps and metadata
Viewing the Database
You may inspect the database using either:
SQLite CLI (after installing sqlite3 and adding it to PATH)
DB Browser for SQLite (recommended for visual inspection)

📄 Installation & Configuration

➡️ All installation, setup, and configuration steps are fully documented in:
📘 Secure_SMS_Installation_Guide.docx

This includes:
Environment setup
Dependency installation
Running backend services
Database inspection

🎓 Academic Notes

This project demonstrates:
Secure software engineering practices
Applied cryptography
Client-side encryption
Real-time systems
Database design & indexing
Authentication & authorization
Threat-aware system design

