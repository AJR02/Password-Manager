CipherNest: Secure Password Vault

A password manager that runs in the browser as a single HTML file (index-v2.html). No server or database needed.

Features
Master password lock screen
Pages for Passwords, Secure Notes, Sharing Center, Security Dashboard, Emergency Contacts and Trash
Add, edit and delete on every page
Card-based UI with a sidebar, live clock and last login
Security

Passwords are protected with the Web Crypto API:

PBKDF2 (SHA-256, 100,000 iterations) to derive keys from the master password
HMAC to hide domain names
AES-GCM to encrypt passwords
SHA-256 checksum to detect tampering