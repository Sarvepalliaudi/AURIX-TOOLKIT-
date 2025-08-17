# Aurix Cybersecurity Toolkit
check it here
https://aurix-toolkit.onrender.com

Aurix is a modern, all-in-one cybersecurity toolkit built with Python and Flask. It features:
- Password Strength Checker
- File Integrity Checker
- Port Scanner
- Encryption/Decryption Tool
- ZIP Password Cracker
- Network Packet Sniffer

## File Explorer (Project Structure)

```
.
├── app.py
├── README.md
├── static/
│   ├── aurix.css
│   └── aurix_logo.svg
├── templates/
│   ├── dashboard.html
│   ├── encryption_tool.html
│   ├── file_integrity.html
│   ├── index.html
│   ├── packet_sniffer.html
│   ├── password_strength.html
│   ├── port_scanner.html
│   └── zip_cracker.html
├── uploads/   # (empty, used for file uploads)
```

## Features
- Beautiful, responsive web UI
- Works on PC and mobile
- Easy to use, educational, and powerful

## Installation & Usage

1. **Clone or download this repository.**
2. **Install requirements:**
   ```sh
   pip install flask scapy pycryptodome werkzeug zipfile36
   ```
3. **Run the app:**
   ```sh
   python app.py
   ```
4. **Open your browser at:**
   [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Toolkit Pages
- `/` — Home (index)
- `/dashboard` — Dashboard
- `/password-strength` — Password Strength Checker
- `/file-integrity` — File Integrity Checker
- `/port-scanner` — Port Scanner
- `/encryption-tool` — Encryption/Decryption Tool
- `/zip-cracker` — ZIP Password Cracker
- `/packet-sniffer` — Network Packet Sniffer

## Author
- AUDI SIVA BHANUVARDHAN SARVEPALLI  
  DHANALAKSMI SRINIVASAN UNIVERSITY, TRICHY, 621 112
- 2025

## About Me
I am passionate about cybersecurity and Python development. Aurix is my first full-featured toolkit, designed to help others learn and secure their digital world. Enjoy using Aurix!
