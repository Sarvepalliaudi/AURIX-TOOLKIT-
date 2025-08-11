
# =============================
# 1. IMPORTS & FLASK APP SETUP
# =============================
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import re
import socket
import zipfile
from base64 import b64encode, b64decode
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from scapy.all import sniff, IP, TCP, UDP

app = Flask(__name__)

# =============================
# 0. MAIN MENU, DASHBOARD, AND TOOL ROUTES
# =============================

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/password-strength', methods=['GET', 'POST'])
def password_strength():
    result = None
    password = ''
    if request.method == 'POST':
        password = request.form.get('password', '')
        # Simple password strength logic (for demo)
        if len(password) >= 12 and any(c.isdigit() for c in password) and any(c.isupper() for c in password) and any(c in '!@#$%^&*()_+-=' for c in password):
            result = 'Very Strong'
        elif len(password) >= 8 and any(c.isdigit() for c in password) and any(c.isupper() for c in password):
            result = 'Strong'
        elif len(password) >= 6:
            result = 'Medium'
        else:
            result = 'Weak'
    return render_template('password_strength.html', result=result, password=password)

@app.route('/file-integrity', methods=['GET', 'POST'])
def file_integrity():
    hash_value = None
    algo = 'sha256'
    if request.method == 'POST':
        file = request.files.get('file')
        algo = request.form.get('algo', 'sha256')
        if file:
            data = file.read()
            if algo == 'md5':
                hash_value = hashlib.md5(data).hexdigest()
            elif algo == 'sha1':
                hash_value = hashlib.sha1(data).hexdigest()
            else:
                hash_value = hashlib.sha256(data).hexdigest()
    return render_template('file_integrity.html', hash_value=hash_value, algo=algo)

@app.route('/port-scanner', methods=['GET', 'POST'])
def port_scanner():
    result = None
    target = ''
    ports = ''
    if request.method == 'POST':
        target = request.form.get('target', '')
        ports = request.form.get('ports', '')
        open_ports = []
        try:
            port_list = []
            for part in ports.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    port_list.extend(range(start, end+1))
                else:
                    port_list.append(int(part))
            for port in port_list:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((target, port)) == 0:
                        open_ports.append(port)
            result = open_ports if open_ports else []
        except Exception as e:
            result = f"Error: {e}"
    return render_template('port_scanner.html', result=result, target=target, ports=ports)
# 6. ENCRYPTION/DECRYPTION TOOL
# =============================
@app.route('/encryption-tool', methods=['GET', 'POST'])
def encryption_tool():
    result = None
    text = ''
    key = ''
    mode = 'encrypt'
    if request.method == 'POST':
        text = request.form.get('text', '')
        key = request.form.get('key', '')
        mode = request.form.get('mode', 'encrypt')
        if text and key:
            try:
                key_bytes = key.encode('utf-8').ljust(16, b'0')[:16]
                cipher = AES.new(key_bytes, AES.MODE_ECB)
                if mode == 'encrypt':
                    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), 16))
                    result = b64encode(ct_bytes).decode('utf-8')
                else:
                    pt = unpad(cipher.decrypt(b64decode(text)), 16)
                    result = pt.decode('utf-8')
            except Exception as e:
                result = f"Error: {e}"
    return render_template('encryption_tool.html', result=result, text=text, key=key, mode=mode)

# =============================
# 7. ZIP PASSWORD CRACKER
# =============================
@app.route('/zip-cracker', methods=['GET', 'POST'])
def zip_cracker():
    result = None
    filename = None
    if request.method == 'POST':
        file = request.files.get('zipfile')
        wordlist = request.form.get('wordlist', '')
        if file and wordlist:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            passwords = [w.strip() for w in wordlist.splitlines() if w.strip()]
            try:
                with zipfile.ZipFile(filepath) as zf:
                    for pwd in passwords:
                        try:
                            zf.extractall(pwd=pwd.encode('utf-8'))
                            result = f"Password found: {pwd}"
                            break
                        except Exception:
                            continue
                    if not result:
                        result = "Password not found in wordlist."
            except Exception as e:
                result = f"Error: {e}"
    return render_template('zip_cracker.html', result=result, filename=filename)

# =============================
# 8. NETWORK PACKET SNIFFER
# =============================
@app.route('/packet-sniffer', methods=['GET', 'POST'])
def packet_sniffer():
    result = None
    count = 10
    if request.method == 'POST':
        try:
            count = int(request.form.get('count', 10))
            packets = sniff(count=count, timeout=5)
            summary = []
            for pkt in packets:
                if IP in pkt:
                    proto = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'Other'
                    summary.append(f"{pkt[IP].src} -> {pkt[IP].dst} ({proto})")
            result = summary if summary else ["No packets captured."]
        except Exception as e:
            result = [f"Error: {e}"]
    return render_template('packet_sniffer.html', result=result, count=count)

# =============================
# 9. MAIN ENTRY POINT
# =============================
if __name__ == '__main__':
    app.run(debug=True)
