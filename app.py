from flask import Flask, render_template, request
import re
import random
import string
from cryptography.fernet import Fernet
import threading
import webbrowser
import os
import subprocess

app = Flask(__name__)

# Password Strength Checker
def check_password_strength(password):
    strength = 0
    suggestions = []
    suggested_password = None

    if len(password) >= 12:
        strength += 2
    elif len(password) >= 8:
        strength += 1
    else:
        suggestions.append("Use at least 8–12 characters.")

    if re.search(r"[A-Z]", password):
        strength += 1
    else:
        suggestions.append("Add uppercase letters (A–Z).")

    if re.search(r"[a-z]", password):
        strength += 1
    else:
        suggestions.append("Add lowercase letters (a–z).")

    if re.search(r"[0-9]", password):
        strength += 1
    else:
        suggestions.append("Include digits (0–9).")

    if re.search(r"[@$!%*?&^#_+\-=\[\]{};:\\|,.<>/]", password):
        strength += 1
    else:
        suggestions.append("Use special characters (e.g., @ # &).")

    # Simple repetition/dictionary check (optional)
    if re.search(r"(password|1234|qwerty|admin)", password, re.IGNORECASE):
        suggestions.append("Avoid common words or sequences (e.g., 'password', '1234').")
        strength = max(strength - 1, 0)

    level = "Weak" if strength <= 2 else ("Medium" if strength <= 4 else "Strong")
    
    # Generate suggested password if weak or medium
    if level in ["Weak", "Medium"]:
        suggested_password = generate_strong_password()
    
    return level, suggestions, suggested_password

# Password Generator
def generate_strong_password(length=16):
    if length < 12:
        length = 12
    
    # Define character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special = "@$!%*?&^#_+-=[]{}|;:,.<>"
    
    # Ensure at least one character from each set
    password = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits),
        random.choice(special)
    ]
    
    # Fill the rest with random characters from all sets
    all_chars = uppercase + lowercase + digits + special
    for _ in range(length - 4):
        password.append(random.choice(all_chars))
    
    # Shuffle the password to avoid predictable patterns
    random.shuffle(password)
    
    return ''.join(password)

# Encryption (Fernet: AES-128 in CBC with HMAC)
key = Fernet.generate_key()
cipher_suite = Fernet(key)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    tips = []
    encrypted = None
    decrypted = None
    show_key = key.decode()
    suggested_password = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "check":
            pwd = request.form.get("password", "")
            result, tips, suggested_password = check_password_strength(pwd)

        if action == "enc":
            msg = request.form.get("message", "")
            encrypted = cipher_suite.encrypt(msg.encode()).decode()

        if action == "dec":
            enc_msg = request.form.get("enc_message", "")
            try:
                decrypted = cipher_suite.decrypt(enc_msg.encode()).decode()
            except Exception:
                decrypted = "Invalid key or ciphertext."

    return render_template(
        "index.html",
        result=result,
        tips=tips,
        encrypted=encrypted,
        decrypted=decrypted,
        show_key=show_key,
        suggested_password=suggested_password
    )



def _open_in_chrome(url):
    chrome_paths = [
        r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        r"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    ]
    for p in chrome_paths:
        if os.path.exists(p):
            try:
                subprocess.Popen([p, url])
                return
            except Exception:
                pass
    try:
        webbrowser.get('chrome').open_new_tab(url)
    except Exception:
        pass

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))