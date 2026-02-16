from flask import Flask, render_template, request
import re
import random
import string
import hashlib
import base64
import math
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import threading
import webbrowser
import os
import subprocess

app = Flask(__name__)

# Fixed Internal Server Error issues

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

# Password Entropy Calculator
def calculate_password_entropy(password):
    if not password:
        return 0
    
    # Calculate character set size
    char_sets = 0
    if re.search(r"[a-z]", password):
        char_sets += 26
    if re.search(r"[A-Z]", password):
        char_sets += 26
    if re.search(r"[0-9]", password):
        char_sets += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        char_sets += 32
    
    # Calculate entropy
    entropy = len(password) * math.log2(char_sets) if char_sets > 0 else 0
    return round(entropy, 2)

# Advanced Password Generator with Custom Options
def generate_custom_password(length=16, include_uppercase=True, include_lowercase=True, 
                          include_digits=True, include_special=True, exclude_ambiguous=True):
    if length < 8:
        length = 8
    
    char_sets = []
    if include_uppercase:
        char_sets.append(string.ascii_uppercase)
    if include_lowercase:
        char_sets.append(string.ascii_lowercase)
    if include_digits:
        char_sets.append(string.digits)
    if include_special:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if exclude_ambiguous:
            special_chars = special_chars.replace('0', '').replace('O', '').replace('l', '').replace('1', '').replace('I', '')
        char_sets.append(special_chars)
    
    if not char_sets:
        return "Error: At least one character type must be selected"
    
    all_chars = ''.join(char_sets)
    password = []
    
    # Ensure at least one character from each selected set
    for char_set in char_sets:
        password.append(random.choice(char_set))
    
    # Fill the rest
    for _ in range(length - len(password)):
        password.append(random.choice(all_chars))
    
    random.shuffle(password)
    return ''.join(password)

# SHA256 Hashing
def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Base64 Encoding/Decoding
def base64_encode(text):
    return base64.b64encode(text.encode()).decode()

def base64_decode(text):
    try:
        return base64.b64decode(text.encode()).decode()
    except Exception:
        return "Invalid Base64 input"

# Password Hashing (Simulated bcrypt-like)
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    
    # Use PBKDF2 for secure password hashing
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
    )
    hashed = kdf.derive(password.encode())
    return f"{salt}:{hashed.hex()}"

def verify_password(password, hashed_password):
    try:
        salt, hash_hex = hashed_password.split(':')
        new_hash = hash_password(password, salt)
        return new_hash == hashed_password
    except Exception:
        return False

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
    entropy = None
    sha256_result = None
    base64_encoded = None
    base64_decoded = None
    hashed_password = None
    password_verified = None
    custom_password = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "check":
            pwd = request.form.get("password", "")
            result, tips, suggested_password = check_password_strength(pwd)
            entropy = calculate_password_entropy(pwd)

        elif action == "enc":
            msg = request.form.get("message", "")
            encrypted = cipher_suite.encrypt(msg.encode()).decode()

        elif action == "dec":
            enc_msg = request.form.get("enc_message", "")
            try:
                decrypted = cipher_suite.decrypt(enc_msg.encode()).decode()
            except Exception:
                decrypted = "Invalid key or ciphertext."

        elif action == "generate_custom":
            length = int(request.form.get("length", 16))
            include_uppercase = request.form.get("include_uppercase") == "on"
            include_lowercase = request.form.get("include_lowercase") == "on"
            include_digits = request.form.get("include_digits") == "on"
            include_special = request.form.get("include_special") == "on"
            exclude_ambiguous = request.form.get("exclude_ambiguous") == "on"
            custom_password = generate_custom_password(length, include_uppercase, include_lowercase, 
                                              include_digits, include_special, exclude_ambiguous)

        elif action == "sha256":
            text = request.form.get("sha256_text", "")
            sha256_result = sha256_hash(text)

        elif action == "base64_encode":
            text = request.form.get("base64_text", "")
            base64_encoded = base64_encode(text)

        elif action == "base64_decode":
            text = request.form.get("base64_decode_text", "")
            base64_decoded = base64_decode(text)

        elif action == "hash_password":
            pwd = request.form.get("hash_pwd", "")
            hashed_password = hash_password(pwd)

        elif action == "verify_password":
            pwd = request.form.get("verify_pwd", "")
            hashed_pwd = request.form.get("hashed_pwd", "")
            password_verified = verify_password(pwd, hashed_pwd)

    return render_template(
        "index.html",
        result=result,
        tips=tips,
        encrypted=encrypted,
        decrypted=decrypted,
        show_key=show_key,
        suggested_password=suggested_password,
        entropy=entropy,
        sha256_result=sha256_result,
        base64_encoded=base64_encoded,
        base64_decoded=base64_decoded,
        hashed_password=hashed_password,
        password_verified=password_verified,
        custom_password=custom_password
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