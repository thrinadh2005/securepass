from flask import Flask, render_template, request, Response
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
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
import hmac
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

rsa_private_key = None
rsa_public_key_pem = None

def rsa_generate_keys():
    global rsa_private_key, rsa_public_key_pem
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = rsa_private_key.public_key()
    from cryptography.hazmat.primitives import serialization
    rsa_public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return rsa_public_key_pem

def rsa_encrypt_message(message):
    global rsa_private_key
    if rsa_private_key is None:
        rsa_generate_keys()
    public_key = rsa_private_key.public_key()
    ciphertext = public_key.encrypt(
        message.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt_message(b64ciphertext):
    global rsa_private_key
    if rsa_private_key is None:
        return "RSA keys not generated"
    try:
        ciphertext = base64.b64decode(b64ciphertext.encode())
        plaintext = rsa_private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
    except Exception:
        return "Invalid RSA ciphertext"

def compute_digest(text, algorithm="SHA256"):
    algo = algorithm.upper()
    if algo == "SHA1":
        return hashlib.sha1(text.encode()).hexdigest()
    elif algo == "SHA256":
        return hashlib.sha256(text.encode()).hexdigest()
    elif algo == "SHA512":
        return hashlib.sha512(text.encode()).hexdigest()
    else:
        return "Unsupported algorithm"

def hmac_sha256(key_text, message_text):
    hm = hmac.new(key_text.encode(), message_text.encode(), hashlib.sha256)
    return hm.hexdigest()

def hmac_verify(key_text, message_text, provided_hex):
    calc = hmac_sha256(key_text, message_text)
    try:
        return hmac.compare_digest(calc, provided_hex.strip())
    except Exception:
        return False

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    tips = []
    encrypted = None
    decrypted = None
    suggested_password = None
    entropy = None
    sha256_result = None
    digest_result = None
    base64_encoded = None
    base64_decoded = None
    hashed_password = None
    password_verified = None
    custom_password = None
    rsa_public_key = None
    rsa_ciphertext = None
    rsa_plaintext = None
    hmac_result = None
    hmac_verified = None
    active_section = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "check":
            pwd = request.form.get("password", "")
            result, tips, suggested_password = check_password_strength(pwd)
            entropy = calculate_password_entropy(pwd)
            active_section = "password-strength"

        elif action == "enc":
            msg = request.form.get("message", "")
            encrypted = cipher_suite.encrypt(msg.encode()).decode()
            active_section = "encryption"

        elif action == "dec":
            enc_msg = request.form.get("enc_message", "")
            try:
                decrypted = cipher_suite.decrypt(enc_msg.encode()).decode()
            except Exception:
                decrypted = "Invalid key or ciphertext."
            active_section = "encryption"

        elif action == "generate_custom":
            length = int(request.form.get("length", 16))
            include_uppercase = request.form.get("include_uppercase") == "on"
            include_lowercase = request.form.get("include_lowercase") == "on"
            include_digits = request.form.get("include_digits") == "on"
            include_special = request.form.get("include_special") == "on"
            exclude_ambiguous = request.form.get("exclude_ambiguous") == "on"
            custom_password = generate_custom_password(length, include_uppercase, include_lowercase, 
                                              include_digits, include_special, exclude_ambiguous)
            active_section = "password-generator"

        elif action == "sha256":
            text = request.form.get("sha256_text", "")
            sha256_result = sha256_hash(text)
            active_section = "hashing-tools"

        elif action == "digest":
            text = request.form.get("digest_text", "")
            algo = request.form.get("digest_algo", "SHA256")
            digest_result = compute_digest(text, algo)
            active_section = "hashing-tools"

        elif action == "hmac_generate":
            key_text = request.form.get("hmac_key", "")
            msg_text = request.form.get("hmac_message", "")
            hmac_result = hmac_sha256(key_text, msg_text)
            active_section = "hashing-tools"

        elif action == "hmac_verify":
            key_text = request.form.get("vhmac_key", "")
            msg_text = request.form.get("vhmac_message", "")
            provided_hex = request.form.get("vhmac_provided", "")
            hmac_verified = hmac_verify(key_text, msg_text, provided_hex)
            active_section = "hashing-tools"

        elif action == "base64_encode":
            text = request.form.get("base64_text", "")
            base64_encoded = base64_encode(text)
            active_section = "encoding-tools"

        elif action == "base64_decode":
            text = request.form.get("base64_decode_text", "")
            base64_decoded = base64_decode(text)
            active_section = "encoding-tools"

        elif action == "hash_password":
            pwd = request.form.get("hash_pwd", "")
            hashed_password = hash_password(pwd)
            active_section = "hashing-tools"

        elif action == "verify_password":
            pwd = request.form.get("verify_pwd", "")
            hashed_pwd = request.form.get("hashed_pwd", "")
            password_verified = verify_password(pwd, hashed_pwd)
            active_section = "hashing-tools"

        elif action == "rsa_generate":
            rsa_public_key = rsa_generate_keys()
            active_section = "encryption"

        elif action == "rsa_encrypt":
            msg = request.form.get("rsa_message", "")
            rsa_ciphertext = rsa_encrypt_message(msg)
            active_section = "encryption"

        elif action == "rsa_decrypt":
            enc_b64 = request.form.get("rsa_ciphertext", "")
            rsa_plaintext = rsa_decrypt_message(enc_b64)
            active_section = "encryption"

    return render_template(
        "index.html",
        result=result,
        tips=tips,
        encrypted=encrypted,
        decrypted=decrypted,
        suggested_password=suggested_password,
        entropy=entropy,
        sha256_result=sha256_result,
        digest_result=digest_result,
        base64_encoded=base64_encoded,
        base64_decoded=base64_decoded,
        hashed_password=hashed_password,
        password_verified=password_verified,
        custom_password=custom_password,
        rsa_public_key=rsa_public_key,
        rsa_ciphertext=rsa_ciphertext,
        rsa_plaintext=rsa_plaintext,
        hmac_result=hmac_result,
        hmac_verified=hmac_verified,
        active_section=active_section
    )


@app.route("/download/tools-doc", methods=["GET"])
def download_tools_doc():
    doc = []
    doc.append("# SecurePass Cryptography Tools Guide")
    doc.append("")
    doc.append("## Overview")
    doc.append("SecurePass provides a hub of cryptography and security tools for analysis, hashing, encoding, and encryption.")
    doc.append("")
    doc.append("## Password Strength Checker")
    doc.append("- Evaluates presence of uppercase, lowercase, digits, special characters")
    doc.append("- Estimates entropy: entropy = length × log2(character_set_size)")
    doc.append("- Suggests improvements and generates a strong password when weak/medium")
    doc.append("Example: Enter 'P@ssw0rd123!' and check strength; view entropy and tips")
    doc.append("")
    doc.append("## Advanced Password Generator")
    doc.append("- Custom length (8–64)")
    doc.append("- Toggle character sets; ensures at least one from each selected type")
    doc.append("Example: Length=16, include upper/lower/digits/special → copy generated")
    doc.append("")
    doc.append("## Hashing Tools")
    doc.append("### PBKDF2 (Secure Password Hash)")
    doc.append("- Algorithm: PBKDF2-HMAC-SHA256, 100,000 iterations, 32 bytes")
    doc.append("- Format: salt:hash_hex")
    doc.append("Example: Hash a password and verify by providing the same salt:hash")
    doc.append("")
    doc.append("### Digest (SHA1 / SHA256 / SHA512)")
    doc.append("- Algorithms: hashlib SHA1/SHA256/SHA512")
    doc.append("Example: Choose SHA512, enter text, copy hex digest")
    doc.append("")
    doc.append("### HMAC-SHA256")
    doc.append("- Algorithm: HMAC with SHA256")
    doc.append("- Generate and verify using a shared key")
    doc.append("Example: Key='secret', Message='hello', compute HMAC and verify")
    doc.append("")
    doc.append("## Encoding Tools")
    doc.append("### Base64")
    doc.append("- Encode text to Base64 and decode back")
    doc.append("Example: Encode 'SecurePass', then decode the result")
    doc.append("")
    doc.append("## Encryption")
    doc.append("### AES (Fernet)")
    doc.append("- Library: cryptography.Fernet (AES-CBC + HMAC, authenticated encryption)")
    doc.append("- Per-session key; encrypt/decrypt messages")
    doc.append("Example: Enter message → Encrypt; paste ciphertext → Decrypt")
    doc.append("")
    doc.append("### RSA (2048, OAEP-SHA256)")
    doc.append("- Generate RSA key pair (public/private) for the session")
    doc.append("- Encrypt with public key; decrypt with private key")
    doc.append("- Padding: OAEP with SHA256 (MGF1-SHA256)")
    doc.append("Example: Generate keys, encrypt message, then decrypt Base64 ciphertext")
    doc.append("")
    doc.append("## Notes")
    doc.append("- Keys are session-scoped in memory; private keys are not displayed")
    doc.append("- Do not reuse example secrets in production")
    doc.append("")
    content = "\n".join(doc)
    headers = {
        "Content-Disposition": "attachment; filename=SecurePass-Tools-Guide.md"
    }
    return Response(content, mimetype="text/markdown", headers=headers)


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
