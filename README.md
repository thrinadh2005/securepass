# 🔐 SecurePass - Advanced Security Tools

A comprehensive password security and cryptography suite that provides multiple tools for password analysis, generation, hashing, and encryption.

## 🌟 Features

### 🔍 Password Strength Checker
- **Real-time Analysis**: Evaluates password strength based on multiple criteria
- **Entropy Calculation**: Measures password complexity in bits
- **Visual Feedback**: Color-coded strength indicator with progress bar
- **Improvement Tips**: Provides specific suggestions for weak passwords
- **Smart Suggestions**: Automatically generates stronger passwords for weak/medium entries

**How it works:**
- Checks length (8-12+ characters)
- Validates character types (uppercase, lowercase, digits, special)
- Detects common patterns and dictionary words
- Calculates entropy using the formula: `entropy = length × log₂(character_set_size)`

### 🎲 Advanced Password Generator
- **Customizable Length**: Generate passwords from 8 to 64 characters
- **Character Type Control**: Toggle inclusion of:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)  
  - Digits (0-9)
  - Special characters (!@#$%^&*()_+-=[]{}|;:,.<>?)
- **Ambiguous Character Exclusion**: Option to exclude confusing characters (0, O, l, 1, I)
- **Guaranteed Diversity**: Ensures at least one character from each selected type

**How it works:**
1. Builds character sets based on selected options
2. Guarantees one character from each selected set
3. Fills remaining positions with random characters from combined sets
4. Shuffles final password to eliminate predictable patterns

### 🔐 Hashing Tools

#### SHA256 Hash Generator
- **Cryptographic Hashing**: Generates SHA256 hashes for any text input
- **One-way Function**: Secure for password storage and data integrity
- **Fixed Output**: Always produces 64-character hexadecimal string

**How it works:**
- Uses Python's `hashlib.sha256()` implementation
- Converts input to UTF-8 encoded bytes
- Returns hexadecimal representation of the hash

#### Secure Password Hashing (PBKDF2)
- **Industry Standard**: Uses PBKDF2-HMAC-SHA256 algorithm
- **High Security**: 100,000 iterations for resistance against brute force attacks
- **Salt Generation**: Automatically generates unique 16-byte salt for each hash
- **Verification Support**: Includes password verification functionality

**How it works:**
1. Generates random salt if not provided
2. Uses PBKDF2-HMAC with SHA256 as the underlying hash function
3. Performs 100,000 iterations for key derivation
4. Returns format: `{salt}:{hash}` for storage
5. Verification extracts salt and recomputes hash for comparison

### 🔄 Encoding Tools

#### Base64 Encode/Decode
- **Text Encoding**: Convert plain text to Base64 format
- **Decoding Support**: Convert Base64 back to original text
- **Error Handling**: Graceful handling of invalid Base64 input
- **Copy Support**: One-click clipboard functionality

**How it works:**
- Encoding: Uses `base64.b64encode()` to convert text bytes to Base64
- Decoding: Uses `base64.b64decode()` with error handling for invalid input

### 🔒 AES Encryption (Fernet)
- **Symmetric Encryption**: AES-128 in CBC mode with HMAC
- **Session-based Keys**: Generates unique encryption key per session
- **Secure Implementation**: Uses Python's cryptography library Fernet
- **Key Display**: Shows session key for decryption purposes

**How it works:**
1. Generates random 256-bit Fernet key
2. Uses AES-128-CBC with HMAC for authentication
3. Encrypts messages with timestamp for replay protection
4. Requires same key for encryption and decryption

## 🚀 Getting Started

### Prerequisites
- Python 3.7+
- pip package manager

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/thrinadh2005/securepass.git
cd securepass
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the application:**
```bash
python app.py
```

4. **Access the application:**
   - Local: http://localhost:5000
   - Production: https://securepass-56vg.onrender.com

### Dependencies
- **Flask 2.3.3**: Web framework
- **cryptography 41.0.4**: Cryptographic functions
- **Python Standard Libraries**: 
  - `hashlib`, `base64`, `math`, `re`, `random`, `string`
  - `os`, `threading`, `webbrowser`, `subprocess`

## 📋 Usage Guide

### Password Strength Checking
1. Enter a password in the "Password Strength Checker" section
2. Click "Check Strength"
3. View results:
   - Strength level (Weak/Medium/Strong)
   - Entropy value with visual meter
   - Improvement suggestions
   - Suggested stronger password (if weak/medium)

### Custom Password Generation
1. Set desired password length (8-64 characters)
2. Select character types to include
3. Choose whether to exclude ambiguous characters
4. Click "Generate Password"
5. Copy the generated password

### Hashing Operations
1. **SHA256 Hash**: Enter text and click "Generate SHA256"
2. **Password Hash**: Enter password and click "Hash Password"
3. **Password Verification**: Enter password and hash, then click "Verify Password"

### Base64 Operations
1. **Encoding**: Enter text and click "Encode to Base64"
2. **Decoding**: Enter Base64 text and click "Decode from Base64"

### AES Encryption/Decryption
1. **Encryption**: Enter message and click "Encrypt"
2. **Decryption**: Paste ciphertext and click "Decrypt"
3. Note the session key for future decryption

## 🔒 Security Features

### Cryptographic Security
- **PBKDF2**: 100,000 iterations for password hashing
- **AES-128**: Industry-standard symmetric encryption
- **SHA256**: Cryptographic hash function
- **Random Generation**: Cryptographically secure random number generation

### Best Practices
- **No Password Storage**: No passwords are stored permanently
- **Session-based Keys**: Encryption keys are generated per session
- **Secure Defaults**: Recommended settings for all operations
- **Input Validation**: Proper handling of edge cases and errors

## 🛠️ Technical Implementation

### Password Strength Algorithm
```python
strength = 0
if length >= 12: strength += 2
elif length >= 8: strength += 1
if has_uppercase: strength += 1
if has_lowercase: strength += 1
if has_digits: strength += 1
if has_special: strength += 1
if common_pattern: strength -= 1
```

### Entropy Calculation
```python
char_sets = 0
if has_lowercase: char_sets += 26
if has_uppercase: char_sets += 26
if has_digits: char_sets += 10
if has_special: char_sets += 32
entropy = length * log2(char_sets)
```

### Password Hashing
```python
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt.encode(),
    iterations=100000,
)
hashed = kdf.derive(password.encode())
```

## 🌐 Deployment

### Local Development
```bash
python app.py
# Access at http://localhost:5000
```

### Production (Render)
1. Connect GitHub repository to Render
2. Set build command: `pip install -r requirements.txt`
3. Set start command: `python app.py`
4. Deploy and access at provided URL

### Environment Variables
- `PORT`: Server port (default: 5000)
- `FLASK_ENV`: Environment mode (development/production)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 🔗 Links

- **Live Demo**: https://securepass-56vg.onrender.com
- **GitHub Repository**: https://github.com/thrinadh2005/securepass
- **Issues & Support**: https://github.com/thrinadh2005/securepass/issues

## 📊 Feature Matrix

| Feature | Description | Security Level |
|---------|-------------|----------------|
| Password Strength Check | Analyzes password complexity | 🟡 Medium |
| Entropy Calculator | Measures password randomness | 🟢 High |
| Custom Generator | Creates secure passwords | 🟢 High |
| SHA256 Hash | Cryptographic hashing | 🟢 High |
| PBKDF2 Hashing | Secure password storage | 🟢 High |
| Base64 Encode/Decode | Text encoding utility | 🟡 Medium |
| AES Encryption | Message encryption | 🟢 High |

## 🎯 Use Cases

- **Security Auditors**: Test password strength and generate secure passwords
- **Developers**: Hash passwords and encrypt sensitive data
- **Security Enthusiasts**: Learn about cryptography concepts
- **System Administrators**: Generate secure credentials
- **Educational Purposes**: Demonstrate cryptographic principles

---

**SecurePass** - Your comprehensive security toolkit for password management and cryptography! 🛡️
