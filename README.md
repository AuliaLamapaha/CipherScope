# 🔐 CipherScope — Cipher & Hash Analyzer

A cybersecurity-focused Python tool that detects, classifies, and decodes encoded strings, classical ciphers, and cryptographic hashes. Available as both a **Streamlit web interface** and a **CLI foundation**.

---

## Overview

CipherScope accepts a raw input string and passes it through a structured analysis pipeline:

```
INPUT → NORMALIZER → DETECTOR → CLASSIFIER → DECODER / ANALYZER → RESULT
```

| Stage | Description |
|---|---|
| **Input** | Raw text, hash, encoded string, or ciphertext |
| **Normalizer** | Strips surrounding whitespace |
| **Detector** | Identifies probable encoding/hash type with confidence level |
| **Classifier** | Routes to the appropriate decoder or analyzer |
| **Decoder / Analyzer** | Decodes (Base64, Hex, URL, ROT13, Caesar, Atbash) or identifies hash candidates |
| **Result** | Displays decoded output or structured analysis |

---

## Features

| Feature | Status |
|---|---|
| Base64 decoding | ✅ |
| Hexadecimal decoding | ✅ |
| URL percent-encoding decoding | ✅ |
| ROT13 decoding | ✅ |
| Caesar cipher detection & decoding (all 25 shifts) | ✅ |
| Atbash cipher detection & decoding | ✅ |
| Classical cipher heuristic detection | ✅ |
| Hash algorithm identification (structural/heuristic) | ✅ |
| Input validation | ✅ |
| Streamlit web interface | ✅ |
| CLI foundation (`main.py`) | ✅ |

---

## Supported Hash Detection

CipherScope identifies probable hash algorithms based on **structural characteristics** — string length, character set, and known prefix patterns. No brute-force, no dictionary attack, and no password recovery is performed.

| Algorithm | Detection method |
|---|---|
| MD5, NTLM, MD4 | 32-char hex digest |
| SHA-1, RIPEMD-160 | 40-char hex digest |
| SHA-224, SHA3-224 | 56-char hex digest |
| SHA-256, SHA3-256, BLAKE2s | 64-char hex digest |
| SHA-384, SHA3-384 | 96-char hex digest |
| SHA-512, SHA3-512, BLAKE2b | 128-char hex digest |
| bcrypt | `$2a$` / `$2b$` / `$2y$` prefix |
| Argon2 | `$argon2i/d/id$` prefix |
| scrypt | `$scrypt$` prefix |
| PBKDF2 | `$pbkdf2` prefix |
| SHA-256/512 crypt (Unix) | `$5$` / `$6$` prefix |
| MD5 crypt (Unix) | `$1$` prefix |

> **Note:** Hash detection results are heuristic inferences, not guarantees.

---

## Project Structure

```
CipherScope/
├── app.py                    # Streamlit web interface
├── main.py                   # CLI entry point
├── detector.py               # Primary type detector (detect_type)
├── requirements.txt          # Python dependencies
│
├── decoders/
│   ├── atbash_decoder.py
│   ├── base64_decoder.py
│   ├── caesar_decoder.py
│   ├── hex_decoder.py
│   ├── rot13_decoder.py
│   └── url_decoder.py
│
├── detectors/
│   ├── cipher_detector.py    # Classical cipher heuristic detection
│   └── hash_detector.py      # Hash algorithm identification
│
├── utils/
│   ├── formatters.py         # CLI output formatters
│   └── validators.py         # Input validation helpers
│
└── tests/
    ├── test_cipher_detector.py
    ├── test_decoders.py
    ├── test_detector.py
    ├── test_formatters.py
    ├── test_hash_detector.py
    └── test_validators.py
```

---

## Requirements

- **Python** 3.10 or later
- **Streamlit** ≥ 1.63.0 (only third-party dependency)

All other imports (`re`, `base64`, `codecs`, `urllib`, etc.) are Python standard library modules.

---

## Installation

**1. Clone or download the project**

```bash
git clone https://github.com/your-username/cipherscope.git
cd cipherscope
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Run the Streamlit web interface**

```bash
streamlit run app.py
```

The app will open at `http://localhost:8501`.

**4. (Optional) Run the CLI**

```bash
python main.py
```

---

## Usage

### Web Interface

1. Open the app in a browser (`streamlit run app.py`).
2. Paste any encoded string, hash, or ciphertext into the input area.
3. Click **Analyze**.
4. CipherScope will display the detected type, confidence level, and decoded output.

### Example

| Input | Detected Type | Decoded Output |
|---|---|---|
| `SGVsbG8gV29ybGQ=` | Base64 (Medium) | `Hello World` |
| `48656c6c6f` | Hexadecimal (Medium) | `Hello` |
| `hello%20world` | URL Encoding (High) | `hello world` |
| `Uryyb Jbeyq` | ROT13 (Low) | `Hello World` |
| `5d41402abc4b2a76b9719d911017c592` | Hash — MD5 (High) | *(not decoded — hash identified only)* |

---

## Testing

CipherScope includes a comprehensive automated test suite covering all modules.

```bash
pytest tests/ -q
```

**Final result: 162 passed**

---

## Limitations

- **Detection is heuristic.** Results are probability-based inferences, not guaranteed classifications. Short inputs may produce false positives or low-confidence results.
- **Hash identification only.** CipherScope never attempts to crack, reverse, or brute-force hash values.
- **Classical cipher scoring uses English frequency analysis.** Non-English ciphertexts may not be detected correctly.
- **ROT13 detection** applies a common-word heuristic and may miss short or ambiguous inputs.

---

## Version

**CipherScope v1.0**

---

## License

License not yet determined.
