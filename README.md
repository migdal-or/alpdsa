# AlpDSA — Passwordless Linux Login via Android Phone

This project is inspired by [ALP](https://github.com/gernotfeichter/alp), yet independently written from scratch.

Android has excellent hardware-backed security for private keys: the Keystore system with TEE (Trusted Execution Environment). **AlpDSA leverages this fully.** The ECDSA private key is generated and lives exclusively inside the phone's secure hardware — it cannot be extracted, backed up, or stolen by software. Only the public key is exported during one-time pairing. 

You decide, on your Linux machine, whether to trust that public key. You decide, on your phone, whether to allow authentication right now (Setup Mode on/off). No secrets ever leave the device.

Replace password entry on Linux with ECDSA challenge-response authentication using your Android phone over local TCP. No Bluetooth, no FIDO2 tokens, no cloud.

## What this project does NOT do (yet)

- No push notifications on the phone to accept/decline each login attempt. The original [ALP](https://github.com/gernotfeichter/alp) had this, but it added complexity and latency. AlpDSA auto-approves every valid signature from the active key. You control access by toggling Setup Mode (blocks pairing) or stopping the service entirely.

## How it works

1. **Pairing (one time)**: Linux asks the phone for its public key. You save it. The private key never leaves the phone.

2. **Login (every time)**: Linux generates a random 32-byte challenge and sends it to the phone. The phone signs it with its private key and returns the signature. Linux verifies the signature against the stored public key. If it matches — you're in.

## Why this is secure

**Someone listening on your Wi-Fi?** They'll see the public key and the signatures. That's fine — the public key is *public*, and signatures can't be reused because the challenge is random every time.

**Someone trying to replay an old login?** Won't work. Each challenge is a fresh 32-byte random number. A signature that worked before won't match the new challenge.

**Someone sitting between your computer and your phone (man-in-the-middle)?** They can intercept the challenge, but they can't forge a valid signature — that would require the private key, which is locked in the phone's secure hardware. If they send a different challenge to the phone, the signature they get back won't match what the computer expects. Either way, they lose.

**The only way to break this**: steal the private key from the phone. But it's stored in the TEE (Trusted Execution Environment) — a hardware-isolated chip that even the operating system can't read. To extract it, you'd need physical access, specialised equipment, and serious expertise.

In short: you can watch all the traffic, intercept every packet, and still gain nothing. The private key stays in the phone. The phone stays in your pocket.

## Architecture

```
┌──────────────┐     TCP:7654       ┌─────────────┐     PAM        ┌─────────────┐
│  Android App │ ◄─── AUTH ───────► │  Linux Host │ ◄────────────► │  GUI Login  │
│  (Kotlin)    │    challenge-      │  pam_alpdsa │                │  (gdm3)     │
│              │    response        │  + alpdsa-  │                │             │
│  Keystore    │                    │    pair     │                │             │
│  TEE-backed  │                    └─────────────┘                └─────────────┘
└──────────────┘
```

### Components

| Component | Language | Purpose |
|-----------|----------|---------|
| Android App | Kotlin (Jetpack Compose) | Generates ECDSA keypair in TEE, signs auth challenges |
| `pam_alpdsa.so` | C + OpenSSL 3.0 | PAM module: sends nonce, verifies signature, authenticates |
| `alpdsa-pair` | Python 3 | One-time pairing: fetches phone's public key, saves config |

### Protocol

- Transport: raw TCP, port 7654, customizable
- Authentication: ECDSA on secp256r1 (P-256), SHA-256
- Challenge-response with 32-byte random nonce (prevents replay)

Commands (binary):
| Byte | Command |
|------|---------|
| 0x01 | `GET_PUBKEY` — fetch active public key (requires Setup Mode on phone) |
| 0x02 | `AUTH` — send nonce, receive signature |

Format: `[cmd:1B] [length:4B big-endian] [data:lengthB]`

## Requirements

**Linux:**
- `libpam0g-dev`, `libssl-dev`, `python3-cryptography`
- Debian 13 (trixie) — primary development and test platform
- Likely works on Ubuntu, other Debian derivatives, and most Linux distributions with PAM + OpenSSL 3.0
- Probably fine on macOS with PAM (needs testing)
- Windows: not supported (no PAM)

**Android:**
- Android 11+ (API 30+)
- APK built from `android/` directory

## Installation

### 1. Build PAM module

```bash
cd pam
make
sudo make install
```

### 2. Python pairing tool

Run the pairing script to fetch the phone's public key:

```bash
python3 alpdsa-pair --host 192.168.1.42 --key-name phone
```

If run as root, files go directly to `/etc/alpdsa/`. If run as a regular user, the script saves them in the current directory and prints instructions:

```
WARNING: /etc not writable, using current directory.
OK. Public key saved to ./phone.pub
Config saved to ./alpdsa.config
INFO: Move these files to /etc/alpdsa/ for PAM to find them:
  sudo mkdir -p /etc/alpdsa
  sudo cp phone.pub alpdsa.config /etc/alpdsa/
```

### 3. Build and install Android APK

Open `android/` in Android Studio, build, install on phone via ADB or direct APK.

## Setup

### 1. On the phone

- Open AlpDSA app
- Generate a new key (or use default)
- Enable **Setup Mode** (temporarily allows `GET_PUBKEY`)

### 2. Pair with Linux

```bash
alpdsa-pair --host 192.168.1.42 --key-name mi9se
```

This creates:
- `/etc/alpdsa/mi9se.pub` — phone's public key (DER format)
- `/etc/alpdsa/alpdsa.config` — `mi9se 192.168.1.42:7654`

### 3. Configure PAM

For GUI login only (gdm3):

```bash
sudo nano /etc/pam.d/gdm-password
```

Add as **first line** (before `@include common-auth`):
```
auth sufficient pam_alpdsa.so
```

Example:
```
#%PAM-1.0
auth sufficient pam_alpdsa.so
auth    requisite       pam_nologin.so
@include common-auth
...
```

I do NOT add it to `/etc/pam.d/sudo` or `/etc/pam.d/sshd` as I use my phone auth only for GUI unlock.

### 4. Disable Setup Mode

After pairing, turn off Setup Mode in the app. The phone will reject `GET_PUBKEY` but still accept `AUTH`.

## Usage

1. Keep AlpDSA service running on phone
2. At Linux login screen, press Enter (or type anything as password)
3. If phone is on the same Wi-Fi — login succeeds instantly
4. If phone is offline, key is wrong, server disabled, anything bad happens — falls back to password

Timeout: 1 second.

## Testing (without installing to system)

```bash
mkdir /tmp/alpdsa-test
cp /etc/alpdsa/* /tmp/alpdsa-test/

# Create test PAM service
cat > /tmp/alpdsa-test/test-pam << 'EOF'
auth sufficient /path/to/pam_alpdsa.so config=/tmp/alpdsa-test/alpdsa.config
auth required pam_deny.so
EOF

# Symlink and test
sudo ln -s /tmp/alpdsa-test/test-pam /etc/pam.d/test-alpdsa
pamtester test-alpdsa $USER authenticate
sudo rm /etc/pam.d/test-alpdsa
```

## Security

- Private key never leaves Android Keystore (TEE-backed)
- Challenge-response with random nonce prevents replay attacks
- No persistent TCP connection — one request per auth attempt
- `GET_PUBKEY` only works in Setup Mode (must be manually enabled)
- PAM fallback ensures password access if phone unavailable

## Project Structure

```
alpdsa/
├── README.md
├── android/           # Android app (Kotlin, Jetpack Compose)
├── pam/
│   ├── Makefile
│   ├── pam_alpdsa.c
│   ├── alpdsa.c
│   └── alpdsa.h
└── alpdsa-pair        # Python pairing tool
```

## License

GNU GPL 3
