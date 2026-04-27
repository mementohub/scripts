#!/usr/bin/env bash
# harden-sshd.sh — Harden the OpenSSH server configuration
# Must be run as root on a Linux server
#
# What this script does:
#   - Disables password and root login
#   - Enforces public-key authentication only
#   - Sets connection/session limits
#   - Disables unused features (X11, agent/TCP forwarding, tunneling)
#   - Restricts ciphers, MACs, and key-exchange algorithms to modern standards
#   - Validates the config with `sshd -t` before restarting the service
#   - Creates a timestamped backup before making any changes
#
# IMPORTANT: Ensure you have a working SSH key-pair set up BEFORE running
# this script, otherwise you will be locked out of the server.

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_FILE="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG not found. Is OpenSSH installed?" >&2
    exit 1
fi

# Warn the operator before making any changes
echo "=========================================================="
echo " SSH Hardening Script"
echo "=========================================================="
echo ""
echo "This script will modify: $SSHD_CONFIG"
echo "A backup will be saved to: $BACKUP_FILE"
echo ""
echo "WARNING: Password authentication will be DISABLED."
echo "Ensure your SSH public key is already installed before continuing."
echo ""
read -rp "Continue? [y/N] " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------

cp -p "$SSHD_CONFIG" "$BACKUP_FILE"
echo ""
echo "[+] Backup created: $BACKUP_FILE"

# ---------------------------------------------------------------------------
# Helper: set_config KEY VALUE
#   - If the directive (commented or not) already exists, replace it.
#   - If it doesn't exist, append it.
#   - Uses a temp file + cat to preserve ownership/permissions.
# ---------------------------------------------------------------------------

set_config() {
    local key="$1"
    local value="$2"
    local tmpfile
    tmpfile=$(mktemp)

    # Match lines like: "  # Key value" or "Key value" (case-sensitive key)
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG"; then
        sed -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]].*|${key} ${value}|" \
            "$SSHD_CONFIG" > "$tmpfile"
        cat "$tmpfile" > "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi

    rm -f "$tmpfile"
    echo "    ${key} = ${value}"
}

# ---------------------------------------------------------------------------
# Apply hardening settings
# ---------------------------------------------------------------------------

echo ""
echo "[+] Applying hardening settings..."

# -- Authentication --
# Disable root login entirely
set_config "PermitRootLogin"                  "no"
# Require public-key auth; disable all password-based methods
set_config "PubkeyAuthentication"             "yes"
set_config "PasswordAuthentication"           "no"
set_config "PermitEmptyPasswords"             "no"
set_config "ChallengeResponseAuthentication"  "no"
# Modern OpenSSH renamed ChallengeResponseAuthentication
set_config "KbdInteractiveAuthentication"     "no"
# Only allow public-key as the authentication method
set_config "AuthenticationMethods"            "publickey"
# Disable legacy host-based and .rhosts authentication
set_config "HostbasedAuthentication"          "no"
set_config "IgnoreRhosts"                     "yes"
# Don't allow users to set environment variables via SSH
set_config "PermitUserEnvironment"            "no"

# -- Connection and session limits --
# How long (seconds) to wait for a successful login before disconnecting
set_config "LoginGraceTime"                   "30"
# Disconnect after 3 failed auth attempts
set_config "MaxAuthTries"                     "3"
# Max concurrent unauthenticated connections: start throttling at 10,
# drop 30% probability until 60 pending, then reject all
set_config "MaxStartups"                      "10:30:60"
# Max open sessions per network connection
set_config "MaxSessions"                      "4"
# File/directory permission checks (e.g. ~/.ssh must not be world-writable)
set_config "StrictModes"                      "yes"

# -- Idle timeout --
# Send a keep-alive packet every 300 s; after 2 missed responses (~10 min
# idle) the session is disconnected
set_config "ClientAliveInterval"              "300"
set_config "ClientAliveCountMax"              "2"

# -- Disable unused / risky features --
# No X11 display forwarding
set_config "X11Forwarding"                    "no"
# No SSH agent forwarding (prevents agent-hijacking attacks)
set_config "AllowAgentForwarding"             "no"
# No TCP port forwarding / tunneling
set_config "AllowTcpForwarding"               "no"
set_config "GatewayPorts"                     "no"
set_config "PermitTunnel"                     "no"
# Don't print /etc/motd on login (reduce info leakage)
set_config "PrintMotd"                        "no"

# -- Logging --
# VERBOSE logs the key fingerprint used on login, useful for auditing
set_config "SyslogFacility"                   "AUTH"
set_config "LogLevel"                         "VERBOSE"

# -- Cryptography: modern, forward-secret algorithms only --
# Ciphers: prefer ChaCha20 and AES-GCM; remove legacy CBC/RC4/3DES
set_config "Ciphers" \
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"

# MACs: ETM (Encrypt-then-MAC) variants only
set_config "MACs" \
    "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"

# Key exchange: Curve25519 and strong DH groups; no SHA-1 or small-group DH
set_config "KexAlgorithms" \
    "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256"

# Host key algorithms: prefer Ed25519, then ECDSA/RSA with SHA-2
set_config "HostKeyAlgorithms" \
    "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-256,rsa-sha2-512"

# ---------------------------------------------------------------------------
# Validate configuration
# ---------------------------------------------------------------------------

echo ""
echo "[+] Validating configuration with 'sshd -t'..."
if sshd -t -f "$SSHD_CONFIG"; then
    echo "    Configuration is valid."
else
    echo "" >&2
    echo "Error: sshd reported an invalid configuration." >&2
    echo "Restoring backup: $BACKUP_FILE" >&2
    cp -p "$BACKUP_FILE" "$SSHD_CONFIG"
    echo "Backup restored. No changes have been applied." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Reload / restart SSH service
# ---------------------------------------------------------------------------

echo ""
echo "[+] Reloading SSH service..."

restart_ok=0

if command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet sshd 2>/dev/null; then
        systemctl restart sshd
        echo "    sshd restarted via systemctl."
        restart_ok=1
    elif systemctl is-active --quiet ssh 2>/dev/null; then
        systemctl restart ssh
        echo "    ssh restarted via systemctl."
        restart_ok=1
    else
        # Unit exists but may be inactive; try to enable and start
        systemctl enable --now sshd 2>/dev/null || systemctl enable --now ssh 2>/dev/null || true
        restart_ok=1
    fi
fi

if [[ $restart_ok -eq 0 ]] && command -v service &>/dev/null; then
    service sshd restart 2>/dev/null || service ssh restart 2>/dev/null || true
    echo "    SSH service restarted via service."
    restart_ok=1
fi

if [[ $restart_ok -eq 0 ]]; then
    echo ""
    echo "WARNING: Could not detect a supported init system." >&2
    echo "Please restart sshd manually to apply the changes." >&2
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=========================================================="
echo " Hardening complete"
echo "=========================================================="
echo ""
echo "  Config file : $SSHD_CONFIG"
echo "  Backup      : $BACKUP_FILE"
echo ""
echo "  Key changes applied:"
echo "    - Root login          : disabled"
echo "    - Password auth       : disabled (public-key only)"
echo "    - Empty passwords     : disabled"
echo "    - X11 forwarding      : disabled"
echo "    - Agent forwarding    : disabled"
echo "    - TCP forwarding      : disabled"
echo "    - Idle timeout        : ~10 minutes"
echo "    - Max auth tries      : 3"
echo "    - Weak ciphers/MACs   : removed"
echo ""
echo "  To restore the original config:"
echo "    cp $BACKUP_FILE $SSHD_CONFIG && systemctl restart sshd"
echo ""
