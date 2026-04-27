#!/bin/bash

# Script to create a new user on Ubuntu server with sudo access and SSH key
# Requires root privileges

set -e  # Exit on any error

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root"
    exit 1
fi

# Prompt for username
read -p "Enter username: " USERNAME

# Validate username
if [ -z "$USERNAME" ]; then
    echo "Error: Username cannot be empty"
    exit 1
fi

# Check if user already exists
if id "$USERNAME" &>/dev/null; then
    echo "Error: User $USERNAME already exists"
    exit 1
fi

# Prompt for public key
echo "Enter the public SSH key (paste the entire key and press Enter):"
read -r PUBLIC_KEY

# Validate public key
if [ -z "$PUBLIC_KEY" ]; then
    echo "Error: Public key cannot be empty"
    exit 1
fi

# Validate public key format (basic check)
if [[ ! "$PUBLIC_KEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ]]; then
    echo "Error: Invalid public key format"
    exit 1
fi

echo ""
echo "Creating user: $USERNAME"

# Create the user with a home directory
useradd -m -s /bin/bash "$USERNAME"

# Add user to sudo group
usermod -aG sudo "$USERNAME"
echo "✓ User added to sudo group"

# Set up SSH directory and authorized_keys
USER_HOME="/home/$USERNAME"
SSH_DIR="$USER_HOME/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

# Create .ssh directory
mkdir -p "$SSH_DIR"
echo "✓ Created .ssh directory"

# Add public key to authorized_keys
echo "$PUBLIC_KEY" > "$AUTH_KEYS"
echo "✓ Added public key to authorized_keys"

# Set proper ownership and permissions
chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
chmod 700 "$SSH_DIR"
chmod 600 "$AUTH_KEYS"
echo "✓ Set proper permissions"

# Force password change on first login
passwd -d "$USERNAME"  # Remove password (make it empty)
passwd -e "$USERNAME"  # Expire the password immediately
echo "✓ Password reset forced on first login"

echo ""
echo "======================================"
echo "User $USERNAME created successfully!"
echo "======================================"
echo ""
echo "User details:"
echo "  - Username: $USERNAME"
echo "  - Home directory: $USER_HOME"
echo "  - Sudo access: Enabled"
echo "  - SSH key: Configured"
echo "  - Password reset: Required on first login"
echo ""
echo "Note: The user will need to set a password when they first connect."
echo "      They can SSH in with their key, and will be prompted to create a password."
