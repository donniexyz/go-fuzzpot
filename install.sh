#!/bin/bash
# fuzzpot install script — creates system user, copies binary, installs service
set -euo pipefail

BINDIR="/opt/fuzzpot"
CONFDIR="/etc/fuzzpot"
LOGDIR="/var/log/fuzzpot"
SERVICE="/etc/systemd/system/fuzzpot.service"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== fuzzpot install ==="

# 1. Create unprivileged system user
if ! id fuzzpot &>/dev/null; then
    echo "[*] Creating user 'fuzzpot'..."
    s2do useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin --no-create-home fuzzpot
else
    echo "[*] User 'fuzzpot' already exists"
fi

# 2. Install binary
echo "[*] Installing binary to ${BINDIR}..."
s2do mkdir -p "${BINDIR}"
s2do cp "${SCRIPT_DIR}/fuzzpot" "${BINDIR}/fuzzpot"
s2do chmod 755 "${BINDIR}/fuzzpot"

# 3. Install config
echo "[*] Installing config to ${CONFDIR}..."
s2do mkdir -p "${CONFDIR}"
if [ ! -f "${CONFDIR}/config.yaml" ]; then
    s2do cp "${SCRIPT_DIR}/config/config.yaml" "${CONFDIR}/config.yaml"
    s2do chmod 640 "${CONFDIR}/config.yaml"
    s2do chown fuzzpot:fuzzpot "${CONFDIR}/config.yaml"
else
    echo "[*] Config already exists, skipping (edit manually)"
fi

# 4. Create log directory
echo "[*] Creating log directory ${LOGDIR}..."
s2do mkdir -p "${LOGDIR}"
s2do chown fuzzpot:fuzzpot "${LOGDIR}"
s2do chmod 750 "${LOGDIR}"

# 5. Install systemd service
echo "[*] Installing systemd service..."
s2do cp "${SCRIPT_DIR}/fuzzpot.service" "${SERVICE}"
s2do systemctl daemon-reload

echo ""
echo "=== Installation complete ==="
echo ""
echo "  Binary:   ${BINDIR}/fuzzpot"
echo "  Config:   ${CONFDIR}/config.yaml"
echo "  Logs:     ${LOGDIR}/"
echo "  Service:  fuzzpot.service"
echo ""
echo "Commands:"
echo "  s2do systemctl enable --now fuzzpot   # start + enable on boot"
echo "  s2do systemctl status fuzzpot         # check status"
echo "  journalctl -u fuzzpot -f              # live logs"
echo "  s2do systemctl stop fuzzpot           # stop"
echo ""
