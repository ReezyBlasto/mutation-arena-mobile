#!/usr/bin/env bash
# SecTeam setup script — idempotent, run as root or sudo user.
# Sets up the secteam user, data directories, Python venv, and systemd service.

set -euo pipefail

INSTALL_DIR="/opt/secteam"
DATA_DIR="/var/lib/secteam"
LOG_FILE="/var/log/secteam.log"
SERVICE_USER="secteam"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[secteam]${NC} $*"; }
warn()    { echo -e "${YELLOW}[secteam]${NC} $*"; }
error()   { echo -e "${RED}[secteam]${NC} $*" >&2; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (or with sudo)"
        exit 1
    fi
}

check_ollama() {
    if command -v ollama &>/dev/null; then
        info "Ollama found: $(ollama --version 2>/dev/null || echo 'version unknown')"
    else
        warn "Ollama not found. Install from https://ollama.com/download"
        warn "SecTeam will work with API keys if set in environment."
    fi
}

create_user() {
    if ! id "$SERVICE_USER" &>/dev/null; then
        info "Creating user: $SERVICE_USER"
        useradd --system --no-create-home \
            --shell /bin/false \
            --comment "SecTeam security daemon" \
            "$SERVICE_USER"
    else
        info "User $SERVICE_USER already exists"
    fi

    # Add to relevant groups for log access
    for grp in adm syslog systemd-journal audit; do
        if getent group "$grp" &>/dev/null; then
            usermod -aG "$grp" "$SERVICE_USER" 2>/dev/null || true
        fi
    done
}

setup_dirs() {
    info "Setting up directories..."
    mkdir -p "$DATA_DIR" "$DATA_DIR/quarantine" "$INSTALL_DIR"
    touch "$LOG_FILE"

    chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
    chown    "$SERVICE_USER:$SERVICE_USER" "$LOG_FILE"
    chmod    700 "$DATA_DIR"
    chmod    700 "$DATA_DIR/quarantine"
}

install_system_deps() {
    info "Installing system dependencies..."
    apt-get update -qq
    apt-get install -y -qq \
        python3 python3-pip python3-venv \
        inotify-tools \
        nmap \
        net-tools \
        libmagic1 \
        libpq-dev 2>/dev/null || true
}

setup_venv() {
    info "Setting up Python virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
    "$INSTALL_DIR/venv/bin/pip" install -r "$REPO_DIR/requirements.txt" -q
    info "Python environment ready."
}

install_files() {
    info "Installing SecTeam files to $INSTALL_DIR..."
    cp -r "$REPO_DIR/secteam" "$INSTALL_DIR/"
    cp    "$REPO_DIR/main.py"  "$INSTALL_DIR/"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

    # CLI symlink
    ln -sf "$INSTALL_DIR/venv/bin/python" /usr/local/bin/secteam-python
    cat > /usr/local/bin/secteam << 'EOF'
#!/bin/bash
exec /opt/secteam/venv/bin/python /opt/secteam/main.py "$@"
EOF
    chmod +x /usr/local/bin/secteam
    info "CLI available: secteam --help"
}

install_service() {
    info "Installing systemd service..."
    cp "$REPO_DIR/systemd/secteam.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable secteam
    info "Service installed. Start with: systemctl start secteam"
}

setup_sudoers() {
    # Allow secteam to run specific commands without password
    cat > /etc/sudoers.d/secteam << 'EOF'
# SecTeam daemon permissions
secteam ALL=(root) NOPASSWD: /usr/sbin/ufw *, \
                              /bin/systemctl stop *, \
                              /bin/systemctl restart *, \
                              /usr/bin/apt-get install *, \
                              /usr/bin/apt-get update, \
                              /sbin/iptables *, \
                              /usr/bin/fail2ban-client *, \
                              /usr/sbin/lynis *, \
                              /usr/bin/rkhunter *, \
                              /usr/sbin/chkrootkit, \
                              /usr/bin/aide *, \
                              /bin/kill *, \
                              /usr/bin/find / *, \
                              /bin/chmod *, \
                              /bin/chown *, \
                              /usr/sbin/sysctl *
EOF
    chmod 440 /etc/sudoers.d/secteam
    info "Sudoers configured for secteam user."
}

run_initial_audit() {
    info "Running initial system audit..."
    sudo -u "$SERVICE_USER" \
        SECTEAM_DATA="$DATA_DIR" \
        "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/main.py" audit --baseline \
        2>/dev/null || warn "Initial audit failed — check logs after starting the service"
}

print_summary() {
    info ""
    info "═══════════════════════════════════════════════"
    info " SecTeam Installation Complete"
    info "═══════════════════════════════════════════════"
    info ""
    info "Commands:"
    info "  systemctl start secteam      # start daemon"
    info "  systemctl status secteam     # check status"
    info "  secteam status               # live dashboard"
    info "  secteam audit                # run full audit"
    info "  secteam ask 'question here'  # query any agent"
    info "  secteam events               # list open events"
    info "  secteam report               # posture report"
    info "  secteam tools                # tool recommendations"
    info "  secteam models               # LLM model status"
    info "  secteam pull llama3.1:8b     # pull a model"
    info ""
    info "Data:    $DATA_DIR"
    info "Logs:    journalctl -u secteam -f"
    info ""
    check_ollama
}

main() {
    require_root
    info "SecTeam setup starting..."
    create_user
    setup_dirs
    install_system_deps
    setup_venv
    install_files
    install_service
    setup_sudoers
    run_initial_audit
    print_summary
}

main "$@"
