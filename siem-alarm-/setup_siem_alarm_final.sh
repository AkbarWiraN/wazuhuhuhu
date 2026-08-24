#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

BASE_DIR="/opt/wazuh-risk-scoring"
CONFIG_DIR="/etc/wazuh-risk-scoring"
SERVICE_USER="siem-alarm"
SERVICE_GROUP="siem-alarm"
EXPECTED_WAZUH_VERSION="4.14.7"
EXPECTED_FILEBEAT_VERSION="7.10.2"
CA_SOURCE="${WAZUH_CA_SOURCE:-/etc/wazuh-indexer/certs/root-ca.pem}"
INDEXER_CERT_SOURCE="${WAZUH_INDEXER_CERT_SOURCE:-/etc/wazuh-indexer/certs/indexer.pem}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
BACKUP_DIR="${BASE_DIR}/backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"

required_files=(
  "siem_alarm_scoring_final.py"
  "wazuh_field_audit_final.py"
  "siem_alarm_template_final.json"
  "siem_alarm_ism_policy.json"
  "config.siem_alarm.example.json"
  "assets.example.json"
  "final_checklist_siem_alarm_wazuh_4_14_7.md"
  "tests/test_siem_alarm_scoring.py"
)

die() {
  echo "[!] $*" >&2
  exit 1
}

on_error() {
  local exit_code=$?
  trap - ERR
  echo "[!] Installation failed with exit code ${exit_code}. The timer was not enabled." >&2
  if [[ -d "${BACKUP_DIR}" ]]; then
    echo "[!] Review or restore backups from ${BACKUP_DIR}" >&2
  fi
  exit "${exit_code}"
}

trap on_error ERR

if [[ "${EUID}" -ne 0 ]]; then
  die "Run this installer as root: sudo bash ${SCRIPT_DIR}/setup_siem_alarm_final.sh"
fi

for command_name in /usr/bin/python3 dpkg-query filebeat openssl systemctl systemd-analyze install useradd groupadd getent id chown chmod cp tee date; do
  command -v "${command_name}" >/dev/null 2>&1 || die "Required command not found: ${command_name}"
done

for file_name in "${required_files[@]}"; do
  [[ -f "${SCRIPT_DIR}/${file_name}" ]] || die "Required source file not found: ${SCRIPT_DIR}/${file_name}"
done

check_package_version() {
  local package_name="$1"
  local expected_version="$2"
  local installed_version normalized_version
  installed_version="$(dpkg-query -W -f='${Version}' "${package_name}" 2>/dev/null)" \
    || die "Required Ubuntu package is not installed: ${package_name}"
  normalized_version="${installed_version#*:}"
  case "${normalized_version}" in
    "${expected_version}"|"${expected_version}"-*|"${expected_version}"+*|"${expected_version}"~*) ;;
    *) die "${package_name} must be ${expected_version}; found ${installed_version}" ;;
  esac
  echo "[+] Version OK: ${package_name} ${installed_version}"
}

check_package_version wazuh-manager "${EXPECTED_WAZUH_VERSION}"
check_package_version wazuh-indexer "${EXPECTED_WAZUH_VERSION}"
check_package_version wazuh-dashboard "${EXPECTED_WAZUH_VERSION}"
check_package_version filebeat "${EXPECTED_FILEBEAT_VERSION}"

for wazuh_unit in wazuh-manager.service wazuh-indexer.service wazuh-dashboard.service filebeat.service; do
  systemctl cat "${wazuh_unit}" >/dev/null 2>&1 || die "Required Wazuh AIO unit not found: ${wazuh_unit}"
  systemctl is-active --quiet "${wazuh_unit}" || die "Required Wazuh AIO unit is not active: ${wazuh_unit}"
done

[[ -f "${CA_SOURCE}" ]] || die "Wazuh root CA not found: ${CA_SOURCE}. Set WAZUH_CA_SOURCE if its path differs."
[[ -f "${INDEXER_CERT_SOURCE}" ]] \
  || die "Wazuh Indexer certificate not found: ${INDEXER_CERT_SOURCE}. Set WAZUH_INDEXER_CERT_SOURCE if its path differs."
openssl x509 -checkend 86400 -noout -in "${CA_SOURCE}" >/dev/null \
  || die "Wazuh root CA is invalid or expires within 24 hours: ${CA_SOURCE}"
openssl x509 -checkend 86400 -noout -in "${INDEXER_CERT_SOURCE}" >/dev/null \
  || die "Wazuh Indexer certificate is invalid or expires within 24 hours: ${INDEXER_CERT_SOURCE}"
openssl verify -purpose sslserver -CAfile "${CA_SOURCE}" "${INDEXER_CERT_SOURCE}" >/dev/null \
  || die "Wazuh Indexer certificate does not verify against ${CA_SOURCE}"
filebeat test output >/dev/null \
  || die "Filebeat cannot connect securely to the Wazuh Indexer"

PYTHON_VERSION="$(/usr/bin/python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PYTHON_OK="$(/usr/bin/python3 -c 'import sys; print(1 if sys.version_info >= (3, 9) else 0)')"
[[ "${PYTHON_OK}" == "1" ]] || die "python3 >= 3.9 is required. Found ${PYTHON_VERSION}."

echo "[+] Pre-validating source files"
/usr/bin/python3 -m json.tool "${SCRIPT_DIR}/config.siem_alarm.example.json" >/dev/null
/usr/bin/python3 -m json.tool "${SCRIPT_DIR}/assets.example.json" >/dev/null
/usr/bin/python3 -m json.tool "${SCRIPT_DIR}/siem_alarm_template_final.json" >/dev/null
/usr/bin/python3 -m json.tool "${SCRIPT_DIR}/siem_alarm_ism_policy.json" >/dev/null
/usr/bin/python3 -c 'import ast, pathlib, sys; [ast.parse(pathlib.Path(p).read_text(encoding="utf-8"), filename=p) for p in sys.argv[1:]]' \
  "${SCRIPT_DIR}/siem_alarm_scoring_final.py" \
  "${SCRIPT_DIR}/wazuh_field_audit_final.py"
(
  cd -- "${SCRIPT_DIR}"
  /usr/bin/python3 -B -m unittest discover -s tests -v
)

if [[ -f "${BASE_DIR}/config.siem_alarm.json" ]]; then
  /usr/bin/python3 -m json.tool "${BASE_DIR}/config.siem_alarm.json" >/dev/null \
    || die "Existing config.siem_alarm.json is invalid JSON; no files were changed"
fi
if [[ -f "${BASE_DIR}/assets.json" ]]; then
  /usr/bin/python3 -m json.tool "${BASE_DIR}/assets.json" >/dev/null \
    || die "Existing assets.json is invalid JSON; no files were changed"
fi

TIMER_WAS_ENABLED=0
if systemctl is-enabled --quiet siem-alarm-scoring.timer 2>/dev/null; then
  TIMER_WAS_ENABLED=1
fi
if systemctl is-active --quiet siem-alarm-scoring.timer 2>/dev/null; then
  echo "[+] Stopping existing timer before upgrade"
  systemctl stop siem-alarm-scoring.timer
fi
if systemctl is-active --quiet siem-alarm-scoring.service 2>/dev/null; then
  echo "[+] Stopping existing scoring service before upgrade"
  systemctl stop siem-alarm-scoring.service
fi
if [[ "${TIMER_WAS_ENABLED}" -eq 1 ]]; then
  systemctl disable siem-alarm-scoring.timer
fi

if ! getent group "${SERVICE_GROUP}" >/dev/null; then
  echo "[+] Creating system group ${SERVICE_GROUP}"
  groupadd --system "${SERVICE_GROUP}"
fi

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  echo "[+] Creating system user ${SERVICE_USER}"
  useradd --system --gid "${SERVICE_GROUP}" --home-dir "${BASE_DIR}" --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

install -d -o root -g "${SERVICE_GROUP}" -m 0750 "${BASE_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0750 "${BASE_DIR}/logs"
install -d -o root -g "${SERVICE_GROUP}" -m 0750 "${CONFIG_DIR}"

backup_if_exists() {
  local source_path="$1"
  if [[ -e "${source_path}" ]]; then
    install -d -o root -g root -m 0700 "${BACKUP_DIR}"
    cp -a -- "${source_path}" "${BACKUP_DIR}/"
  fi
}

for existing_path in \
  "${BASE_DIR}/siem_alarm_scoring_final.py" \
  "${BASE_DIR}/wazuh_field_audit_final.py" \
  "${BASE_DIR}/siem_alarm_template_final.json" \
  "${BASE_DIR}/siem_alarm_ism_policy.json" \
  "/etc/systemd/system/siem-alarm-scoring.service" \
  "/etc/systemd/system/siem-alarm-scoring.timer" \
  "/etc/logrotate.d/siem-alarm-scoring"; do
  backup_if_exists "${existing_path}"
done

echo "[+] Installing application files"
install -o root -g "${SERVICE_GROUP}" -m 0750 \
  "${SCRIPT_DIR}/siem_alarm_scoring_final.py" \
  "${BASE_DIR}/siem_alarm_scoring_final.py"
install -o root -g "${SERVICE_GROUP}" -m 0750 \
  "${SCRIPT_DIR}/wazuh_field_audit_final.py" \
  "${BASE_DIR}/wazuh_field_audit_final.py"
install -o root -g "${SERVICE_GROUP}" -m 0640 \
  "${SCRIPT_DIR}/siem_alarm_template_final.json" \
  "${BASE_DIR}/siem_alarm_template_final.json"
install -o root -g "${SERVICE_GROUP}" -m 0640 \
  "${SCRIPT_DIR}/siem_alarm_ism_policy.json" \
  "${BASE_DIR}/siem_alarm_ism_policy.json"
install -o root -g "${SERVICE_GROUP}" -m 0640 "${CA_SOURCE}" "${BASE_DIR}/root-ca.pem"

if [[ ! -f "${BASE_DIR}/config.siem_alarm.json" ]]; then
  install -o root -g "${SERVICE_GROUP}" -m 0640 \
    "${SCRIPT_DIR}/config.siem_alarm.example.json" \
    "${BASE_DIR}/config.siem_alarm.json"
else
  echo "[!] Existing config.siem_alarm.json preserved"
fi

if [[ ! -f "${BASE_DIR}/assets.json" ]]; then
  install -o root -g "${SERVICE_GROUP}" -m 0640 \
    "${SCRIPT_DIR}/assets.example.json" \
    "${BASE_DIR}/assets.json"
else
  echo "[!] Existing assets.json preserved"
fi

if [[ ! -f "${CONFIG_DIR}/siem-alarm.env" ]]; then
  install -o root -g "${SERVICE_GROUP}" -m 0640 /dev/null "${CONFIG_DIR}/siem-alarm.env"
  printf '%s\n' 'WAZUH_PASS="GANTI_PASSWORD_INDEXER_ANDA"' >"${CONFIG_DIR}/siem-alarm.env"
else
  echo "[!] Existing ${CONFIG_DIR}/siem-alarm.env preserved"
fi

chown root:"${SERVICE_GROUP}" \
  "${BASE_DIR}/config.siem_alarm.json" \
  "${BASE_DIR}/assets.json" \
  "${CONFIG_DIR}/siem-alarm.env"
chmod 0640 \
  "${BASE_DIR}/config.siem_alarm.json" \
  "${BASE_DIR}/assets.json" \
  "${CONFIG_DIR}/siem-alarm.env"

/usr/bin/python3 -m json.tool "${BASE_DIR}/config.siem_alarm.json" >/dev/null
/usr/bin/python3 -m json.tool "${BASE_DIR}/assets.json" >/dev/null
while IFS= read -r config_warning; do
  [[ -n "${config_warning}" ]] && echo "[!] Config migration required: ${config_warning}"
done < <(/usr/bin/python3 -c '
import json, sys
config = json.load(open(sys.argv[1], encoding="utf-8"))
if "password" in config:
    print("remove inline password and use password_env=WAZUH_PASS")
if config.get("username") == "admin":
    print("replace Indexer admin with dedicated siem_alarm_service user")
if config.get("verify_ssl") is not True:
    print("set verify_ssl=true and verify the installed root CA")
if config.get("install_template") is not False:
    print("set install_template=false after one-time template installation")
' "${BASE_DIR}/config.siem_alarm.json")

echo "[+] Installing hardened systemd units"
tee /etc/systemd/system/siem-alarm-scoring.service >/dev/null <<EOF
[Unit]
Description=SIEM Alarm Scoring - Wazuh Progressive Alarm Aggregation
After=network-online.target wazuh-indexer.service
Wants=network-online.target wazuh-indexer.service

[Service]
Type=oneshot
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
EnvironmentFile=${CONFIG_DIR}/siem-alarm.env
ExecStart=/usr/bin/python3 -B ${BASE_DIR}/siem_alarm_scoring_final.py --config ${BASE_DIR}/config.siem_alarm.json --once
WorkingDirectory=${BASE_DIR}
RuntimeDirectory=siem-alarm
RuntimeDirectoryMode=0750
UMask=0027
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${BASE_DIR}/logs
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
EOF

tee /etc/systemd/system/siem-alarm-scoring.timer >/dev/null <<'EOF'
[Unit]
Description=SIEM Alarm Scoring Timer - every 5 minutes

[Timer]
OnCalendar=*-*-* *:0/5:00
AccuracySec=30s
Persistent=true
Unit=siem-alarm-scoring.service

[Install]
WantedBy=timers.target
EOF

tee /etc/logrotate.d/siem-alarm-scoring >/dev/null <<EOF
${BASE_DIR}/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 ${SERVICE_USER} ${SERVICE_GROUP}
    su ${SERVICE_USER} ${SERVICE_GROUP}
}
EOF

chmod 0644 /etc/systemd/system/siem-alarm-scoring.service
chmod 0644 /etc/systemd/system/siem-alarm-scoring.timer
chmod 0644 /etc/logrotate.d/siem-alarm-scoring

echo "[+] Validating installed files and systemd units"
/usr/bin/python3 -m json.tool "${BASE_DIR}/config.siem_alarm.json" >/dev/null
/usr/bin/python3 -m json.tool "${BASE_DIR}/assets.json" >/dev/null
/usr/bin/python3 -m json.tool "${BASE_DIR}/siem_alarm_template_final.json" >/dev/null
/usr/bin/python3 -m json.tool "${BASE_DIR}/siem_alarm_ism_policy.json" >/dev/null
/usr/bin/python3 -c 'import ast, pathlib, sys; [ast.parse(pathlib.Path(p).read_text(encoding="utf-8"), filename=p) for p in sys.argv[1:]]' \
  "${BASE_DIR}/siem_alarm_scoring_final.py" \
  "${BASE_DIR}/wazuh_field_audit_final.py"
systemd-analyze verify \
  /etc/systemd/system/siem-alarm-scoring.service \
  /etc/systemd/system/siem-alarm-scoring.timer
systemctl daemon-reload

echo
echo "[!] Timer was installed but NOT enabled. Complete the production checklist first."
if [[ "${TIMER_WAS_ENABLED}" -eq 1 ]]; then
  echo "[!] The previous timer was enabled and has been disabled for mandatory post-upgrade validation."
fi
echo "[!] Create the dedicated Wazuh Indexer role/user, then edit:"
echo "    ${BASE_DIR}/config.siem_alarm.json"
echo "    ${BASE_DIR}/assets.json"
echo "    ${CONFIG_DIR}/siem-alarm.env"
echo
echo "[+] Recommended next document:"
echo "    ${SCRIPT_DIR}/final_checklist_siem_alarm_wazuh_4_14_7.md"
if [[ -d "${BACKUP_DIR}" ]]; then
  echo "[+] Replaced files were backed up to ${BACKUP_DIR}"
fi
