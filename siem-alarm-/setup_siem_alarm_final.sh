#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/wazuh-risk-scoring"

echo "[+] Creating ${BASE_DIR}"
sudo mkdir -p "${BASE_DIR}/logs"

echo "[+] Copying files from current directory"
sudo cp siem_alarm_scoring_final.py "${BASE_DIR}/siem_alarm_scoring_final.py"
sudo cp wazuh_field_audit_final.py "${BASE_DIR}/wazuh_field_audit_final.py"
sudo cp siem_alarm_template_final.json "${BASE_DIR}/siem_alarm_template_final.json"

if [[ ! -f "${BASE_DIR}/config.siem_alarm.json" ]]; then
  sudo cp config.siem_alarm.example.json "${BASE_DIR}/config.siem_alarm.json"
else
  echo "[!] Existing config.siem_alarm.json preserved"
fi

if [[ ! -f "${BASE_DIR}/assets.json" ]]; then
  sudo cp assets.example.json "${BASE_DIR}/assets.json"
else
  echo "[!] Existing assets.json preserved"
fi

echo "[+] Setting permissions"
sudo chown -R root:root "${BASE_DIR}"
sudo chmod 750 "${BASE_DIR}"
sudo chmod 750 "${BASE_DIR}/logs"
sudo chmod 750 "${BASE_DIR}/siem_alarm_scoring_final.py"
sudo chmod 750 "${BASE_DIR}/wazuh_field_audit_final.py"
sudo chmod 640 "${BASE_DIR}/siem_alarm_template_final.json"
sudo chmod 600 "${BASE_DIR}/config.siem_alarm.json"
sudo chmod 640 "${BASE_DIR}/assets.json"

echo "[+] Validating JSON and Python syntax"
sudo python3 -m json.tool "${BASE_DIR}/config.siem_alarm.json" >/dev/null
sudo python3 -m json.tool "${BASE_DIR}/assets.json" >/dev/null
sudo python3 -m json.tool "${BASE_DIR}/siem_alarm_template_final.json" >/dev/null
sudo python3 -m py_compile "${BASE_DIR}/siem_alarm_scoring_final.py"
sudo python3 -m py_compile "${BASE_DIR}/wazuh_field_audit_final.py"

echo "[+] Installing systemd service and timer units"
sudo tee /etc/systemd/system/siem-alarm-scoring.service >/dev/null <<EOF
[Unit]
Description=SIEM Alarm Scoring - Wazuh Progressive Alarm Aggregation
After=network.target wazuh-indexer.service
Wants=wazuh-indexer.service

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 ${BASE_DIR}/siem_alarm_scoring_final.py --config ${BASE_DIR}/config.siem_alarm.json --once
StandardOutput=append:${BASE_DIR}/logs/siem_alarm_scoring.log
StandardError=append:${BASE_DIR}/logs/siem_alarm_scoring.log
WorkingDirectory=${BASE_DIR}
EOF

sudo tee /etc/systemd/system/siem-alarm-scoring.timer >/dev/null <<EOF
[Unit]
Description=SIEM Alarm Scoring Timer - update alarm every 5 minutes
Requires=siem-alarm-scoring.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload

echo
echo "[!] Edit indexer password:"
echo "    sudo nano ${BASE_DIR}/config.siem_alarm.json"
echo
echo "[+] Run field audit:"
echo "    sudo python3 ${BASE_DIR}/wazuh_field_audit_final.py --url https://127.0.0.1:9200 --user admin --password 'PASSWORD_INDEXER' --hours 24 --limit 3000"
echo
echo "[+] Run scoring once:"
echo "    sudo python3 ${BASE_DIR}/siem_alarm_scoring_final.py --config ${BASE_DIR}/config.siem_alarm.json --once"
echo
echo "[+] Enable the 5-minute systemd timer after editing config:"
echo "    sudo systemctl enable --now siem-alarm-scoring.timer"
echo "    sudo systemctl list-timers --all | grep siem-alarm"
