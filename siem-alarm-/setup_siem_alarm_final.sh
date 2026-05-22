#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/wazuh-risk-scoring"

echo "[+] Creating ${BASE_DIR}"
sudo mkdir -p "${BASE_DIR}/logs"

echo "[+] Copying files from current directory"
sudo cp siem_alarm_scoring_final.py "${BASE_DIR}/siem_alarm_scoring_final.py"
sudo cp wazuh_field_audit_final.py "${BASE_DIR}/wazuh_field_audit_final.py"

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
sudo chmod 600 "${BASE_DIR}/config.siem_alarm.json"
sudo chmod 640 "${BASE_DIR}/assets.json"

echo "[+] Validating JSON and Python syntax"
sudo python3 -m json.tool "${BASE_DIR}/config.siem_alarm.json" >/dev/null
sudo python3 -m json.tool "${BASE_DIR}/assets.json" >/dev/null
sudo python3 -m py_compile "${BASE_DIR}/siem_alarm_scoring_final.py"
sudo python3 -m py_compile "${BASE_DIR}/wazuh_field_audit_final.py"

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
echo "[+] Cron example every 5 minutes:"
echo "    */5 * * * * /usr/bin/python3 ${BASE_DIR}/siem_alarm_scoring_final.py --config ${BASE_DIR}/config.siem_alarm.json --once >> ${BASE_DIR}/logs/cron.log 2>&1"
