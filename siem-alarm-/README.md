# SIEM Alarm Scoring for Wazuh 4.14.7

Progressive alarm aggregation for a single-node/all-in-one Wazuh deployment. Raw evidence in `wazuh-alerts-*` is read-only; aggregated state and immutable escalation events are written to `siem-alarm-*`.

Target yang divalidasi adalah Ubuntu AIO dengan `wazuh-manager`, `wazuh-indexer`, dan `wazuh-dashboard` 4.14.7 serta Filebeat OSS 7.10.2. Installer menolak versi yang berbeda.

## Safety status

The installer performs static validation and unit tests, creates backups, installs hardened systemd units, and leaves the timer disabled. Production activation remains a deliberate operator step after credentials, assets, template, retention, and manual validation are complete.

## Package validation

Run before copying the package to the Wazuh host:

```bash
python3 -B -m unittest discover -s tests -v
bash -n setup_siem_alarm_final.sh
python3 -m json.tool config.siem_alarm.example.json >/dev/null
python3 -m json.tool assets.example.json >/dev/null
python3 -m json.tool siem_alarm_template_final.json >/dev/null
python3 -m json.tool siem_alarm_ism_policy.json >/dev/null
```

## Install on the Wazuh AIO host

```bash
cd /path/ke/folder/siem-alarm-
sudo bash ./setup_siem_alarm_final.sh
```

The installer does not enable the timer. Continue with the complete production checklist before go-live:

- [Production checklist](final_checklist_siem_alarm_wazuh_4_14_7.md)
- Example runtime configuration: `config.siem_alarm.example.json`
- Example asset inventory: `assets.example.json`
- Index template: `siem_alarm_template_final.json`
- 90-day retention policy: `siem_alarm_ism_policy.json`

## Core reliability guarantees

- Deterministic `alarm.id` and escalation IDs.
- Escalation event is create-only and written before alarm state.
- Failed state writes are safe to retry without losing or duplicating escalation events.
- Local process lock prevents timer/manual overlap on the AIO host.
- Search timeout and failed shards abort the run instead of writing partial counts.
- Retry with exponential backoff for transient Indexer failures.
- TLS verification is enabled in the production example.
- Runtime template installation is disabled; template and retention policy are installed once.

Do not place real passwords in this repository. The installed service reads `WAZUH_PASS` from `/etc/wazuh-risk-scoring/siem-alarm.env`, which is restricted to `root:siem-alarm`.
