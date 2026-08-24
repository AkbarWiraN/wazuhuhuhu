# FINAL CHECKLIST Implementasi `siem-alarm-*` di Wazuh 4.14.2 AIO

> **Versi 4.0** — Production-hardened Progressive Alarm + Immutable Escalation Log
> Timer: 5 menit | Bucket: 1 jam | Log eskalasi: dokumen baru saat risk.level masuk Medium/High/Critical atau naik

---

## 0. Keputusan Desain Final

- Wazuh 4.14.2 berjalan **single node / all-in-one** di Ubuntu VM.
- `wazuh-alerts-*` **tetap dipertahankan** sebagai raw evidence.
- `siem-alarm-*` adalah index baru untuk **alarm agregasi SOC**, bukan copy mentah.
- Default deduplication key:

```text
agent.id + rule.id + timestamp_bucket_1h
```

- Script jalan **setiap 5 menit**, bucket tetap **1 jam**.
- `alarm.id` dibuat deterministik dari hash `case_key` → update, bukan duplikasi.
- Log eskalasi dibuat secara **create-only sebelum state di-update** saat risk.level pertama kali masuk Medium/High/Critical atau naik ke level lebih tinggi.
- Satu host hanya boleh menjalankan satu proses scoring; lock default: `/opt/wazuh-risk-scoring/logs/scoring.lock`.
- TLS verification wajib untuk production menggunakan salinan Wazuh root CA.
- Runtime memakai user Linux dan user Wazuh Indexer khusus `siem-alarm`, bukan `root`/`admin`.
- Field `srcip`, `dstip`, `dstport`, `proto`, `url`, `user`, `file_path`, `hash`, `CVE`, SCA = **evidence**, bukan pemecah case.

---

## 1. Tujuan Implementasi

```text
Mengurangi alert fatigue SOC dengan mengubah banyak raw alert Wazuh menjadi
alarm agregasi yang lebih sedikit, lebih prioritas, dan lebih mudah dianalisis.
```

Desain data:

```text
wazuh-alerts-* = raw alert / evidence asli (tidak diubah)
siem-alarm-*   = aggregated SOC alarm, di-update tiap 5 menit, bucket 1 jam
```

Contoh alur progressive alarm untuk aset critical (`asset_value=5`) dan rule high threat (`threat_score=4`):

```text
Menit 00 → 3 alert masuk   → raw_alert_count=3   → score=3.33 → risk=Medium   → alarm TERBENTUK + LOG ESKALASI ①
Menit 05 → 12 alert masuk  → raw_alert_count=15  → score=3.67 → risk=High     → alarm UPDATE + LOG ESKALASI ②
Menit 10 → 40 alert masuk  → raw_alert_count=55  → score=4.00 → risk=High     → alarm UPDATE (silent)
Menit 20 → 65 alert masuk  → raw_alert_count=120 → score=4.33 → risk=High     → alarm UPDATE (silent)
Menit 35 → 390 alert masuk → raw_alert_count=510 → score=4.67 → risk=Critical → alarm UPDATE + LOG ESKALASI ③
Menit 40 → 20 alert masuk  → raw_alert_count=530 → score=4.67 → risk=Critical → alarm UPDATE (silent)
```

Hasil akhir bucket 1 jam:

```text
1 dokumen alarm_state di siem-alarm-* | raw_alert_count=530 | 3 dokumen alarm_escalation dibuat
```

---

## 2. Definisi Final "Alert yang Sama"

### 2.1 Definisi default

```text
Alert dianggap sama jika:
  agent.id sama
  rule.id sama
  berada dalam bucket waktu 1 jam yang sama
```

Case key internal:

```text
coarse|<agent.id>|<rule.id>|<timestamp_bucket_1h>
```

Contoh:

```text
coarse|003|2010935|2026-05-22T10:00:00Z
```

`alarm.id` = `sha256(case_key)` → stabil, deterministik, dipakai sebagai document ID di index.

Gunakan hash SHA-256 penuh 64 karakter hex. Jangan memotong hash menjadi 32 karakter karena document ID OpenSearch bebas menerima string panjang dan hash penuh menurunkan risiko collision.

### 2.2 Kenapa `srcip` tidak masuk primary key?

Attacker bisa pakai proxy, VPN, botnet, rotating IP, cloud scanner. Jika `srcip` jadi primary key, satu attack wave pecah jadi banyak alarm.

### 2.3 Posisi field network

Disimpan sebagai evidence, bukan pemecah:

```text
source_observed.srcip_unique_count
source_observed.srcip_samples
source_observed.top_srcip
target_observed.dstip_unique_count
target_observed.dstip_samples
target_observed.dstport_samples
target_observed.proto_samples
```

### 2.4 Mode lanjutan opsional

```text
coarse      = default (agent.id + rule.id + bucket_1h)
target_aware = agent.id + rule.id + dstip + bucket_1h
smart        = rule-specific, misal FIM pakai syscheck.path
```

Gunakan mode lanjutan hanya jika SOC menilai default terlalu kasar untuk rule tertentu.

---

## 3. Definisi `raw_alert_count`

```text
raw_alert_count = jumlah dokumen wazuh-alerts-* yang tergabung ke satu siem-alarm-*
                  berdasarkan case_key yang sama dalam bucket 1 jam berjalan.
```

Tiga field ini harus selalu sama nilainya:

```text
source.raw_alert_count = alarm.event_count = risk.frequency_count_1h
```

Nilai ini **bertambah setiap kali script jalan** selama bucket masih berjalan.

Perbedaan penting:

```text
alarm_state.source.raw_alert_count      = kondisi terbaru/final bucket
alarm_escalation.source.raw_alert_count = snapshot saat log eskalasi dibuat
```

Jadi jika `alarm_escalation` level Medium punya `raw_alert_count=55`, lalu `alarm_state` akhir bucket punya `raw_alert_count=510`, itu normal dan bukan inkonsistensi.

---

## 4. Rumus Risk Scoring

### 4.1 Rumus

```text
Risk Score = (Asset Value + Threat Level + Frequency Score) / 3
```

### 4.2 A — Asset Value

| Nilai | Kategori | Contoh |
|---:|---|---|
| 5 | Critical | Database server, AD/LDAP, firewall |
| 4 | High | Web server, mail server, VPN |
| 3 | Medium | Internal app server |
| 2 | Low | Workstation, printer |
| 1 | Minimal | Dev/test environment |

### 4.3 B — Threat Level dari `rule.level`

| Wazuh Rule Level | Threat Score |
|---:|---:|
| 0–3 | 1 |
| 4–6 | 2 |
| 7–9 | 3 |
| 10–12 | 4 |
| ≥13 | 5 |

### 4.4 C — Frequency Score

| raw_alert_count dalam bucket 1 jam | Frequency Score |
|---:|---:|
| 1–9 | 1 |
| 10–49 | 2 |
| 50–99 | 3 |
| 100–499 | 4 |
| ≥500 | 5 |

### 4.5 Risk Level

| Risk Score | Risk Level |
|---:|---|
| 1.00–1.49 | Information |
| 1.50–2.49 | Low |
| 2.50–3.49 | Medium |
| 3.50–4.49 | High |
| 4.50–5.00 | Critical |

---

## 5. Asset Value

### 5.1 Prioritas sumber

```text
1. Agent labels dari alert Wazuh
2. assets.json
3. Default = Medium (3)
```

### 5.2 Label yang direkomendasikan

```xml
<labels>
  <label key="asset.value">5</label>
  <label key="asset.category">Critical</label>
  <label key="asset.type">Database Server</label>
  <label key="asset.owner">Diskominfo</label>
  <label key="asset.environment">Production</label>
</labels>
```

### 5.3 Validasi label

```json
GET wazuh-alerts-*/_search
{
  "size": 5,
  "_source": ["timestamp", "agent", "agent.labels", "labels", "asset", "rule"],
  "sort": [{ "timestamp": { "order": "desc" } }]
}
```

---

## 6. Struktur Dokumen `siem-alarm-*`

Contoh dokumen dengan progressive alarm state:

```json
{
  "timestamp": "2026-05-22T10:00:00Z",
  "document": {
    "type": "alarm_state"
  },
  "alarm": {
    "id": "a3f9c2b1d4e8...",
    "case_key": "coarse|003|2010935|2026-05-22T10:00:00Z",
    "deduplication_mode": "coarse",
    "case_type": "coarse_rule_agent",
    "status": "open",
    "dedup_key_fields": ["agent.id", "rule.id", "timestamp_bucket_1h"],
    "bucket_start": "2026-05-22T10:00:00Z",
    "bucket_size": "1h",
    "first_seen": "2026-05-22T10:03:20Z",
    "last_seen": "2026-05-22T10:35:50Z",
    "event_count": 510
  },
  "agent": {
    "id": "003",
    "name": "pfsense-suricata",
    "ip": "10.10.10.1"
  },
  "rule": {
    "id": "2010935",
    "level": 12,
    "description": "ET WEB_SERVER Possible WebShell Upload",
    "groups": ["ids", "suricata"]
  },
  "source_observed": {
    "srcip_unique_count": 100,
    "srcip_samples": ["45.10.1.1", "103.22.5.9"],
    "top_srcip": [
      {"value": "45.10.1.1", "count": 40}
    ]
  },
  "target_observed": {
    "dstip_unique_count": 3,
    "dstip_samples": ["10.10.10.10", "10.10.10.20"],
    "dstport_samples": ["80", "443"],
    "proto_samples": ["TCP"]
  },
  "asset": {
    "value": 5,
    "category": "Critical",
    "type": "Firewall/IDS Sensor",
    "owner": "Diskominfo",
    "environment": "Production",
    "source": "agent_label"
  },
  "risk": {
    "asset_value": 5,
    "threat_score": 4,
    "frequency_count_1h": 510,
    "frequency_score": 5,
    "score": 4.67,
    "level": "Critical",
    "previous_level": "High",
    "level_changed": true,
    "escalation_log_required": true,
    "level_history": [
      {"level": "Medium",   "at": "2026-05-22T10:03:20Z"},
      {"level": "High",     "at": "2026-05-22T10:05:10Z"},
      {"level": "Critical", "at": "2026-05-22T10:35:50Z"}
    ],
    "formula": "(A+B+C)/3"
  },
  "source": {
    "index": "wazuh-alerts-*",
    "raw_alert_count": 510,
    "sample_document_id": "abc123"
  },
  "soc": {
    "recommended_action": "Investigate",
    "sla": "1 hour",
    "notification": true,
    "escalation_log": true
  }
}
```

Contoh dokumen log eskalasi yang dibuat saat level naik:

```json
{
  "timestamp": "2026-05-22T10:35:50Z",
  "document": {
    "type": "alarm_escalation"
  },
  "event": {
    "kind": "alert",
    "category": ["siem_alarm"],
    "type": ["change"],
    "action": "risk_level_escalated",
    "created": "2026-05-22T10:35:55Z"
  },
  "escalation": {
    "id": "f6a8...",
    "state_alarm_id": "a3f9c2b1d4e8...",
    "level": "Critical",
    "previous_level": "High",
    "reason": "risk_level_increased"
  },
  "alarm": {
    "id": "a3f9c2b1d4e8...",
    "case_key": "coarse|003|2010935|2026-05-22T10:00:00Z",
    "bucket_start": "2026-05-22T10:00:00Z",
    "last_seen": "2026-05-22T10:35:50Z",
    "event_count": 510
  },
  "risk": {
    "score": 4.67,
    "level": "Critical",
    "previous_level": "High"
  },
  "source": {
    "raw_alert_count": 510
  },
  "soc": {
    "notification": true,
    "escalation_log": true
  }
}
```

### 6.1 Tipe dokumen

| `document.type` | Fungsi | Perilaku |
|---|---|---|
| `alarm_state` | State agregasi utama | Di-update dengan `alarm.id` yang sama |
| `alarm_escalation` | Log event untuk aplikasi eksternal | Dokumen baru saat level pertama kali eligible atau naik |

### 6.2 Penjelasan field risk baru

| Field | Tipe | Keterangan |
|---|---|---|
| `risk.previous_level` | keyword | Risk level sebelum update ini |
| `risk.level_changed` | boolean | `true` jika level naik dari sebelumnya |
| `risk.level_history` | array | Riwayat semua eskalasi level dalam bucket |

> **Penting**: `level_changed` di-set `true` **hanya saat level naik**. Jika level turun (sangat jarang dalam bucket berjalan) atau sama, `level_changed = false`.

### 6.3 Logika `alarm.id` sebagai document ID

```text
alarm.id = sha256(case_key)

Script menggunakan:
  PUT siem-alarm-*/_doc/<alarm.id>

Karena document ID sama → dokumen yang ada di-UPDATE, bukan INSERT baru.
Tidak ada duplikasi dokumen untuk case_key yang sama dalam satu bucket.
```

---

## 7. Instalasi File

### 7.1 Preflight

```bash
cd /path/ke/folder/siem-alarm-
sudo bash ./setup_siem_alarm_final.sh
```

Installer wajib dijalankan dari paket lengkap, tetapi tidak bergantung pada current directory setelah path script ditemukan. Installer akan:

- Memvalidasi seluruh Python/JSON dan menjalankan automated unit tests sebelum mengubah `/opt` atau systemd.
- Membuat user/group Linux `siem-alarm`.
- Menyalin Wazuh CA dari `/etc/wazuh-indexer/certs/root-ca.pem`.
- Membuat backup file lama di `/opt/wazuh-risk-scoring/backups/<UTC timestamp>`.
- Mempertahankan config, assets, dan environment file yang sudah ada.
- Memasang service, timer, dan logrotate tetapi **tidak meng-enable timer**.
- Menjalankan `systemd-analyze verify`.

Jika CA berada di lokasi lain:

```bash
sudo WAZUH_CA_SOURCE=/path/root-ca.pem bash ./setup_siem_alarm_final.sh
```

### 7.2 File hasil instalasi

```text
/opt/wazuh-risk-scoring/siem_alarm_scoring_final.py
/opt/wazuh-risk-scoring/wazuh_field_audit_final.py
/opt/wazuh-risk-scoring/siem_alarm_template_final.json
/opt/wazuh-risk-scoring/siem_alarm_ism_policy.json
/opt/wazuh-risk-scoring/config.siem_alarm.json
/opt/wazuh-risk-scoring/assets.json
/opt/wazuh-risk-scoring/root-ca.pem
/etc/wazuh-risk-scoring/siem-alarm.env
/etc/systemd/system/siem-alarm-scoring.service
/etc/systemd/system/siem-alarm-scoring.timer
/etc/logrotate.d/siem-alarm-scoring
```

> Repository menyimpan script installer sebagai file biasa. Gunakan `sudo bash ./setup_siem_alarm_final.sh`; tidak perlu mengandalkan executable bit.

---

## 8. Validasi Wazuh AIO

### 8.1 Cek service

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
sudo systemctl status filebeat
```

### 8.2 Cek koneksi indexer

Sebelum test, buat internal user `siem_alarm_service` dan custom role melalui **Indexer Management → Security** dengan prinsip least privilege:

- Read/search pada `wazuh-alerts-*`.
- Create index dan create/update document pada `siem-alarm-*`.
- Tidak diberi akses ke Security API, system index, atau index Wazuh lain.
- Template dan ISM policy dipasang satu kali memakai administrator; runtime account tidak memerlukan cluster-admin.

Gunakan input password interaktif dan verifikasi CA. Jangan memasukkan password ke argumen command.

```bash
curl --fail --silent --show-error \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  https://127.0.0.1:9200
```

> Jika certificate SAN tidak memuat `127.0.0.1`, ganti URL dengan hostname/IP yang tercantum pada sertifikat. Jangan kembali memakai `-k` di production.

### 8.3 Cek raw alert

```bash
curl --fail --silent --show-error \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=1&pretty"
```

---

## 9. Audit Field Wazuh

### 9.1 Kenapa wajib

Field Wazuh bersifat dynamic tergantung decoder. Audit wajib dilakukan sebelum production.

### 9.2 Jalankan audit

**Cara aman — input interaktif + CA verification:**

```bash
sudo -u siem-alarm /usr/bin/python3 -B \
  /opt/wazuh-risk-scoring/wazuh_field_audit_final.py \
  --url https://127.0.0.1:9200 \
  --user siem_alarm_service \
  --verify-ssl \
  --ca-cert /opt/wazuh-risk-scoring/root-ca.pem \
  --hours 24 \
  --limit 3000 \
  --output /opt/wazuh-risk-scoring/logs/wazuh_field_audit_report.json
```

Jika hanya untuk diagnosis sertifikat, opsi `--insecure` tersedia. Jangan gunakan sebagai konfigurasi production permanen.

```bash
sudo -u siem-alarm /usr/bin/python3 -B \
  /opt/wazuh-risk-scoring/wazuh_field_audit_final.py \
  --url https://127.0.0.1:9200 \
  --user siem_alarm_service \
  --insecure --hours 1 --limit 100 \
  --output /opt/wazuh-risk-scoring/logs/wazuh_field_audit_report.json
```

Laporan dibuat dengan mode `0600` dan penulisan melalui symbolic link ditolak pada Linux.

### 9.3 Yang harus dicek dari laporan

- [ ] Top `rule.id` paling noisy.
- [ ] Top `rule.groups`.
- [ ] Field yang muncul untuk `srcip`.
- [ ] Field yang muncul untuk `dstip`.
- [ ] Field yang muncul untuk `dstport`.
- [ ] Field yang muncul untuk `proto`.
- [ ] Field yang muncul untuk `url`.
- [ ] Field yang muncul untuk `user`.
- [ ] Field FIM seperti `syscheck.path`.
- [ ] Field vulnerability seperti `vulnerability.cve`.
- [ ] Field SCA seperti `sca.check.id`.
- [ ] Field custom dari custom decoder.

---

## 10. Buat Index Template

### 10.1 Instalasi satu kali

Runtime tidak lagi meng-install template setiap 5 menit:

```json
"install_template": false
```

Install template satu kali menggunakan administrator Indexer; `--user admin` akan meminta password secara interaktif:

```bash
sudo curl --fail --silent --show-error \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  -H 'Content-Type: application/json' \
  -X PUT 'https://127.0.0.1:9200/_index_template/siem-alarm-template' \
  --data-binary @/opt/wazuh-risk-scoring/siem_alarm_template_final.json
```

Install retention policy 90 hari satu kali. Sesuaikan `min_index_age` di file sebelum command bila kebijakan organisasi berbeda:

```bash
sudo curl --fail --silent --show-error \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  -H 'Content-Type: application/json' \
  -X PUT 'https://127.0.0.1:9200/_plugins/_ism/policies/siem-alarm-retention-90d' \
  --data-binary @/opt/wazuh-risk-scoring/siem_alarm_ism_policy.json
```

> Jika `destination_index_prefix` bukan `siem-alarm`, ubah `index_patterns` pada kedua file JSON sebelum instalasi. Fungsi template internal Python otomatis mengikuti prefix config, tetapi file manual harus tetap disinkronkan.

### 10.2 Pastikan mapping mencakup field baru

Field berikut harus ada di template:

```json
"document": {
  "properties": {
    "type": { "type": "keyword" }
  }
},
"event": {
  "properties": {
    "kind": { "type": "keyword" },
    "category": { "type": "keyword" },
    "type": { "type": "keyword" },
    "action": { "type": "keyword" },
    "created": { "type": "date" }
  }
},
"escalation": {
  "properties": {
    "id": { "type": "keyword" },
    "state_alarm_id": { "type": "keyword" },
    "level": { "type": "keyword" },
    "previous_level": { "type": "keyword" },
    "reason": { "type": "keyword" }
  }
},
"risk": {
  "properties": {
    "previous_level": { "type": "keyword" },
    "level_changed": { "type": "boolean" },
    "escalation_log_required": { "type": "boolean" },
    "level_history": {
      "type": "nested",
      "properties": {
        "level": { "type": "keyword" },
        "at": { "type": "date" }
      }
    }
  }
},
"rule": {
  "properties": {
    "level_strategy": { "type": "keyword" },
    "max_level": { "type": "integer" },
    "mode_level": { "type": "integer" },
    "median_level": { "type": "integer" },
    "level_counts": {
      "properties": {
        "level": { "type": "integer" },
        "count": { "type": "integer" }
      }
    }
  }
},
"soc": {
  "properties": {
    "notification": { "type": "boolean" },
    "escalation_log": { "type": "boolean" }
  }
}
```

> **Catatan sinkronisasi template**: `siem_alarm_template_final.json` dan fungsi `template()` di `siem_alarm_scoring_final.py` harus selalu di-update bersama. Automated test memverifikasi keduanya identik untuk prefix default.

### 10.3 Via Dev Tools

```text
Wazuh Dashboard → Indexer Management → Dev Tools
```

---

## 11. Jalankan Script Manual

### 11.1 Edit config

```bash
sudoedit /opt/wazuh-risk-scoring/config.siem_alarm.json
sudoedit /opt/wazuh-risk-scoring/assets.json
sudoedit /etc/wazuh-risk-scoring/siem-alarm.env
```

Pastikan config memakai nama key yang memang dibaca oleh script:

```json
{
  "opensearch_url": "https://127.0.0.1:9200",
  "username": "siem_alarm_service",
  "password_env": "WAZUH_PASS",
  "verify_ssl": true,
  "ca_cert": "/opt/wazuh-risk-scoring/root-ca.pem",
  "retry_attempts": 4,
  "retry_backoff_seconds": 1.0,
  "bucket_minutes": 60,
  "lookback_minutes": 60,
  "process_current_bucket_only": true,
  "lookback_overlap_minutes": 7,
  "escalation_log_enabled": true,
  "escalation_log_levels": ["Medium", "High", "Critical"],
  "threat_level_strategy": "max",
  "max_alerts_per_run": 50000,
  "lock_file": "/opt/wazuh-risk-scoring/logs/scoring.lock",
  "install_template": false
}
```

Environment file root-only harus berisi password sebenarnya:

```text
WAZUH_PASS="PASSWORD_INDEXER_SEBENARNYA"
```

Program menolak placeholder `GANTI_*`/`CHANGE_*`, prefix index yang tidak aman, numeric limit di luar batas, CA yang tidak ada, dan bucket yang tidak membagi 1 hari secara utuh.

Interval eksekusi 5 menit diatur oleh systemd timer `OnCalendar=*-*-* *:0/5:00`, bukan oleh key `schedule_interval_minutes` di config.
Mode `--loop` tersedia di script untuk testing, tetapi tidak direkomendasikan untuk production. Untuk production gunakan systemd timer.

### 11.2 Test syntax

```bash
sudo -u siem-alarm /usr/bin/python3 -B \
  /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py --help >/dev/null
```

### 11.3 Run manual (--once)

```bash
sudo systemctl start siem-alarm-scoring.service
sudo systemctl show siem-alarm-scoring.service -p Result -p ExecMainStatus
```

### 11.4 Cek log

```bash
sudo tail -n 100 /opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
sudo journalctl -u siem-alarm-scoring.service -n 100 --no-pager
```

### 11.5 Cek index

```bash
curl --fail --silent --show-error \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  "https://127.0.0.1:9200/_cat/indices/siem-alarm-*?v"
```

### 11.6 Validasi progressive update

Jalankan script dua kali dengan jeda, pastikan `raw_alert_count` bertambah dan document ID tetap sama:

```bash
# Run pertama
sudo systemctl start siem-alarm-scoring.service

# Ambil alarm_state terbaru dan catat alarm.id + raw_alert_count
curl --fail --silent --show-error \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service -X GET \
  "https://127.0.0.1:9200/siem-alarm-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 5,
    "sort": [{ "alarm.last_seen": { "order": "desc" } }],
    "query": { "term": { "document.type": "alarm_state" } },
    "_source": ["alarm.id", "alarm.case_key", "alarm.last_seen", "source.raw_alert_count", "risk.level"]
  }'

# Tunggu 5 menit atau tunggu alert baru masuk
sleep 300

# Run kedua
sudo systemctl start siem-alarm-scoring.service

# Cek ulang query di atas: alarm.id sama, raw_alert_count bertambah
```

---

## 12. Setup Scheduling (Systemd Timer)

> **Rekomendasi**: Systemd timer dibanding cron — lebih terintegrasi journald, ada dependency management, mudah di-monitor.

### 12.1 Buat systemd service unit

File ini dibuat otomatis oleh installer. Gunakan isi berikut untuk review:

```ini
[Unit]
Description=SIEM Alarm Scoring - Wazuh Progressive Alarm Aggregation
After=network-online.target wazuh-indexer.service
Wants=network-online.target wazuh-indexer.service

[Service]
Type=oneshot
User=siem-alarm
Group=siem-alarm
EnvironmentFile=/etc/wazuh-risk-scoring/siem-alarm.env
ExecStart=/usr/bin/python3 -B /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py --config /opt/wazuh-risk-scoring/config.siem_alarm.json --once
WorkingDirectory=/opt/wazuh-risk-scoring
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
ReadWritePaths=/opt/wazuh-risk-scoring/logs
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
```

### 12.2 Buat systemd timer unit

File ini juga dibuat otomatis oleh installer:

```ini
[Unit]
Description=SIEM Alarm Scoring Timer - update alarm setiap 5 menit, bucket 1 jam

[Timer]
OnCalendar=*-*-* *:0/5:00
AccuracySec=30s
Persistent=true
Unit=siem-alarm-scoring.service

[Install]
WantedBy=timers.target
```

> **Catatan konfigurasi timer:**
> - `OnCalendar=*-*-* *:0/5:00` — jalankan pada menit 00/05/10/... setiap jam.
> - `AccuracySec=30s` — toleransi 30 detik, cukup presisi untuk SOC tanpa membebani scheduler.
> - `Persistent=true` — efektif karena timer memakai `OnCalendar`; satu catch-up run dijalankan setelah jadwal terlewat.
> - Tidak ada `Requires=siem-alarm-scoring.service`; timer akan mengaktifkan service bernama sama ketika jadwal tiba tanpa menjalankannya prematur saat timer di-start.

### 12.3 Reload dan enable

```bash
sudo systemd-analyze verify \
  /etc/systemd/system/siem-alarm-scoring.service \
  /etc/systemd/system/siem-alarm-scoring.timer
sudo systemctl daemon-reload
sudo systemctl enable --now siem-alarm-scoring.timer
```

### 12.4 Validasi timer aktif

```bash
# Status timer
sudo systemctl status siem-alarm-scoring.timer

# Lihat semua timer aktif + next run
sudo systemctl list-timers --all | grep siem-alarm

# Cek hasil run terakhir
sudo systemctl status siem-alarm-scoring.service
```

Output yang diharapkan dari `list-timers`:

```text
NEXT                        LEFT   LAST                        PASSED  UNIT
Thu 2026-05-22 10:15:00 WIB 3min   Thu 2026-05-22 10:10:02 WIB 1min    siem-alarm-scoring.timer
```

### 12.5 Test manual via systemd

```bash
sudo systemctl start siem-alarm-scoring.service
sudo journalctl -u siem-alarm-scoring.service -n 50 --no-pager
```

### 12.6 Troubleshooting scheduling

**Timer tidak muncul:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now siem-alarm-scoring.timer
```

**Service gagal:**
```bash
sudo journalctl -u siem-alarm-scoring.service -n 100 --no-pager
sudo tail -n 100 /opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
```

**Cek python path:**
```bash
test -x /usr/bin/python3 && /usr/bin/python3 --version
# Installer berhenti sebelum mutasi jika /usr/bin/python3 tidak tersedia.
```

**Reset setelah perubahan:**
```bash
sudo systemctl daemon-reload
sudo systemctl restart siem-alarm-scoring.timer
```

### 12.7 Manual backfill setelah outage

`lookback_overlap_minutes=7` melindungi alert di akhir bucket jika service terlambat beberapa menit. Jika VM/service mati lebih lama dari overlap tersebut, jalankan backfill manual dengan window waktu eksplisit.

Gunakan waktu UTC dan mulai dari awal bucket:

```bash
sudo systemctl stop siem-alarm-scoring.timer
read -rsp 'Indexer password: ' WAZUH_PASS; echo
export WAZUH_PASS
sudo --preserve-env=WAZUH_PASS -u siem-alarm /usr/bin/python3 -B \
  /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py \
  --config /opt/wazuh-risk-scoring/config.siem_alarm.json \
  --once \
  --from 2026-05-22T10:00:00Z \
  --to 2026-05-22T12:00:00Z
unset WAZUH_PASS
sudo systemctl start siem-alarm-scoring.timer
```

Catatan:
- Gunakan `--from` pada awal jam/bucket agar count bucket awal tidak parsial.
- `--from` bersifat inclusive (`>=`) dan `--to` bersifat exclusive (`<`). Contoh di atas memproses `10:00:00Z <= timestamp < 12:00:00Z`.
- Jangan gunakan `--loop` untuk backfill.
- Hentikan timer selama backfill agar run calendar tidak bertabrakan; lock tetap menjadi pengaman terakhir.
- Jika jumlah alert sangat besar dan run berhenti karena `max_alerts_per_run`, naikkan limit sementara atau pecah backfill menjadi window lebih kecil.
- Backfill historis dapat membuat dokumen `alarm_escalation` lama. Untuk mencegah aplikasi eksternal menganggapnya alert baru, pertimbangkan set sementara `"escalation_log_enabled": false` saat backfill historis, atau pastikan aplikasi eksternal memfilter window waktu yang benar.

### 12.8 Checklist scheduling

- [ ] `/etc/systemd/system/siem-alarm-scoring.service` dibuat.
- [ ] `/etc/systemd/system/siem-alarm-scoring.timer` dibuat.
- [ ] `OnCalendar=*-*-* *:0/5:00` sudah terkonfigurasi.
- [ ] `systemctl daemon-reload` dijalankan.
- [ ] Timer di-enable dan di-start.
- [ ] `systemctl list-timers` menampilkan NEXT run dalam ~5 menit.
- [ ] Service berhasil jalan minimal sekali.
- [ ] Log tidak ada error.
- [ ] `raw_alert_count` bertambah antara dua run berturutan (validasi progressive update).

---

## 13. Buat Index Pattern di Wazuh Dashboard

- [ ] Buka Wazuh Dashboard → Dashboard Management → Index Patterns.
- [ ] Create index pattern: `siem-alarm-*`
- [ ] Time field: `timestamp`
- [ ] Buka Discover → pilih `siem-alarm-*` → set `Last 24 hours`.

> `alarm_state.timestamp` adalah awal bucket 1 jam. `alarm_escalation.timestamp` adalah waktu event eskalasi (`alarm.last_seen`). Untuk dashboard case utama gunakan filter `document.type = alarm_state`; untuk panel eskalasi gunakan `document.type = alarm_escalation`.

---

## 14. Validasi `raw_alert_count` dan Progressive Update

### 14.1 Query alarm terbesar

```json
GET siem-alarm-*/_search
{
  "size": 5,
  "query": {
    "term": { "document.type": "alarm_state" }
  },
  "sort": [{ "source.raw_alert_count": { "order": "desc" } }]
}
```

Validasi:

```text
source.raw_alert_count = alarm.event_count = risk.frequency_count_1h
```

### 14.2 Validasi progressive update

Cek dokumen `alarm_escalation` untuk memastikan log eskalasi tercatat:

```json
GET siem-alarm-*/_search
{
  "size": 5,
  "query": {
    "term": { "document.type": "alarm_escalation" }
  },
  "_source": [
    "document.type",
    "escalation",
    "alarm.case_key",
    "risk.level",
    "risk.previous_level",
    "risk.level_history",
    "source.raw_alert_count"
  ]
}
```

### 14.3 Cross-check manual ke raw alert

```json
GET wazuh-alerts-*/_count
{
  "query": {
    "bool": {
      "must": [
        { "term": { "agent.id": "003" }},
        { "term": { "rule.id": "2010935" }},
        {
          "range": {
            "timestamp": {
              "gte": "2026-05-22T10:00:00Z",
              "lt": "2026-05-22T11:00:00Z"
            }
          }
        }
      ]
    }
  }
}
```

Hasil `_count` harus sama dengan `source.raw_alert_count` pada bucket tersebut di akhir jam.

---

## 15. Dashboard SOC

### 15.1 Panel wajib

Filter default untuk panel case utama:

```json
{ "term": { "document.type": "alarm_state" } }
```

- [ ] Total alarm Critical.
- [ ] Total alarm High.
- [ ] Distribusi `risk.level`.
- [ ] Top `agent.name`.
- [ ] Top `rule.id` dan `rule.description`.
- [ ] Top `source.raw_alert_count` (alarm paling noisy).
- [ ] Top `source_observed.srcip_unique_count`.
- [ ] Trend alarm per jam berdasarkan `timestamp`.
- [ ] **Panel eskalasi**: dokumen `document.type = alarm_escalation` dalam 1 jam terakhir.
- [ ] Table investigasi utama.

Filter khusus panel eskalasi:

```json
{ "term": { "document.type": "alarm_escalation" } }
```

### 15.2 Kolom table investigasi

```text
document.type
Time (dari timestamp)
alarm.case_key
alarm.event_count
alarm.first_seen
alarm.last_seen
agent.name
rule.id
rule.level
rule.description
source.raw_alert_count
risk.score
risk.level
risk.previous_level
risk.level_changed
risk.level_history
source_observed.srcip_unique_count
source_observed.srcip_samples
target_observed.dstip_unique_count
asset.value
asset.category
soc.recommended_action
soc.sla
```

---

## 16. Log Eskalasi di `siem-alarm-*`

### 16.1 Prinsip

```text
Yang dimaksud "notifikasi" pada desain ini adalah **log event baru di `siem-alarm-*`**, bukan pengiriman Telegram/Slack/email langsung.

Script tetap meng-update dokumen state alarm:

document.type = alarm_state

Selain itu, script membuat dokumen event baru:

document.type = alarm_escalation

Dokumen `alarm_escalation` dibuat saat alarm pertama kali masuk level yang perlu ditindaklanjuti atau saat risk.level naik ke level yang lebih tinggi.

Low      = hanya update alarm_state, tidak membuat alarm_escalation
Medium   = buat log alarm_escalation
High     = buat log alarm_escalation baru
Critical = buat log alarm_escalation baru

Aplikasi notifikasi eksternal, misalnya Telegram app terpisah, cukup membaca dokumen `alarm_escalation` dari `siem-alarm-*`.

Nilai `source.raw_alert_count` pada `alarm_escalation` adalah snapshot pada saat eskalasi dibuat, bukan nilai final bucket.
```

### 16.2 Trigger condition

```text
document.type = "alarm_escalation"
DAN
risk.level IN ["Medium", "High", "Critical"]
```

### 16.3 Anti duplikasi

Gunakan document ID deterministik berikut untuk log eskalasi:

```text
sha256("escalation|" + alarm.id + "|" + risk.level)
```

Satu `alarm.id` + satu `risk.level` hanya menghasilkan satu dokumen `alarm_escalation` per bucket. Jika 5 menit berikutnya level tetap sama, script hanya meng-update `alarm_state` dan tidak membuat log eskalasi baru.

Script memakai endpoint create-only (`PUT <index>/_create/<escalation.id>`) dan memperlakukan HTTP 409 sebagai "sudah ada". Escalation event dibuat **sebelum** state di-update. Jika state write gagal, run berikutnya menemukan escalation ID yang sama lalu mengulangi state write; event tidak hilang dan tidak terduplikasi.

### 16.4 Contoh query untuk aplikasi eksternal

```json
GET siem-alarm-*/_search
{
  "size": 50,
  "sort": [{ "timestamp": { "order": "desc" } }],
  "query": {
    "bool": {
      "must": [
        { "term": { "document.type": "alarm_escalation" }},
        { "terms": { "risk.level": ["Medium", "High", "Critical"] }}
      ]
    }
  }
}
```

### 16.5 Field penting untuk aplikasi eksternal

```text
document.type
event.action
escalation.id
escalation.state_alarm_id
escalation.level
escalation.previous_level
escalation.reason
alarm.id
alarm.case_key
agent.name
rule.description
source.raw_alert_count
risk.score
risk.level
risk.previous_level
risk.level_history
```

---

## 17. Rule Custom Wazuh

### 17.1 Syarat agar bisa diagregasi

```text
agent.id        → wajib ada
rule.id         → wajib ada
rule.level      → wajib ada
rule.description → wajib ada
timestamp       → wajib ada
```

### 17.2 Checklist custom rule

- [ ] Rule custom punya ID unik.
- [ ] Level masuk akal (tidak semua level 12).
- [ ] Description jelas untuk dashboard SOC.
- [ ] Tidak terlalu noisy tanpa tuning.
- [ ] Field custom penting sudah masuk audit.
- [ ] Jika perlu, field custom masuk evidence extraction.

---

## 18. Tuning Lanjutan

### 18.1 Agregasi terlalu kasar

```json
"rule_overrides": {
  "2010935": { "deduplication_mode": "target_aware" }
}
```

### 18.2 Rule terlalu noisy

```json
"excluded_rule_ids": ["5715", "550"]
```

Jangan hapus dari `wazuh-alerts-*`. Exclude hanya dari proses agregasi.

### 18.3 Threshold log eskalasi terlalu sensitif

Ubah config script dari:

```json
"escalation_log_levels": ["Medium", "High", "Critical"]
```

Menjadi:

```json
"escalation_log_levels": ["High", "Critical"]
```

Agar dokumen `alarm_escalation` hanya dibuat saat level High ke atas.

---

## 19. Kesalahan Fatal yang Harus Dihindari

- [ ] Menghapus atau mengubah `wazuh-alerts-*`.
- [ ] Menganggap `siem-alarm-*` sebagai pengganti evidence.
- [ ] Menyalin semua raw alert ke `siem-alarm-*`.
- [ ] Menggunakan INSERT bukan UPDATE untuk document ID yang sama (menyebabkan duplikasi alarm).
- [ ] Tidak menyimpan `risk.previous_level` → log eskalasi tidak bisa dideteksi.
- [ ] Memasukkan terlalu banyak field ke primary dedup key.
- [ ] Memaksa semua alert punya `srcip` atau `dstip`.
- [ ] Tidak membatasi agregasi dengan bucket waktu.
- [ ] Tidak memvalidasi `raw_alert_count`.
- [ ] Membuat log eskalasi langsung dari `wazuh-alerts-*`.
- [ ] Membuat log eskalasi untuk setiap update 5 menit (bukan hanya saat eligible/naik level).
- [ ] Memberi asset value 5 ke semua agent.
- [ ] Mengetik password indexer langsung di command line.
- [ ] Menjalankan timer dan manual/backfill bersamaan dengan lock file berbeda.
- [ ] Menonaktifkan TLS verification untuk production.
- [ ] Membiarkan runtime meng-install template setiap 5 menit.
- [ ] Meng-update `alarm_state` sebelum memastikan event eskalasi sudah ada.

---

## 20. Go-Live Checklist

**Infrastruktur:**
- [ ] Service Wazuh AIO healthy (manager, indexer, dashboard, filebeat).
- [ ] `wazuh-alerts-*` normal dan terisi.

**Persiapan:**
- [ ] Internal user/role Indexer `siem_alarm_service` dibuat dengan least privilege.
- [ ] TLS verification berhasil memakai `/opt/wazuh-risk-scoring/root-ca.pem`; tidak ada `-k`/`verify_ssl: false` di production.
- [ ] `/etc/wazuh-risk-scoring/siem-alarm.env` berisi secret sebenarnya dan permission `0640 root:siem-alarm`.
- [ ] Audit field sudah dijalankan.
- [ ] Asset value disiapkan via labels atau `assets.json`.
- [ ] Config script sudah disesuaikan (`bucket_minutes: 60`, `lookback_minutes: 60`, `process_current_bucket_only: true`, `lookback_overlap_minutes: 7`, `escalation_log_enabled: true`, `max_alerts_per_run: 50000`, `install_template: false`).
- [ ] Index template `siem-alarm-*` sudah dibuat (termasuk mapping field `risk.level_history`).
- [ ] ISM retention policy sudah dipasang dan umur retensi disetujui pemilik data.

**Validasi script:**
- [ ] Automated unit test lokal berhasil.
- [ ] `systemd-analyze verify` berhasil pada Ubuntu target.
- [ ] Run manual `--once` berhasil.
- [ ] `siem-alarm-*` terbentuk.
- [ ] `raw_alert_count` tervalidasi.
- [ ] Progressive update tervalidasi (run dua kali, count bertambah, document ID sama).
- [ ] `risk.level_history` terisi dengan benar.
- [ ] `risk.level_changed` ter-set `true` saat level naik.

**Scheduling:**
- [ ] Systemd service dan timer dibuat.
- [ ] `systemctl list-timers` menampilkan NEXT run dalam ~5 menit.
- [ ] Timer jalan minimal sekali setelah di-enable.
- [ ] Tidak ada dua proses scoring bersamaan; lock contention menghasilkan exit gagal yang terlihat.

**Dashboard & log eskalasi:**
- [ ] Index pattern `siem-alarm-*` dibuat, time field = `timestamp`.
- [ ] Dashboard SOC dengan panel eskalasi tersedia.
- [ ] Query aplikasi eksternal membaca `document.type = alarm_escalation`.
- [ ] Dedup log eskalasi via `escalation.id` sudah aktif.
- [ ] Test eskalasi: pastikan log baru muncul saat level eligible/naik, bukan setiap update 5 menit.
- [ ] Failure injection: jika state write gagal setelah escalation create, run berikutnya pulih tanpa kehilangan/duplikasi escalation event.

**Operasional:**
- [ ] Log script dimonitor.
- [ ] Logrotate berhasil dan journal tidak berisi duplikasi baris ke file yang sama.
- [ ] Rollback plan disiapkan.
- [ ] Prosedur manual backfill `--from/--to` dipahami untuk outage panjang.
- [ ] SOP SOC diperbarui dengan penjelasan progressive alarm.

---

## 21. Rollback Plan

### 21.1 Kapan rollback dilakukan

```text
- risk.score tidak masuk akal (semua 0 atau semua 5)
- raw_alert_count tidak konsisten
- level_changed selalu true padahal level tidak naik
- Duplikasi dokumen ditemukan (alarm.id tidak unik per bucket)
- Index siem-alarm-* membengkak tidak wajar
- Log escalation storm (dokumen `alarm_escalation` dibuat berulang untuk case dan level yang sama)
```

### 21.2 Langkah rollback

**Step 1 — Stop timer:**
```bash
sudo systemctl stop siem-alarm-scoring.timer
sudo systemctl stop siem-alarm-scoring.service
sudo systemctl disable siem-alarm-scoring.timer
```

**Step 2 — Verifikasi berhenti:**
```bash
sudo systemctl list-timers --all | grep siem-alarm
# Tidak ada entry aktif
```

**Step 3 — Hapus index bermasalah:**
```bash
sudo curl --fail --silent --show-error \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  'https://127.0.0.1:9200/_cat/indices/siem-alarm-*?v'

# Hapus index tertentu
sudo curl --fail --silent --show-error \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin -X DELETE \
  "https://127.0.0.1:9200/siem-alarm-2026.05.22"

# ATAU hapus semua hanya setelah konfirmasi eksplisit
read -r -p 'Ketik HAPUS-SEMUA-SIEM-ALARM: ' CONFIRM_DELETE
if [[ "${CONFIRM_DELETE}" == "HAPUS-SEMUA-SIEM-ALARM" ]]; then
  sudo curl --fail --silent --show-error \
    --cacert /opt/wazuh-risk-scoring/root-ca.pem \
    --user admin -X DELETE \
    "https://127.0.0.1:9200/siem-alarm-*"
else
  echo 'Pembatalan: konfirmasi tidak cocok.'
fi
```

> `wazuh-alerts-*` **TIDAK DISENTUH** dalam rollback apapun.

**Step 4 — Identifikasi penyebab dari log:**
```bash
sudo tail -n 200 /opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
sudo journalctl -u siem-alarm-scoring.service -n 100 --no-pager
```

**Step 5 — Perbaiki config/script:**
```bash
sudoedit /opt/wazuh-risk-scoring/config.siem_alarm.json
# Perubahan source dilakukan di repository, dites, lalu deploy ulang via installer.
```

**Step 6 — Test manual ulang:**
```bash
sudo systemctl start siem-alarm-scoring.service

sudo tail -n 50 /opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
```

**Step 7 — Re-enable setelah yakin benar:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now siem-alarm-scoring.timer
sudo systemctl list-timers | grep siem-alarm
```

### 21.3 Rollback checklist

- [ ] Timer dihentikan sebelum rollback.
- [ ] `wazuh-alerts-*` tidak disentuh.
- [ ] Penyebab diidentifikasi dari log.
- [ ] Script/config diperbaiki.
- [ ] Test manual berhasil sebelum re-enable.
- [ ] Timer di-enable ulang dan NEXT run terlihat.

---

## 22. Kesimpulan Final

Desain final:

```text
wazuh-alerts-*  → raw evidence, tidak pernah diubah
siem-alarm-*    → progressive alarm, di-update tiap 5 menit, bucket 1 jam

Dedup key default  : agent.id + rule.id + timestamp_bucket_1h
alarm.id           : sha256(case_key), dipakai sebagai document ID → update, bukan insert baru
raw_alert_count    : bertambah setiap 5 menit selama bucket berjalan
risk.score         : naik organik seiring raw_alert_count bertambah
Log eskalasi       : dokumen alarm_escalation di siem-alarm-* saat level eligible/naik
Maks log eskalasi  : 3 per alarm per bucket (Medium, High, Critical)
Evidence           : srcip/dstip/port/proto/url/user/file/hash — bukan pemecah case
```

Ini adalah desain yang paling realistis untuk menekan alert fatigue tanpa kehilangan raw evidence dan tetap memberikan visibilitas real-time ke SOC.

---

*Versi 4.0 — Hardening production: escalation create-only sebelum state, retry/backoff, validasi failed shard, process lock, strict config/alert validation, TLS/CA, least-privilege service, calendar timer yang benar-benar persistent, journald + logrotate, backup installer, systemd verification, dan ISM retention policy.*
