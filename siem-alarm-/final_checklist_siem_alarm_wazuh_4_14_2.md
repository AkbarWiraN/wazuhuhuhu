# FINAL CHECKLIST Implementasi `siem-alarm-*` di Wazuh 4.14.2 AIO

> **Versi 3.1** — Progressive Alarm + Escalating Notification Pattern
> Timer: 5 menit | Bucket: 1 jam | Notifikasi: setiap kali risk.level naik

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
- Notifikasi dikirim **hanya saat risk.level naik** (Escalating Notification Pattern).
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

Contoh alur progressive alarm:

```text
Menit 00 → 3 alert masuk   → raw_alert_count=3   → risk=Low      → alarm TERBENTUK
Menit 05 → 12 alert masuk  → raw_alert_count=15  → risk=Low      → alarm UPDATE (silent)
Menit 10 → 40 alert masuk  → raw_alert_count=55  → risk=Medium   → alarm UPDATE + NOTIFIKASI ①
Menit 20 → 65 alert masuk  → raw_alert_count=120 → risk=High     → alarm UPDATE + NOTIFIKASI ②
Menit 35 → 390 alert masuk → raw_alert_count=510 → risk=Critical → alarm UPDATE + NOTIFIKASI ③
Menit 40 → 20 alert masuk  → raw_alert_count=530 → risk=Critical → alarm UPDATE (silent)
```

Hasil akhir bucket 1 jam:

```text
1 dokumen siem-alarm-* | raw_alert_count=530 | 3 notifikasi terkirim
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
    "value": 4,
    "category": "High",
    "type": "Firewall/IDS Sensor",
    "owner": "Diskominfo",
    "environment": "Production",
    "source": "assets_json"
  },
  "risk": {
    "asset_value": 4,
    "threat_score": 4,
    "frequency_count_1h": 510,
    "frequency_score": 5,
    "score": 4.33,
    "level": "Critical",
    "previous_level": "High",
    "level_changed": true,
    "level_history": [
      {"level": "Low",      "at": "2026-05-22T10:03:20Z"},
      {"level": "Medium",   "at": "2026-05-22T10:10:05Z"},
      {"level": "High",     "at": "2026-05-22T10:20:10Z"},
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
    "notification": true
  }
}
```

### 6.1 Penjelasan field risk baru

| Field | Tipe | Keterangan |
|---|---|---|
| `risk.previous_level` | keyword | Risk level sebelum update ini |
| `risk.level_changed` | boolean | `true` jika level naik dari sebelumnya |
| `risk.level_history` | array | Riwayat semua eskalasi level dalam bucket |

> **Penting**: `level_changed` di-set `true` **hanya saat level naik**. Jika level turun (sangat jarang dalam bucket berjalan) atau sama, `level_changed = false`.

### 6.2 Logika `alarm.id` sebagai document ID

```text
alarm.id = sha256(case_key)

Script menggunakan:
  PUT siem-alarm-*/_doc/<alarm.id>

Karena document ID sama → dokumen yang ada di-UPDATE, bukan INSERT baru.
Tidak ada duplikasi dokumen untuk case_key yang sama dalam satu bucket.
```

---

## 7. Instalasi File

### 7.1 Buat direktori

```bash
sudo mkdir -p /opt/wazuh-risk-scoring/logs
sudo chown -R root:root /opt/wazuh-risk-scoring
sudo chmod 750 /opt/wazuh-risk-scoring
```

### 7.2 Simpan file

```text
/opt/wazuh-risk-scoring/siem_alarm_scoring_final.py
/opt/wazuh-risk-scoring/config.siem_alarm.json
/opt/wazuh-risk-scoring/assets.json
/opt/wazuh-risk-scoring/wazuh_field_audit_final.py
```

### 7.3 Permission

```bash
sudo chown root:root /opt/wazuh-risk-scoring/*
sudo chmod 750 /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py
sudo chmod 750 /opt/wazuh-risk-scoring/wazuh_field_audit_final.py
sudo chmod 600 /opt/wazuh-risk-scoring/config.siem_alarm.json
sudo chmod 640 /opt/wazuh-risk-scoring/assets.json
```

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

> **Keamanan**: Jangan ketik password langsung di command line — tersimpan di bash history.

**Cara aman — input interaktif:**
```bash
curl -k -u admin https://127.0.0.1:9200
```

**Cara aman — environment variable:**
```bash
export WAZUH_PASS='PASSWORD_INDEXER'
curl -k -u admin:"$WAZUH_PASS" https://127.0.0.1:9200
unset WAZUH_PASS
```

### 8.3 Cek raw alert

```bash
export WAZUH_PASS='PASSWORD_INDEXER'
curl -k -u admin:"$WAZUH_PASS" "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=1&pretty"
unset WAZUH_PASS
```

---

## 9. Audit Field Wazuh

### 9.1 Kenapa wajib

Field Wazuh bersifat dynamic tergantung decoder. Audit wajib dilakukan sebelum production.

### 9.2 Jalankan audit

```bash
sudo python3 /opt/wazuh-risk-scoring/wazuh_field_audit_final.py \
  --url https://127.0.0.1:9200 \
  --user admin \
  --password 'PASSWORD_INDEXER' \
  --hours 24 \
  --limit 3000 \
  --output /tmp/wazuh_field_audit_report.json
```

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

### 10.1 Via script

```json
"install_template": true
```

### 10.2 Pastikan mapping mencakup field baru

Field berikut harus ada di template:

```json
"risk": {
  "properties": {
    "previous_level": { "type": "keyword" },
    "level_changed": { "type": "boolean" },
    "level_history": {
      "type": "nested",
      "properties": {
        "level": { "type": "keyword" },
        "at": { "type": "date" }
      }
    }
  }
}
```

### 10.3 Via Dev Tools

```text
Wazuh Dashboard → Indexer Management → Dev Tools
```

---

## 11. Jalankan Script Manual

### 11.1 Edit config

```bash
sudo nano /opt/wazuh-risk-scoring/config.siem_alarm.json
```

Pastikan config memakai nama key yang memang dibaca oleh script:

```json
{
  "bucket_minutes": 60,
  "lookback_minutes": 60,
  "process_current_bucket_only": true,
  "password": "GANTI_PASSWORD_INDEXER_ANDA",
  "install_template": true
}
```

Interval eksekusi 5 menit diatur oleh systemd timer `OnUnitActiveSec=5min`, bukan oleh key `schedule_interval_minutes` di config.

### 11.2 Test syntax

```bash
sudo python3 -m py_compile /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py
```

### 11.3 Run manual (--once)

```bash
sudo python3 /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py \
  --config /opt/wazuh-risk-scoring/config.siem_alarm.json \
  --once
```

### 11.4 Cek log

```bash
sudo tail -n 100 /opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
```

### 11.5 Cek index

```bash
export WAZUH_PASS='PASSWORD_INDEXER'
curl -k -u admin:"$WAZUH_PASS" "https://127.0.0.1:9200/_cat/indices/siem-alarm-*?v"
unset WAZUH_PASS
```

### 11.6 Validasi progressive update

Jalankan script dua kali dengan jeda, pastikan `raw_alert_count` bertambah dan document ID tetap sama:

```bash
# Run pertama
sudo python3 /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py \
  --config /opt/wazuh-risk-scoring/config.siem_alarm.json --once

# Catat alarm.id dari output log

# Tunggu 5 menit atau tunggu alert baru masuk
sleep 300

# Run kedua
sudo python3 /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py \
  --config /opt/wazuh-risk-scoring/config.siem_alarm.json --once

# Cek: alarm.id sama, raw_alert_count bertambah
```

---

## 12. Setup Scheduling (Systemd Timer)

> **Rekomendasi**: Systemd timer dibanding cron — lebih terintegrasi journald, ada dependency management, mudah di-monitor.

### 12.1 Buat systemd service unit

```bash
sudo nano /etc/systemd/system/siem-alarm-scoring.service
```

```ini
[Unit]
Description=SIEM Alarm Scoring - Wazuh Progressive Alarm Aggregation
After=network.target wazuh-indexer.service
Wants=wazuh-indexer.service

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py \
  --config /opt/wazuh-risk-scoring/config.siem_alarm.json \
  --once
StandardOutput=append:/opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
StandardError=append:/opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
WorkingDirectory=/opt/wazuh-risk-scoring

[Install]
WantedBy=multi-user.target
```

### 12.2 Buat systemd timer unit

```bash
sudo nano /etc/systemd/system/siem-alarm-scoring.timer
```

```ini
[Unit]
Description=SIEM Alarm Scoring Timer - update alarm setiap 5 menit, bucket 1 jam
Requires=siem-alarm-scoring.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
```

> **Catatan konfigurasi timer:**
> - `OnBootSec=2min` — tunggu 2 menit setelah boot sebelum run pertama, beri waktu wazuh-indexer siap.
> - `OnUnitActiveSec=5min` — jalankan tiap 5 menit setelah run sebelumnya selesai.
> - `AccuracySec=30s` — toleransi 30 detik, cukup presisi untuk SOC tanpa membebani scheduler.
> - `Persistent=true` — jika server sempat mati dan melewati jadwal, langsung jalankan saat boot.

### 12.3 Reload dan enable

```bash
sudo systemctl daemon-reload
sudo systemctl enable siem-alarm-scoring.timer
sudo systemctl start siem-alarm-scoring.timer
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
which python3
# Sesuaikan ExecStart jika path berbeda dari /usr/bin/python3
```

**Reset setelah perubahan:**
```bash
sudo systemctl daemon-reload
sudo systemctl restart siem-alarm-scoring.timer
```

### 12.7 Checklist scheduling

- [ ] `/etc/systemd/system/siem-alarm-scoring.service` dibuat.
- [ ] `/etc/systemd/system/siem-alarm-scoring.timer` dibuat.
- [ ] `OnUnitActiveSec=5min` sudah terkonfigurasi.
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

> `timestamp` di `siem-alarm-*` adalah awal bucket 1 jam, bukan waktu update terakhir. Gunakan `alarm.last_seen` untuk waktu event terbaru dalam bucket.

---

## 14. Validasi `raw_alert_count` dan Progressive Update

### 14.1 Query alarm terbesar

```json
GET siem-alarm-*/_search
{
  "size": 5,
  "sort": [{ "source.raw_alert_count": { "order": "desc" } }]
}
```

Validasi:

```text
source.raw_alert_count = alarm.event_count = risk.frequency_count_1h
```

### 14.2 Validasi progressive update

Cek field level_history untuk memastikan eskalasi tercatat:

```json
GET siem-alarm-*/_search
{
  "size": 5,
  "query": {
    "term": { "risk.level_changed": true }
  },
  "_source": [
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

- [ ] Total alarm Critical.
- [ ] Total alarm High.
- [ ] Distribusi `risk.level`.
- [ ] Top `agent.name`.
- [ ] Top `rule.id` dan `rule.description`.
- [ ] Top `source.raw_alert_count` (alarm paling noisy).
- [ ] Top `source_observed.srcip_unique_count`.
- [ ] Trend alarm per jam berdasarkan `timestamp`.
- [ ] **Panel eskalasi**: alarm dengan `risk.level_changed = true` dalam 1 jam terakhir.
- [ ] Table investigasi utama.

### 15.2 Kolom table investigasi

```text
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

## 16. Notifikasi — Escalating Notification Pattern

### 16.1 Prinsip

```text
Notifikasi dikirim HANYA saat risk.level naik ke level yang lebih tinggi.

Low    → tidak ada notifikasi otomatis
Medium → notifikasi ① (eskalasi pertama)
High   → notifikasi ② (eskalasi kedua)
Critical → notifikasi ③ (eskalasi ketiga, paling urgent)

Maksimal 3 notifikasi per alarm per bucket 1 jam.
```

### 16.2 Trigger condition

```text
risk.level_changed = true
DAN
risk.level IN ["Medium", "High", "Critical"]
```

### 16.3 Anti duplikasi

Gunakan kombinasi unik berikut sebagai dedup key notifikasi:

```text
alarm.id + risk.level
```

Satu `alarm.id` + satu `risk.level` hanya boleh menghasilkan satu notifikasi. Notifikasi tidak dikirim ulang jika level tidak berubah.

### 16.4 Implementasi dengan Elastalert2

```yaml
name: siem-alarm-escalation
type: any
index: siem-alarm-*

filter:
  - term:
      risk.level_changed: true
  - terms:
      risk.level: ["Medium", "High", "Critical"]

# Dedup: alarm.id + risk.level
query_key:
  - alarm.id
  - risk.level

# Jangan kirim ulang untuk kombinasi alarm.id + level yang sama
realert:
  hours: 2

alert:
  - slack

slack_webhook_url: "https://hooks.slack.com/services/XXXXX"

alert_subject: "[{0}] ESKALASI ALARM — {1}"
alert_subject_args:
  - risk.level
  - agent.name

alert_text: |
  *Risk Level*: {0} (sebelumnya: {1})
  *Agent*: {2}
  *Rule*: {3}
  *Event Count*: {4}
  *Score*: {5}
  *Bucket*: {6} s/d {7}
  *Case Key*: {8}

alert_text_args:
  - risk.level
  - risk.previous_level
  - agent.name
  - rule.description
  - source.raw_alert_count
  - risk.score
  - alarm.first_seen
  - alarm.last_seen
  - alarm.case_key

alert_text_type: alert_text_only
```

### 16.5 Perbandingan tool notifikasi

| Tool | Kelebihan | Cocok untuk |
|---|---|---|
| **Elastalert2** | Query langsung `siem-alarm-*`, dedup per `alarm.id+level` | SOC tanpa dev resource |
| **Custom Python webhook** | Kontrol penuh, bisa cek `level_history` | Tim dengan dev resource |
| **Wazuh Active Response** | Built-in, tanpa tool tambahan | Notifikasi sederhana dari raw alert |

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

### 18.3 Threshold notifikasi terlalu sensitif

Ubah filter Elastalert2 dari:

```yaml
- terms:
    risk.level: ["Medium", "High", "Critical"]
```

Menjadi:

```yaml
- terms:
    risk.level: ["High", "Critical"]
```

Agar hanya notifikasi saat level High ke atas.

---

## 19. Kesalahan Fatal yang Harus Dihindari

- [ ] Menghapus atau mengubah `wazuh-alerts-*`.
- [ ] Menganggap `siem-alarm-*` sebagai pengganti evidence.
- [ ] Menyalin semua raw alert ke `siem-alarm-*`.
- [ ] Menggunakan INSERT bukan UPDATE untuk document ID yang sama (menyebabkan duplikasi alarm).
- [ ] Tidak menyimpan `risk.previous_level` → notifikasi eskalasi tidak bisa dideteksi.
- [ ] Memasukkan terlalu banyak field ke primary dedup key.
- [ ] Memaksa semua alert punya `srcip` atau `dstip`.
- [ ] Tidak membatasi agregasi dengan bucket waktu.
- [ ] Tidak memvalidasi `raw_alert_count`.
- [ ] Mengirim notifikasi langsung dari `wazuh-alerts-*`.
- [ ] Mengirim notifikasi untuk setiap update (bukan hanya saat level naik).
- [ ] Memberi asset value 5 ke semua agent.
- [ ] Mengetik password indexer langsung di command line.

---

## 20. Go-Live Checklist

**Infrastruktur:**
- [ ] Service Wazuh AIO healthy (manager, indexer, dashboard, filebeat).
- [ ] `wazuh-alerts-*` normal dan terisi.

**Persiapan:**
- [ ] Audit field sudah dijalankan.
- [ ] Asset value disiapkan via labels atau `assets.json`.
- [ ] Config script sudah disesuaikan (`bucket_minutes: 60`, `lookback_minutes: 60`, `process_current_bucket_only: true`).
- [ ] Index template `siem-alarm-*` sudah dibuat (termasuk mapping field `risk.level_history`).

**Validasi script:**
- [ ] Test syntax: `python3 -m py_compile` berhasil.
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

**Dashboard & notifikasi:**
- [ ] Index pattern `siem-alarm-*` dibuat, time field = `timestamp`.
- [ ] Dashboard SOC dengan panel eskalasi tersedia.
- [ ] Notifikasi dikonfigurasi dengan Elastalert2 atau tool lain.
- [ ] Dedup notifikasi via `alarm.id + risk.level` sudah aktif.
- [ ] Test eskalasi: pastikan notifikasi hanya dikirim saat level naik.

**Operasional:**
- [ ] Log script dimonitor.
- [ ] Rollback plan disiapkan.
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
- Notifikasi storm (dikirim berulang untuk case yang sama)
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
export WAZUH_PASS='PASSWORD_INDEXER'

# Hapus index tertentu
curl -k -u admin:"$WAZUH_PASS" -X DELETE \
  "https://127.0.0.1:9200/siem-alarm-2026.05.22"

# ATAU hapus semua (hati-hati)
curl -k -u admin:"$WAZUH_PASS" -X DELETE \
  "https://127.0.0.1:9200/siem-alarm-*"

unset WAZUH_PASS
```

> `wazuh-alerts-*` **TIDAK DISENTUH** dalam rollback apapun.

**Step 4 — Identifikasi penyebab dari log:**
```bash
sudo tail -n 200 /opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
sudo journalctl -u siem-alarm-scoring.service -n 100 --no-pager
```

**Step 5 — Perbaiki config/script:**
```bash
sudo nano /opt/wazuh-risk-scoring/config.siem_alarm.json
sudo nano /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py
```

**Step 6 — Test manual ulang:**
```bash
sudo python3 /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py \
  --config /opt/wazuh-risk-scoring/config.siem_alarm.json \
  --once

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
Notifikasi         : hanya saat risk.level naik (Escalating Notification Pattern)
Maks notifikasi    : 3 per alarm per bucket (Low→Med, Med→High, High→Critical)
Evidence           : srcip/dstip/port/proto/url/user/file/hash — bukan pemecah case
```

Ini adalah desain yang paling realistis untuk menekan alert fatigue tanpa kehilangan raw evidence dan tetap memberikan visibilitas real-time ke SOC.

---

*Versi 3.1 — Perubahan dari v3.0: mapping `risk` ditulis sebagai object `properties`, contoh config disinkronkan dengan key script (`bucket_minutes`, `lookback_minutes`, `process_current_bucket_only`), dan template/script pendukung diselaraskan untuk `risk.previous_level`, `risk.level_changed`, serta `risk.level_history`.*
