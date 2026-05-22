# FINAL CHECKLIST Implementasi `siem-alarm-*` di Wazuh 4.14.2 AIO

## 0. Keputusan Desain Final

Checklist ini adalah versi final berdasarkan diskusi:

- Wazuh 4.14.2 berjalan **single node / all-in-one** di Ubuntu VM.
- `wazuh-alerts-*` **tetap dipertahankan** sebagai raw evidence.
- `siem-alarm-*` adalah index baru untuk **alarm agregasi SOC**, bukan copy mentah dari `wazuh-alerts-*`.
- Definisi default “alert yang sama” dibuat **kasar dan stabil** untuk mengurangi alert fatigue.
- Default deduplication key:

```text
agent.id + rule.id + timestamp_bucket_1h
```

- Di Wazuh Dashboard, field waktu tetap bernama/ditampilkan sebagai **Time** karena index pattern memakai field `timestamp`.
- Istilah internal “bucket 1 jam” berarti `timestamp` dokumen `siem-alarm-*` dibulatkan ke awal jam.
- Field seperti `srcip`, `dstip`, `dstport`, `proto`, `url`, `user`, `file_path`, `hash`, `CVE`, dan SCA **tidak wajib masuk definisi alert sama**.
- Field-field tersebut disimpan sebagai **evidence / observed context**, bukan pemecah case utama.
- `raw_alert_count` berarti jumlah alert mentah dari `wazuh-alerts-*` yang tergabung ke satu dokumen `siem-alarm-*` berdasarkan definisi alert sama.

---

## 1. Tujuan Implementasi

Tujuan utama:

```text
Mengurangi alert fatigue SOC dengan mengubah banyak raw alert Wazuh menjadi alarm agregasi yang lebih sedikit, lebih prioritas, dan lebih mudah dianalisis.
```

Desain data:

```text
wazuh-alerts-* = raw alert / evidence asli
siem-alarm-*   = aggregated SOC alarm / hasil deduplikasi + scoring
```

Contoh hasil:

```text
700 raw alert dari agent dan rule yang sama dalam 1 jam
↓
1 dokumen siem-alarm-* dengan raw_alert_count = 700
```

---

## 2. Definisi Final “Alert yang Sama”

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

### 2.2 Kenapa tidak memasukkan banyak variabel?

Karena tidak semua rule Wazuh punya field berikut:

```text
srcip
dstip
dstport
proto
url
user
file path
hash
```

Jika field tersebut dipaksa masuk definisi alert sama, agregasi bisa gagal atau terlalu terpecah.

### 2.3 Kenapa `srcip` tidak masuk primary key?

Karena attacker bisa memakai:

```text
proxy
VPN
botnet
rotating IP
cloud scanner
distributed source
```

Jika `srcip` dijadikan primary key, satu attack wave dapat pecah menjadi banyak alarm.

### 2.4 Posisi field network

Field network tetap disimpan sebagai evidence:

```text
source_observed.srcip_unique_count
source_observed.srcip_samples
source_observed.top_srcip
target_observed.dstip_unique_count
target_observed.dstip_samples
target_observed.dstport_samples
target_observed.proto_samples
```

### 2.5 Mode lanjutan opsional

Default tetap `coarse`.

Mode lain hanya untuk rule tertentu jika diperlukan:

```text
target_aware = agent.id + rule.id + dstip + timestamp_bucket_1h
smart        = case_type-specific, misalnya FIM memakai syscheck.path
```

Gunakan mode lanjutan hanya setelah SOC melihat bahwa agregasi default terlalu kasar untuk rule tertentu.

---

## 3. Definisi `raw_alert_count`

### 3.1 Definisi wajib

```text
raw_alert_count = jumlah dokumen raw alert dari wazuh-alerts-* yang tergabung ke satu dokumen siem-alarm-* berdasarkan case_key yang sama.
```

Dalam desain final, tiga field ini harus sama nilainya:

```text
source.raw_alert_count
alarm.event_count
risk.frequency_count_1h
```

### 3.2 Contoh

Raw alert:

```text
agent.id = 003
rule.id = 2010935
Time bucket = 2026-05-22T10:00:00Z
jumlah alert = 700
srcip unik = 100
dstip unik = 3
```

Hasil `siem-alarm-*`:

```text
source.raw_alert_count = 700
alarm.event_count = 700
risk.frequency_count_1h = 700
source_observed.srcip_unique_count = 100
target_observed.dstip_unique_count = 3
```

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

| Jumlah Raw Alert Sama dalam 1 Jam | Frequency Score |
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

### 5.1 Prioritas sumber Asset Value

Gunakan urutan:

```text
1. Agent labels dari alert Wazuh
2. assets.json
3. Default Medium
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

Query di Dev Tools:

```json
GET wazuh-alerts-*/_search
{
  "size": 5,
  "_source": [
    "timestamp",
    "agent",
    "agent.labels",
    "labels",
    "asset",
    "rule"
  ],
  "sort": [
    {
      "timestamp": {
        "order": "desc"
      }
    }
  ]
}
```

Jika label belum muncul, gunakan `assets.json`.

---

## 6. Struktur Dokumen `siem-alarm-*`

Contoh final:

```json
{
  "timestamp": "2026-05-22T10:00:00Z",
  "alarm": {
    "id": "sha256-case-key",
    "case_key": "coarse|003|2010935|2026-05-22T10:00:00Z",
    "deduplication_mode": "coarse",
    "case_type": "coarse_rule_agent",
    "status": "open",
    "dedup_key_fields": ["agent.id", "rule.id", "timestamp_bucket_1h"],
    "bucket_start": "2026-05-22T10:00:00Z",
    "bucket_size": "1h",
    "first_seen": "2026-05-22T10:03:20Z",
    "last_seen": "2026-05-22T10:59:50Z",
    "event_count": 700
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
    "frequency_count_1h": 700,
    "frequency_score": 5,
    "score": 4.33,
    "level": "High",
    "formula": "(A+B+C)/3"
  },
  "source": {
    "index": "wazuh-alerts-*",
    "raw_alert_count": 700,
    "sample_document_id": "abc123"
  },
  "soc": {
    "recommended_action": "Investigate",
    "sla": "1 hour",
    "notification": true
  }
}
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

```bash
curl -k -u admin:'PASSWORD_INDEXER' https://127.0.0.1:9200
```

### 8.3 Cek raw alert

```bash
curl -k -u admin:'PASSWORD_INDEXER' "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=1&pretty"
```

---

## 9. Audit Field Wazuh

### 9.1 Kenapa wajib

Wazuh punya dynamic fields hasil decoder. Untuk rule bawaan dan rule custom, field bisa berbeda-beda. Karena itu audit field wajib dilakukan sebelum production.

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

Script scoring otomatis memasang template jika:

```json
"install_template": true
```

### 10.2 Via Dev Tools

Jalankan isi `siem_alarm_template_final.json` ke Dev Tools:

```text
Wazuh Dashboard → Indexer Management → Dev Tools
```

---

## 11. Jalankan Script Manual

### 11.1 Edit config

```bash
sudo nano /opt/wazuh-risk-scoring/config.siem_alarm.json
```

Minimal ganti:

```json
"password": "GANTI_PASSWORD_INDEXER_ANDA"
```

### 11.2 Test syntax

```bash
sudo python3 -m py_compile /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py
```

### 11.3 Run manual

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
curl -k -u admin:'PASSWORD_INDEXER' "https://127.0.0.1:9200/_cat/indices/siem-alarm-*?v"
```

---

## 12. Buat Index Pattern di Wazuh Dashboard

- [ ] Buka Wazuh Dashboard.
- [ ] Masuk ke `Dashboard Management`.
- [ ] Buka `Index Patterns`.
- [ ] Create index pattern:

```text
siem-alarm-*
```

- [ ] Pilih time field:

```text
timestamp
```

- [ ] Buka Discover.
- [ ] Pilih `siem-alarm-*`.
- [ ] Set time range `Last 24 hours` atau `Last 7 days`.

Catatan:

```text
Di dashboard, kolom Time berasal dari field timestamp.
timestamp di siem-alarm-* adalah awal bucket agregasi 1 jam.
```

---

## 13. Validasi `raw_alert_count`

### 13.1 Query alarm terbesar

```json
GET siem-alarm-*/_search
{
  "size": 5,
  "sort": [
    {
      "source.raw_alert_count": {
        "order": "desc"
      }
    }
  ]
}
```

Validasi:

```text
source.raw_alert_count = alarm.event_count = risk.frequency_count_1h
```

### 13.2 Cross-check manual ke raw alert

Ambil satu `case_key`, misalnya:

```text
coarse|003|2010935|2026-05-22T10:00:00Z
```

Query raw count:

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

Hasil `_count` harus sama dengan:

```text
source.raw_alert_count
alarm.event_count
risk.frequency_count_1h
```

---

## 14. Dashboard SOC

### 14.1 Panel wajib

- [ ] Total alarm Critical.
- [ ] Total alarm High.
- [ ] Distribusi `risk.level`.
- [ ] Top `agent.name`.
- [ ] Top `rule.id`.
- [ ] Top `rule.description.keyword`.
- [ ] Top `source.raw_alert_count`.
- [ ] Top `source_observed.srcip_unique_count`.
- [ ] Top `target_observed.dstip_unique_count`.
- [ ] Trend alarm per jam berdasarkan `timestamp`.
- [ ] Table investigasi utama.

### 14.2 Kolom table investigasi

```text
Time
timestamp
alarm.case_key
alarm.deduplication_mode
alarm.event_count
alarm.first_seen
alarm.last_seen
agent.name
rule.id
rule.level
rule.description
source.raw_alert_count
risk.frequency_count_1h
risk.frequency_score
risk.score
risk.level
source_observed.srcip_unique_count
source_observed.srcip_samples
target_observed.dstip_unique_count
target_observed.dstip_samples
asset.value
asset.category
soc.recommended_action
soc.sla
```

---

## 15. Notifikasi

### 15.1 Prinsip

Notifikasi jangan langsung dari `wazuh-alerts-*`.

Gunakan:

```text
siem-alarm-*
```

### 15.2 Rule notifikasi awal

```text
risk.level = Critical
OR risk.level = High AND asset.value >= 4
OR risk.frequency_score = 5 AND risk.threat_score >= 4
```

### 15.3 Anti duplikasi

Gunakan:

```text
alarm.id
alarm.case_key
timestamp
```

Jangan kirim notifikasi berkali-kali untuk case yang sama dalam bucket yang sama.

---

## 16. Rule Custom Wazuh

### 16.1 Apakah fleksibel?

Ya, karena default key hanya:

```text
agent.id + rule.id + timestamp_bucket_1h
```

Rule custom tetap bisa diagregasi selama menghasilkan alert dengan:

```text
agent.id
rule.id
rule.level
rule.description
timestamp
```

### 16.2 Field custom

Jika custom decoder menghasilkan field unik, field tersebut tetap bisa terlihat melalui audit field. Jika penting, tambahkan ke alias list di script.

### 16.3 Checklist custom rule

- [ ] Rule custom punya ID unik.
- [ ] Rule custom punya level yang masuk akal.
- [ ] Rule custom description jelas.
- [ ] Rule custom tidak terlalu noisy tanpa tuning.
- [ ] Field custom yang penting sudah masuk audit.
- [ ] Jika perlu, tambahkan field custom ke evidence extraction.

---

## 17. Tuning Lanjutan

### 17.1 Saat agregasi terlalu kasar

Jika satu alarm menggabungkan konteks yang terlalu berbeda, gunakan rule override.

Contoh:

```json
"rule_overrides": {
  "2010935": {
    "deduplication_mode": "target_aware"
  }
}
```

### 17.2 Saat agregasi terlalu detail

Tetap gunakan:

```json
"deduplication_mode": "coarse"
```

### 17.3 Saat rule terlalu noisy

Gunakan:

```json
"excluded_rule_ids": ["5715", "550"]
```

Atau turunkan di dashboard/notifikasi, bukan langsung dibuang dari `wazuh-alerts-*`.

---

## 18. Kesalahan Fatal yang Harus Dihindari

- [ ] Menghapus atau mengubah `wazuh-alerts-*`.
- [ ] Menganggap `siem-alarm-*` sebagai pengganti evidence.
- [ ] Menyalin semua raw alert ke `siem-alarm-*`.
- [ ] Memasukkan terlalu banyak field ke primary dedup key.
- [ ] Memaksa semua alert punya `dstip`/`dstport`.
- [ ] Memaksa semua alert punya `srcip`.
- [ ] Menganggap banyak `srcip` berarti banyak case.
- [ ] Tidak membatasi agregasi dengan bucket waktu.
- [ ] Tidak memvalidasi `raw_alert_count`.
- [ ] Tidak melakukan audit field untuk rule custom.
- [ ] Mengirim notifikasi dari raw alert.
- [ ] Memberi asset value 5 ke semua agent.
- [ ] Menaruh password indexer dengan permission file longgar.

---

## 19. Go-Live Checklist

- [ ] Service Wazuh AIO healthy.
- [ ] `wazuh-alerts-*` normal.
- [ ] Script audit field sudah dijalankan.
- [ ] Asset value sudah disiapkan via labels atau `assets.json`.
- [ ] Config script sudah disesuaikan.
- [ ] Template `siem-alarm-*` sudah dibuat.
- [ ] Script manual berhasil.
- [ ] `siem-alarm-*` terbentuk.
- [ ] Index pattern `siem-alarm-*` dibuat.
- [ ] Time field = `timestamp`.
- [ ] `raw_alert_count` tervalidasi.
- [ ] Dashboard SOC dibuat.
- [ ] Notifikasi membaca `siem-alarm-*`.
- [ ] Cron/systemd timer aktif.
- [ ] Log script dimonitor.
- [ ] SOP SOC diperbarui.

---

## 20. Kesimpulan Final

Desain final yang paling sesuai untuk SOC Anda:

```text
wazuh-alerts-* tetap sebagai raw evidence
siem-alarm-* menjadi alarm agregasi SOC
alert sama default = agent.id + rule.id + timestamp bucket 1 jam
raw_alert_count = jumlah alert mentah yang tergabung dalam case itu
srcip/dstip/port/proto/url/user/file/hash = evidence, bukan pemecah default
```

Ini adalah desain yang paling realistis untuk menekan alert fatigue tanpa kehilangan raw evidence.
