# FINAL CHECKLIST Implementasi `siem-alarm-*` di Wazuh 4.14.7 AIO

> **Versi 5.2** — Wazuh 4.14.7 compatibility + Production-hardened Snapshot-Bulk V2
> Timer: 5 menit | Bucket: 1 jam | Log eskalasi: dokumen baru saat risk.level masuk Medium/High/Critical atau naik

---

## 0. Keputusan Desain Final

- Wazuh 4.14.7 berjalan **single node / all-in-one** di Ubuntu VM.
- Python sistem minimal 3.8; Ubuntu 20.04 dapat memakai `/usr/bin/python3` bawaan tanpa mengganti symlink atau menambah PPA.
- `wazuh-alerts-*` **tetap dipertahankan** sebagai raw evidence.
- `siem-alarm-*` adalah index baru untuk **alarm agregasi SOC**, bukan copy mentah.
- Default deduplication key:

```text
agent.id + rule.id + timestamp_bucket_1h
```

- Script jalan **setiap 5 menit**, bucket tetap **1 jam**.
- Bucket current dihitung ulang setiap run; bucket tertutup menjadi eligible setelah delay default tujuh menit dan difinalisasi **sekali dan terpisah** pada tick timer berikutnya (normalnya sekitar boundary +10 menit untuk timer 5 menit). Tidak ada lagi window gabungan previous+current.
- Source default `wazuh-alerts-4.x-{date}` diekspansi ke index harian UTC yang relevan, bukan fan-out ke seluruh history.
- State lama dibaca melalui `/{index}/_mget`; escalation create-only dan alarm state ditulis melalui dua fase `/{index}/_bulk` yang dibatasi jumlah action dan byte. Operasi dikelompokkan per concrete destination index dan tidak membawa `_index` eksplisit di payload.
- Checkpoint atomik default `/var/lib/wazuh-risk-scoring/checkpoint.json` membatasi recovery maksimal dua bucket per run tanpa membuat buffer raw alert baru.
- `alarm.id` dibuat deterministik dari hash `case_key` → update, bukan duplikasi.
- Log eskalasi dibuat secara **create-only sebelum state di-update** saat risk.level pertama kali masuk Medium/High/Critical atau naik ke level lebih tinggi.
- Satu host hanya boleh menjalankan satu proses scoring; lock default: `/opt/wazuh-risk-scoring/logs/scoring.lock`.
- TLS verification wajib untuk production menggunakan salinan Wazuh root CA.
- Runtime memakai user Linux `siem-alarm` dan user Wazuh Indexer `siem_alarm_service`, bukan `root`/`admin`.
- Field `srcip`, `dstip`, `dstport`, `proto`, `url`, `user`, `file_path`, `hash`, `CVE`, SCA = **evidence**, bukan pemecah case.

### 0.1 Baseline kompatibilitas 4.14.7

- Semua komponen sentral harus berada pada patch yang sama: `wazuh-manager`, `wazuh-indexer`, dan `wazuh-dashboard` versi `4.14.7`.
- Wazuh Indexer 4.14.7 dipasangkan dengan Filebeat OSS `7.10.2`.
- Unit systemd resmi tetap `wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard`, dan `filebeat`.
- Index alert resmi tetap memakai pola `wazuh-alerts-*`; proyek hanya membacanya.
- Perubahan 4.14.7 yang menghapus daemon lama `wazuh-dbd` tidak memengaruhi proyek karena tidak ada tahapan yang memakainya.

Rujukan resmi yang menjadi baseline review:

- [Wazuh 4.14.7 release notes](https://documentation.wazuh.com/current/release-notes/release-4-14-7.html)
- [Wazuh central components compatibility](https://documentation.wazuh.com/current/upgrade-guide/index.html)
- [Wazuh Indexer indices](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
- [Wazuh RBAC/internal users](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html)

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
  target_port_aware = agent.id + rule.id + dstip + dstport + bucket_1h
  file_aware        = agent.id + rule.id + syscheck.path + bucket_1h
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

Nilai ini dihitung ulang secara eksak dari raw evidence dan biasanya **bertambah setiap kali script jalan** selama bucket masih berjalan. Engine tidak menambah counter incremental, sehingga retry tidak menggandakan count.

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
1. assets.json milik root: lookup agent.id, lalu agent.name
2. Agent labels resmi Wazuh di agent.labels.* hanya sebagai fallback
3. Default = Medium (3)
```

Urutan ini disengaja: inventori `root:siem-alarm` tidak boleh dikalahkan oleh label lokal dari endpoint. Field root `labels.asset.*` atau `asset.*` dari decoder/log payload tidak dipercaya. `assets.json` wajib memakai nilai integer `1` sampai `5`; kategori harus sesuai dan schema divalidasi fail-closed. Installer baru membuat runtime inventory kosong `{}`, bukan menyalin ID contoh `001`–`004`.

### 5.2 Label yang direkomendasikan

```xml
<ossec_config>
  <labels>
    <label key="asset.value">5</label>
    <label key="asset.category">Critical</label>
    <label key="asset.type">Database Server</label>
    <label key="asset.owner">Diskominfo</label>
    <label key="asset.environment">Production</label>
  </labels>
</ossec_config>
```

Untuk production 5–25 agent, metode utama adalah `assets.json`; label dipakai hanya bila memang ingin metadata ikut melekat pada raw alert. Konfigurasi label terpusat harus dibungkus `<agent_config>` di `agent.conf` dan divalidasi dengan `/var/ossec/bin/verify-agent-conf` sebelum diaktifkan.

### 5.3 Validasi label

```json
GET wazuh-alerts-4.x-2026.05.22/_search
{
  "size": 5,
  "_source": ["timestamp", "agent.id", "agent.name", "agent.labels", "rule"],
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
    "case_type": "network",
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
    "source": "assets_json"
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
    "index": "wazuh-alerts-4.x-2026.05.22",
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

`alarm.status` adalah lifecycle bucket, bukan status penanganan insiden: `open` untuk bucket berjalan dan `finalized` setelah snapshot bucket tertutup berhasil ditulis. Jangan memakainya sebagai field acknowledge/resolve analyst.

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

Script menggunakan action `index` dengan ID deterministik di fase `_bulk` state:
  POST siem-alarm-YYYY.MM.DD/_bulk

Karena document ID sama → dokumen yang ada di-UPDATE, bukan INSERT baru.
Tidak ada duplikasi dokumen untuk case_key yang sama dalam satu bucket.
```

---

## 7. Instalasi File

### 7.1 Preflight

Konfirmasi versi paket dan kesehatan output Filebeat sebelum menjalankan installer:

```bash
dpkg-query -W -f='${Package} ${Version}\n' \
  wazuh-manager wazuh-indexer wazuh-dashboard filebeat
sudo filebeat test output
```

Output wajib menunjukkan tiga komponen Wazuh `4.14.7` dan Filebeat `7.10.2`. Jangan lanjut jika patch komponen sentral berbeda atau `filebeat test output` gagal.

```bash
cd /path/ke/folder/siem-alarm-
sudo bash ./setup_siem_alarm_final.sh
```

Installer wajib dijalankan dari paket lengkap, tetapi tidak bergantung pada current directory setelah path script ditemukan. Installer akan:

- Memastikan paket Wazuh tepat `4.14.7`, Filebeat tepat `7.10.2`, seluruh service AIO aktif, certificate chain valid, dan `filebeat test output` berhasil.
- Memvalidasi seluruh Python/JSON dan menjalankan automated unit tests sebelum mengubah `/opt` atau systemd.
- Membuat user/group Linux `siem-alarm`.
- Membuat state directory terproteksi `/var/lib/wazuh-risk-scoring` untuk checkpoint lokal; raw alert tidak pernah disalin ke sana.
- Menyalin Wazuh CA dari `/etc/wazuh-indexer/certs/root-ca.pem`.
- Membuat backup mode root-only untuk source lama, config, assets, environment secret, CA, checkpoint, dan unit di `/opt/wazuh-risk-scoring/backups/<UTC timestamp>`.
- Mempertahankan config, assets, dan environment file yang sudah ada.
- Pada instalasi baru, membuat `assets.json` kosong (`{}`); data `assets.example.json` tidak pernah dijadikan inventory production otomatis.
- Menolak symlink pada source/target terkelola dan memvalidasi schema inventory aset sebelum timer lama dihentikan.
- Memasang service, failure handler, timer, dan logrotate tetapi **tidak meng-enable timer**.
- Menjalankan `systemd-analyze verify`.

Jika CA atau sertifikat node Indexer berada di lokasi lain:

```bash
sudo \
  WAZUH_CA_SOURCE=/path/root-ca.pem \
  WAZUH_INDEXER_CERT_SOURCE=/path/indexer.pem \
  bash ./setup_siem_alarm_final.sh
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
/var/lib/wazuh-risk-scoring/checkpoint.json (dibuat atomik oleh engine pada run sukses)
/etc/systemd/system/siem-alarm-scoring.service
/etc/systemd/system/siem-alarm-scoring-failure@.service
/etc/systemd/system/siem-alarm-scoring.timer
/etc/logrotate.d/siem-alarm-scoring
```

> Repository menyimpan script installer sebagai file biasa. Gunakan `sudo bash ./setup_siem_alarm_final.sh`; tidak perlu mengandalkan executable bit.

---

## 8. Validasi Wazuh AIO

### 8.1 Cek service

```bash
sudo systemctl status wazuh-manager --no-pager
sudo systemctl status wazuh-indexer --no-pager
sudo systemctl status wazuh-dashboard --no-pager
sudo systemctl status filebeat --no-pager
```

### 8.2 Cek koneksi indexer

Sebelum test, buka **Indexer Management → Security** sebagai administrator:

1. Pada **Internal users**, buat user `siem_alarm_service` dengan password unik.
2. Pada **Roles**, buat role `siem_alarm_runtime` dengan:
   - Cluster permissions: `cluster_composite_ops_ro`—dibutuhkan untuk `_mget` serta operasi scroll.
   - Cluster permission individual: `indices:data/read/scroll/clear`—dibutuhkan untuk menutup scroll context; action group bawaan `cluster_composite_ops_ro` hanya memuat operasi scroll, bukan clear-scroll.
   - Cluster permission individual: `indices:data/write/bulk*`—Bulk API dievaluasi juga pada scope cluster.
   - Index pattern `wazuh-alerts-*`: allowed action `read`.
   - Index pattern `siem-alarm-*`: allowed actions `read`, `index`, dan `create_index`.
   - Tenant permissions: kosong.
3. Pada tab **Mapped users** role tersebut, map `siem_alarm_service`.

Hak `read` pada `siem-alarm-*` diperlukan karena engine membaca state lama melalui endpoint per-index `_mget`. Action group `read` pada source mencakup clear-scroll pada scope index, sementara permission individual `indices:data/read/scroll/clear` melengkapinya pada scope cluster. Action group index `index` mencakup operasi index/create di dalam bulk, sedangkan permission cluster individual `indices:data/write/bulk*` mengizinkan envelope Bulk API walaupun endpoint-nya per-index. Request dikelompokkan per destination index dan tidak memakai global `/_mget`/`/_bulk` dengan `_index` eksplisit, sehingga tetap kompatibel dengan cluster yang menonaktifkan `rest.action.multi.allow_explicit_index`. Jangan menggantinya dengan `cluster_composite_ops`, karena action group tersebut juga memberi reindex dan pengelolaan alias yang tidak diperlukan. Jangan memberikan `indices_all`, akses Security API, system index, atau index Wazuh lain. Template dan ISM policy dipasang satu kali menggunakan administrator; runtime account tidak memerlukan cluster-admin.

Rujukan permission: [OpenSearch default action groups](https://docs.opensearch.org/latest/security/access-control/default-action-groups/) dan [Bulk API required permissions](https://docs.opensearch.org/latest/api-reference/document-apis/bulk/). Tetap lakukan preflight dengan user production pada Indexer 4.14.7; respons bulk harus diperiksa per item, bukan hanya HTTP status.

Gunakan input password interaktif dan verifikasi CA. Jangan memasukkan password ke argumen command.

```bash
ALERT_INDEX_DATE="$(date -u +%Y.%m.%d)"
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  "https://127.0.0.1:9200/wazuh-alerts-4.x-${ALERT_INDEX_DATE}/_count?pretty"
```

Respons harus HTTP `200`. Endpoint akar `GET /` dapat menghasilkan `403` karena
role runtime sengaja tidak memiliki `cluster:monitor/main`; ini bukan kegagalan
autentikasi dan permission tersebut tidak perlu ditambahkan.

> Jika certificate SAN tidak memuat `127.0.0.1`, ganti URL dengan hostname/IP yang tercantum pada sertifikat. Jangan kembali memakai `-k` di production.

### 8.3 Cek raw alert

```bash
ALERT_INDEX_DATE="$(date -u +%Y.%m.%d)"
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  "https://127.0.0.1:9200/wazuh-alerts-4.x-${ALERT_INDEX_DATE}/_search?size=1&pretty"
```

Command wajib menghasilkan dokumen pada index harian UTC aktual. Jika instalasi memakai nama index custom atau tanggal index tidak mengikuti UTC, jangan mengaktifkan timer dengan pola default: sesuaikan `source_index`, lakukan run shadow, dan buktikan tidak ada alert terlambat yang terlewat. Placeholder `{date}` adalah placeholder engine, bukan shell variable, dan diekspansi menjadi `YYYY.MM.DD` untuk setiap bucket.

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

Default `--index 'wazuh-alerts-4.x-{date}'` di-resolve hanya ke tanggal UTC yang masuk window audit (umumnya dua index untuk 24 jam), bukan wildcard seluruh history. Wildcard ditolak. Jalankan audit satu kali saat beban rendah karena utility memang membaca `_source` lengkap untuk menemukan field custom.

Jangan memakai `--insecure` atau `curl -k`. Jika verifikasi hostname gagal, lihat SAN sertifikat lalu gunakan hostname/IP yang memang tercantum:

```bash
sudo openssl x509 \
  -in /etc/wazuh-indexer/certs/indexer.pem \
  -noout -subject -issuer -dates -ext subjectAltName
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
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  -H 'Content-Type: application/json' \
  -X PUT 'https://127.0.0.1:9200/_index_template/siem-alarm-template' \
  --data-binary @/opt/wazuh-risk-scoring/siem_alarm_template_final.json
```

Install retention policy 90 hari satu kali. Sesuaikan `min_index_age` di file sebelum command bila kebijakan organisasi berbeda:

```bash
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  -H 'Content-Type: application/json' \
  -X PUT 'https://127.0.0.1:9200/_plugins/_ism/policies/siem-alarm-retention-90d' \
  --data-binary @/opt/wazuh-risk-scoring/siem_alarm_ism_policy.json
```

Verifikasi kedua objek setelah instalasi:

```bash
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  'https://127.0.0.1:9200/_index_template/siem-alarm-template?pretty'

sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  'https://127.0.0.1:9200/_plugins/_ism/policies/siem-alarm-retention-90d?pretty'
```

`ism_template` otomatis menerapkan policy hanya ke index baru yang cocok. Jangan menempelkan policy delete ke index lama secara massal sebelum umur index, backup, dan persetujuan retensi diperiksa. Jika policy dengan ID yang sama sudah ada, review hasil GET dan ikuti mekanisme update `if_seq_no`/`if_primary_term`; jangan menghapus policy aktif hanya agar PUT berhasil.

Snapshot-Bulk V2 mempertahankan nama dan schema dokumen `alarm_state`/`alarm_escalation`; `_mget`, `_bulk`, dan checkpoint lokal tidak memerlukan index tambahan atau perubahan ISM. Template tetap harus dipasang **sebelum** bulk pertama agar auto-created daily index memperoleh mapping dan setting yang benar. Jangan memakai `refresh=true` pada bulk; `refresh_interval: 30s` pada template sudah cukup untuk visibilitas dashboard tanpa refresh storm.

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
  "source_index": "wazuh-alerts-4.x-{date}",
  "source_includes": [],
  "bucket_minutes": 60,
  "lookback_minutes": 60,
  "process_current_bucket_only": true,
  "lookback_overlap_minutes": 7,
  "escalation_log_enabled": true,
  "escalation_log_levels": ["Medium", "High", "Critical"],
  "threat_level_strategy": "max",
  "max_alerts_per_bucket": 100000,
  "max_cases_per_bucket": 20000,
  "page_size": 1000,
  "mget_batch_size": 1000,
  "bulk_max_actions": 1000,
  "bulk_max_bytes": 5242880,
  "max_catchup_buckets_per_run": 2,
  "lock_file": "/opt/wazuh-risk-scoring/logs/scoring.lock",
  "checkpoint_file": "/var/lib/wazuh-risk-scoring/checkpoint.json",
  "install_template": false
}
```

Environment file root-only harus berisi password sebenarnya:

```text
WAZUH_PASS="PASSWORD_INDEXER_SEBENARNYA"
```

Program menolak placeholder secret `GANTI_*`/`CHANGE_*`, pola index yang tidak aman, numeric limit di luar batas, CA yang tidak ada, dan bucket yang tidak membagi 1 hari secara utuh. `source_index` V2 wajib mempunyai tepat satu placeholder `{date}`; engine mengekspansinya menggunakan tanggal UTC bucket.

Validasi schema inventory tanpa koneksi Indexer:

```bash
sudo -u siem-alarm /usr/bin/python3 -B \
  /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py \
  --validate-assets-only /opt/wazuh-risk-scoring/assets.json
```

File hilang, tipe/schema salah, nilai di luar `1..5`, kategori tidak cocok, ID berpadded, field typo, atau `agent_name` stale akan menghentikan run sebelum penulisan.

Nama legacy `lookback_overlap_minutes` dipertahankan untuk kompatibilitas config, tetapi semantik V2 adalah **finalization eligibility delay**. Nilai `7` berarti bucket menjadi eligible pada boundary +7 menit; karena timer berjalan tiap 5 menit, finalisasi normal terjadi pada tick berikutnya, sekitar boundary +10 menit (ditambah `AccuracySec`). Bucket tertutup tidak digabung dengan query current.

Jika upgrade dari V1, config lama sengaja dipertahankan oleh installer. Sebelum run manual:

- ganti `source_index: "wazuh-alerts-*"` menjadi pola harian yang sudah dibuktikan, default `wazuh-alerts-4.x-{date}`;
- hapus `max_alerts_per_run` dan gunakan `max_alerts_per_bucket: 100000`;
- tambahkan `max_cases_per_bucket`, `mget_batch_size`, `bulk_max_actions`, `bulk_max_bytes`, `max_catchup_buckets_per_run`, dan `checkpoint_file` seperti contoh;
- jangan membuat atau mengedit checkpoint secara manual; engine menulisnya secara atomik hanya untuk run calendar normal yang sukses;
- manual `--from/--to` tidak boleh memajukan checkpoint calendar.

Checkpoint menyimpan hash identitas case. Perubahan `bucket_minutes`, `source_index`, `min_rule_level`, exclusion rule/group, dedup/rule override, atau destination prefix membuat engine **fail closed** bila tidak cocok dengan checkpoint lama. Untuk perubahan tersebut, hentikan timer lalu pilih salah satu: shadow deployment dengan destination/checkpoint baru, atau archive checkpoint dan lakukan controlled backfill. Jangan menghapus checkpoint hanya agar error hilang. Perubahan asset/threat strategy tidak mengganti identitas case, tetapi closed bucket lama juga tidak dihitung ulang otomatis; backfill diperlukan bila history harus memakai scoring baru.

Nilai 1.000 action/ID dan 5 MiB adalah batas, bukan target yang wajib dipenuhi setiap request. Engine mengirim batch lebih kecil bila ukuran byte tercapai dan tidak memakai `refresh=true`. Jangan menaikkan paralelisme/batch sebelum load test menunjukkan tidak ada `429`, failed shard, atau tekanan heap Indexer.

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
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service -X GET \
  'https://127.0.0.1:9200/siem-alarm-*/_count?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"document.type":"alarm_state"}}}'
```

### 11.6 Validasi progressive update

Jalankan script dua kali dengan jeda, pastikan `raw_alert_count` bertambah dan document ID tetap sama:

```bash
# Run pertama
sudo systemctl start siem-alarm-scoring.service

# Ambil alarm_state terbaru dan catat alarm.id + raw_alert_count
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
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
Wants=network-online.target
OnFailure=siem-alarm-scoring-failure@%n.service

[Service]
Type=oneshot
User=siem-alarm
Group=siem-alarm
EnvironmentFile=/etc/wazuh-risk-scoring/siem-alarm.env
ExecStart=/usr/bin/python3 -B /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py --config /opt/wazuh-risk-scoring/config.siem_alarm.json --once
WorkingDirectory=/opt/wazuh-risk-scoring
RuntimeDirectory=siem-alarm
RuntimeDirectoryMode=0750
StateDirectory=wazuh-risk-scoring
StateDirectoryMode=0750
UMask=0027
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/wazuh-risk-scoring/logs /var/lib/wazuh-risk-scoring
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
TimeoutStartSec=240s
TimeoutStopSec=20s
MemoryHigh=512M
MemoryMax=1G
MemorySwapMax=0
TasksMax=64
LimitNOFILE=4096
Nice=5
CPUWeight=25
IOWeight=25
OOMScoreAdjust=500
CapabilityBoundingSet=
AmbientCapabilities=
```

`After=wazuh-indexer.service` hanya mengatur urutan bila Indexer sedang dimulai oleh mekanisme lain; unit scorer sengaja tidak me-`Wants` Indexer agar maintenance stop tidak dibatalkan oleh timer. `StateDirectory` memisahkan checkpoint mutable dari application files. `MemoryHigh=512M` memberi pressure lebih awal dan `MemoryMax=1G` menjadi hard stop agar Python tidak menekan heap Indexer pada AIO. `MemorySwapMax=0` mencegah scorer membuat host thrashing. `TimeoutStartSec=240s` membatasi eksekusi `Type=oneshot` dan menyisakan waktu sebelum jadwal lima menit berikutnya; bulk/checkpoint yang idempotent membuat run aman diulang bila service dihentikan pada limit. `Nice=5`, `CPUWeight=25`, dan `IOWeight=25` memprioritaskan Wazuh saat ada contention; weight bukan quota sehingga scorer tetap dapat memakai kapasitas idle.

Failure handler berikut juga dibuat installer:

```ini
[Unit]
Description=Record SIEM Alarm Scoring failure for %i

[Service]
Type=oneshot
ExecStart=/usr/bin/logger -p daemon.crit -t siem-alarm-scoring "Unit %i failed; inspect journalctl -u %i"
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=
AmbientCapabilities=
```

Handler hanya mencatat `daemon.crit`; ia tidak mengirim email/webhook. Monitoring SOC wajib membuat alert eksternal untuk journal tag `siem-alarm-scoring` dan heartbeat/checkpoint yang stale.

### 12.2 Buat systemd timer unit

File ini juga dibuat otomatis oleh installer:

```ini
[Unit]
Description=SIEM Alarm Scoring Timer - every 5 minutes

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
  /etc/systemd/system/siem-alarm-scoring-failure@.service \
  /etc/systemd/system/siem-alarm-scoring.timer
sudo systemctl daemon-reload
sudo systemctl enable --now siem-alarm-scoring.timer
```

### 12.4 Validasi timer aktif

```bash
# Status timer
sudo systemctl status siem-alarm-scoring.timer --no-pager

# Lihat semua timer aktif + next run
sudo systemctl list-timers --all | grep siem-alarm

# Cek hasil run terakhir
sudo systemctl status siem-alarm-scoring.service --no-pager

# Failure handler (output kosong adalah normal bila belum pernah gagal)
sudo journalctl -t siem-alarm-scoring -n 50 --no-pager

# Setelah run sukses, verifikasi owner/mode state directory dan checkpoint
sudo stat -c '%U:%G %a %n' \
  /var/lib/wazuh-risk-scoring \
  /var/lib/wazuh-risk-scoring/checkpoint.json
```

Expected: directory `siem-alarm:siem-alarm 750`; checkpoint harus dimiliki service dan tidak world-readable (`640` atau lebih ketat).

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
sudo journalctl -t siem-alarm-scoring -n 100 --no-pager
sudo tail -n 100 /opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
```

Jika initial scroll menghasilkan HTTP `400` dengan pesan `disabling
[track_total_hits] is not allowed in a scroll context`, scorer yang terpasang
masih memakai threshold numerik yang tidak kompatibel dengan Wazuh Indexer
4.14.7/OpenSearch 2.19. Upgrade ke source proyek terkini yang mengirim
`track_total_hits=true`; kegagalan ini terjadi sebelum pagination, bulk, dan
checkpoint, sehingga jangan menghapus index atau checkpoint sebagai respons.

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

`lookback_overlap_minutes=7` adalah finalization eligibility delay: closed bucket menjadi eligible setelah tujuh menit dan normalnya dibaca pada tick +10 menit, terpisah dari current bucket. Alert yang baru terindeks setelah finalisasi aktual memerlukan replay/backfill. Checkpoint V2 memproses maksimal `max_catchup_buckets_per_run=2` bucket tertinggal pada satu run agar restart tidak membuat query storm. Jika outage lebih panjang, checkpoint tidak maju, catch-up tetap tertinggal, atau SOC memerlukan recovery terkontrol, jalankan backfill per bucket dengan window eksplisit.

Gunakan waktu UTC, mulai/akhir tepat pada boundary bucket, dan jalankan melalui transient systemd unit agar proteksi resource tetap berlaku. Blok berikut meminta waktu secara interaktif, hanya menerima **satu** bucket satu jam, meminta konfirmasi, dan tidak akan menyalakan timer yang sebelumnya memang nonaktif. Password dibaca unit dari environment file, bukan command line:

```bash
siem_alarm_backfill_one_bucket() {
read -r -p 'BACKFILL_FROM UTC (YYYY-MM-DDTHH:00:00Z): ' BACKFILL_FROM
read -r -p 'BACKFILL_TO   UTC (YYYY-MM-DDTHH:00:00Z): ' BACKFILL_TO

BOUNDARY_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:00:00Z$'
if [[ ! "${BACKFILL_FROM}" =~ ${BOUNDARY_RE} || ! "${BACKFILL_TO}" =~ ${BOUNDARY_RE} ]]; then
  echo 'Format/boundary UTC ditolak.' >&2
  return 1
fi
BACKFILL_FROM_EPOCH="$(date -u -d "${BACKFILL_FROM}" +%s)" || return 1
BACKFILL_TO_EPOCH="$(date -u -d "${BACKFILL_TO}" +%s)" || return 1
if (( BACKFILL_TO_EPOCH - BACKFILL_FROM_EPOCH != 3600 )); then
  echo 'Backfill harus tepat satu bucket 1 jam.' >&2
  return 1
fi
printf 'Akan backfill: %s <= timestamp < %s\n' "${BACKFILL_FROM}" "${BACKFILL_TO}"
read -r -p 'Ketik BACKFILL untuk melanjutkan: ' BACKFILL_CONFIRM
if [[ "${BACKFILL_CONFIRM}" != 'BACKFILL' ]]; then
  echo 'Backfill dibatalkan.'
  return 1
fi

TIMER_WAS_ACTIVE=0
if sudo systemctl is-active --quiet siem-alarm-scoring.timer; then
  TIMER_WAS_ACTIVE=1
fi
sudo systemctl stop siem-alarm-scoring.timer
sudo systemctl stop siem-alarm-scoring.service
if sudo systemd-run --quiet --wait --collect \
    --unit=siem-alarm-backfill \
    --uid=siem-alarm --gid=siem-alarm \
    --working-directory=/opt/wazuh-risk-scoring \
    --property=EnvironmentFile=/etc/wazuh-risk-scoring/siem-alarm.env \
    --property=StateDirectory=wazuh-risk-scoring \
    --property=StateDirectoryMode=0750 \
    --property=NoNewPrivileges=true \
    --property=PrivateTmp=true \
    --property=ProtectSystem=strict \
    --property=ProtectHome=true \
    --property='ReadWritePaths=/opt/wazuh-risk-scoring/logs /var/lib/wazuh-risk-scoring' \
    --property=MemoryHigh=512M \
    --property=MemoryMax=1G \
    --property=MemorySwapMax=0 \
    --property=CPUWeight=25 \
    --property=IOWeight=25 \
    --property=TimeoutStartSec=240s \
    /usr/bin/python3 -B \
    /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py \
    --config /opt/wazuh-risk-scoring/config.siem_alarm.json \
    --once \
    --from "${BACKFILL_FROM}" \
    --to "${BACKFILL_TO}"; then
  if (( TIMER_WAS_ACTIVE == 1 )); then
    sudo systemctl start siem-alarm-scoring.timer
  fi
  echo 'Backfill sukses.'
else
  BACKFILL_STATUS=$?
  echo "Backfill gagal (exit ${BACKFILL_STATUS}); timer sengaja tetap berhenti." >&2
  return "${BACKFILL_STATUS}"
fi
}
siem_alarm_backfill_one_bucket
BACKFILL_RESULT=$?
unset -f siem_alarm_backfill_one_bucket
(( BACKFILL_RESULT == 0 ))
```

Catatan:
- `--from` dan explicit `--to` wajib tepat pada boundary bucket UTC; engine menolak window manual yang tidak aligned agar snapshot tidak parsial.
- `--from` bersifat inclusive (`>=`) dan `--to` bersifat exclusive (`<`).
- Jangan gunakan `--loop` untuk backfill.
- Hentikan timer dan scorer aktif selama backfill agar run calendar tidak bertabrakan; lock tetap menjadi pengaman terakhir. Pada kegagalan, timer sengaja dibiarkan berhenti untuk investigasi.
- Manual `--from/--to` tidak memajukan checkpoint calendar. Setelah sukses, run calendar berikutnya tetap memvalidasi backlog checkpoint secara idempotent.
- Jika satu bucket melebihi `max_alerts_per_bucket`, **jangan pecah di tengah bucket**: snapshot parsial akan menghasilkan frequency/count yang salah. Ukur resource di staging, lalu naikkan limit dan batas cgroup secara terkontrol atau kurangi alert noisy di sumber agregasi tanpa menghapus raw evidence.
- Backfill historis dapat membuat dokumen `alarm_escalation` lama. Untuk mencegah aplikasi eksternal menganggapnya alert baru, pertimbangkan set sementara `"escalation_log_enabled": false` saat backfill historis, atau pastikan aplikasi eksternal memfilter window waktu yang benar.

### 12.8 Checklist scheduling

- [ ] `/etc/systemd/system/siem-alarm-scoring.service` dibuat.
- [ ] `/etc/systemd/system/siem-alarm-scoring-failure@.service` dibuat dan journal tag-nya dimonitor eksternal.
- [ ] `/etc/systemd/system/siem-alarm-scoring.timer` dibuat.
- [ ] `OnCalendar=*-*-* *:0/5:00` sudah terkonfigurasi.
- [ ] `systemctl daemon-reload` dijalankan.
- [ ] Timer di-enable dan di-start.
- [ ] `systemctl list-timers` menampilkan NEXT run dalam ~5 menit.
- [ ] Service berhasil jalan minimal sekali.
- [ ] Log tidak ada error.
- [ ] Checkpoint `/var/lib/wazuh-risk-scoring/checkpoint.json` dibuat setelah run calendar sukses dan dimiliki `siem-alarm:siem-alarm`.
- [ ] Run selesai sebelum `TimeoutStartSec=240s` dan tidak menyentuh `MemoryMax=1G`.
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
GET wazuh-alerts-4.x-2026.05.22/_count
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
- [ ] Jika scoring membutuhkan field custom, path-nya ditambahkan ke array `source_includes`; tanpa ini field tidak ikut payload `_source` terfilter.

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

### 18.4 Guardrail performa Snapshot-Bulk V2

`max_alerts_per_bucket=100000` dan `max_cases_per_bucket=20000` adalah fail-safe ceiling, **bukan** jaminan bahwa VM mampu memproses batas itu dalam 240 detik. Batas case mencegah mode dedup/cardinality ekstrem memenuhi RAM sebelum bulk. Kapasitas aktual ditentukan alert per bucket, jumlah case unik, cardinality evidence, heap/disk Indexer, dan ukuran dokumen hasil.

Initial search pada scroll memakai `track_total_hits=true`. Wazuh Indexer 4.14.7
menolak threshold numerik `track_total_hits` pada scroll context, sehingga total hit
harus dihitung eksak sebelum cap diperiksa. Cap tetap menghentikan bucket sebelum
pagination, agregasi, bulk, dan checkpoint, tetapi biaya exact-hit count tetap terjadi
dan harus masuk pengukuran load test.

Dengan `A` raw alert, `C` case unik, page/mget/bulk 1.000, jumlah request normal kira-kira:

```text
search/scroll  ≈ ceil(A / 1000)
state _mget    ≈ ceil(C / 1000)
bulk write     ≈ sampai 2 × ceil(C / 1000), dapat bertambah bila batas 5 MiB tercapai
```

Dengan timer lima menit dan laju alert yang relatif merata, snapshot current membaca sekitar `5,5 × A` per jam, lalu finalisasi closed bucket menambah `1 × A`: total sekitar `6,5 × A`. Pola lama yang membaca previous bucket pada dua run awal boundary mendekati `7,5 × A`, sehingga V2 mengurangi scan steady-state sekitar 13% sambil tetap menghasilkan snapshot penuh. Contoh `A=20.000` dan `C=500` memerlukan kira-kira 20 request search/scroll + 1 `_mget` + maksimal 2 bulk, bukan ratusan/ribuan HTTP per-case. Angka ini model kapasitas, bukan pengganti load test karena burst dan cardinality evidence dapat mengubah hasil.

Jangan menambah worker paralel pada AIO. Batch berjalan serial dan bounded agar pengurangan round-trip tidak berubah menjadi burst CPU/heap/disk pada Indexer. Tuning yang aman dilakukan berurutan: pertahankan exact daily index dan source filtering, ukur peak, kurangi rule noisy dari agregasi, lalu ubah batch/limit hanya melalui shadow load test. Raw `wazuh-alerts-*` tetap menjadi buffer/evidence resmi; proyek tidak membuat queue raw kedua.

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
- [ ] Memberi `cluster_composite_ops`/`indices_all` ketika runtime hanya membutuhkan permission bulk individual.
- [ ] Menganggap HTTP 200 berarti seluruh item `_bulk` sukses tanpa memeriksa `errors` dan status setiap item.
- [ ] Memakai `refresh=true` pada setiap bulk dan menambah pressure refresh Indexer.
- [ ] Memecah backfill di tengah bucket lalu menganggap count parsial sebagai snapshot lengkap.
- [ ] Mengedit/menghapus checkpoint saat timer atau service masih aktif.

---

## 20. Go-Live Checklist

**Infrastruktur:**
- [ ] Service Wazuh AIO healthy (manager, indexer, dashboard, filebeat).
- [ ] `wazuh-alerts-*` normal dan terisi.

**Persiapan:**
- [ ] Internal user/role Indexer `siem_alarm_service` memakai cluster `cluster_composite_ops_ro` + `indices:data/read/scroll/clear` + `indices:data/write/bulk*`, source `read`, destination `read,index,create_index`, tanpa permission lebih luas.
- [ ] TLS verification berhasil memakai `/opt/wazuh-risk-scoring/root-ca.pem`; tidak ada `-k`/`verify_ssl: false` di production.
- [ ] `/etc/wazuh-risk-scoring/siem-alarm.env` berisi secret sebenarnya dan permission `0640 root:siem-alarm`.
- [ ] Audit field sudah dijalankan.
- [ ] Inventory root-owned `assets.json` mencakup semua agent emitting; fallback label hanya dipakai bila disengaja dan `asset.source=default` sudah diaudit.
- [ ] Config Snapshot-Bulk V2 sudah disesuaikan (`source_index: wazuh-alerts-4.x-{date}`, `bucket_minutes: 60`, eligibility delay `lookback_overlap_minutes: 7`, `max_alerts_per_bucket: 100000`, `max_cases_per_bucket: 20000`, `_mget`/bulk: 1000, bulk: 5 MiB, catch-up: 2, checkpoint di `/var/lib`, `install_template: false`).
- [ ] Nama/tanggal index harian aktual, boundary tengah malam UTC, dan alert terlambat sudah diuji; pola exact-date tidak kehilangan evidence.
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
- [ ] Output V2 dibandingkan dengan query raw/V1 untuk bucket yang sama: case key, count, score, level, dan escalation identik.
- [ ] Hash identitas checkpoint cocok dengan config; setiap perubahan bucket/source/filter/dedup/destination memiliki rencana shadow/backfill, bukan reset diam-diam.
- [ ] Bulk failure injection membuktikan hanya item gagal yang diulang, `409` create-only dianggap idempotent, dan state tidak mendahului escalation.
- [ ] Load test minimal dua kali peak aktual: p95 run <60 detik, maksimum <240 detik, tidak ada `429`/failed shard, dan checkpoint hanya maju setelah seluruh bucket sukses.

**Scheduling:**
- [ ] Systemd service, failure handler, dan timer dibuat; `systemd-analyze verify` lulus pada host target.
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
- [ ] Log script, journal `daemon.crit`, usia checkpoint, durasi run, memory peak, serta rejection/heap Indexer dimonitor.
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

**Step 1 — Isolasi scorer tanpa menyentuh raw alert atau output:**

```bash
sudo systemctl stop siem-alarm-scoring.timer
sudo systemctl stop siem-alarm-scoring.service
sudo systemctl disable siem-alarm-scoring.timer
if sudo systemctl is-active --quiet siem-alarm-scoring.timer \
  || sudo systemctl is-active --quiet siem-alarm-scoring.service; then
  echo 'Scorer masih aktif; rollback dihentikan.' >&2
  false
else
  echo 'Scorer terisolasi. Wazuh utama tetap berjalan.'
fi
```

Rollback normal berhenti di sini sambil investigasi. `wazuh-alerts-*`, `siem-alarm-*`, dan checkpoint tidak dihapus; dashboard dapat sementara diberi banner bahwa agregasi sedang pause.

**Step 2 — Simpan bukti dan identifikasi penyebab:**

```bash
sudo tail -n 200 /opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
sudo journalctl -u siem-alarm-scoring.service -n 100 --no-pager
sudo ls -1dt /opt/wazuh-risk-scoring/backups/* 2>/dev/null | head
```

**Jalur A — rollback code/config tanpa menghapus output (default):**

- Review backup installer mode root-only dan diff file yang akan dipulihkan.
- Deploy ulang paket known-good melalui `sudo bash ./setup_siem_alarm_final.sh`; installer akan kembali meninggalkan timer nonaktif.
- Jika hanya config/inventory yang salah, pulihkan file itu secara selektif dari backup setelah review. Jangan menyalin seluruh direktori backup secara buta karena checkpoint, unit, secret, dan schema dapat berasal dari versi berbeda.
- Jalankan validator asset, manual service, query output, lalu enable timer hanya setelah hasil benar.

```bash
sudoedit /opt/wazuh-risk-scoring/config.siem_alarm.json
sudo -u siem-alarm /usr/bin/python3 -B \
  /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py \
  --validate-assets-only /opt/wazuh-risk-scoring/assets.json
sudo systemctl start siem-alarm-scoring.service
sudo systemctl show siem-alarm-scoring.service -p Result -p ExecMainStatus
sudo tail -n 50 /opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
```

**Jalur B — rebuild output (change-controlled, bukan rollback rutin):**

Jangan menjalankan wildcard `DELETE siem-alarm-*` dari runbook copy-paste. Rebuild hanya dilakukan setelah snapshot/backup, rentang UTC dan daftar **nama index persis** disetujui, timer/service terbukti berhenti, checkpoint diarsipkan (bukan diedit), dan seluruh bucket yang dihapus dijadwalkan untuk backfill dari `wazuh-alerts-*`. Setelah satu destination index dihapus, checkpoint lama tidak membuktikan history lengkap; jangan start service/timer sampai backfill boundary-aligned pada bagian 12.7 dan validasi count selesai. Jika raw index sumber sudah melewati retensi, rebuild lengkap tidak mungkin dilakukan.

**Step 3 — Re-enable hanya untuk Jalur A yang sudah lolos validasi atau Jalur B yang sudah selesai rebuild:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now siem-alarm-scoring.timer
sudo systemctl list-timers | grep siem-alarm
```

### 21.3 Rollback checklist

- [ ] Timer dihentikan sebelum rollback.
- [ ] Checkpoint tetap utuh untuk rollback normal; archive/rebuild hanya lewat change control.
- [ ] `wazuh-alerts-*` tidak disentuh.
- [ ] Penyebab diidentifikasi dari log.
- [ ] Jalur A (restore code/config) atau Jalur B (rebuild output) dipilih dan didokumentasikan.
- [ ] Test manual berhasil sebelum re-enable.
- [ ] Timer di-enable ulang dan NEXT run terlihat.

---

## 22. Kesimpulan Final

Desain final:

```text
wazuh-alerts-*  → raw evidence, tidak pernah diubah; query memakai concrete daily index
siem-alarm-*    → snapshot progressive alarm, di-update tiap 5 menit, bucket 1 jam

Dedup key default  : agent.id + rule.id + timestamp_bucket_1h
alarm.id           : sha256(case_key), dipakai sebagai document ID → update, bukan insert baru
raw_alert_count    : dihitung ulang eksak; retry tidak menambah count dua kali
risk.score         : naik organik seiring raw_alert_count bertambah
Log eskalasi       : dokumen alarm_escalation di siem-alarm-* saat level eligible/naik
Maks log eskalasi  : 3 per alarm per bucket (Medium, High, Critical)
Evidence           : srcip/dstip/port/proto/url/user/file/hash — bukan pemecah case
Read/write state   : `_mget` + two-phase bounded `_bulk`, tanpa refresh paksa
Recovery           : checkpoint atomik + maksimal dua catch-up bucket per run
```

Ini adalah desain yang paling realistis untuk menekan alert fatigue tanpa kehilangan raw evidence dan tetap memberikan visibilitas real-time ke SOC.

---

*Versi 5.2 — Baseline Wazuh 4.14.7/Filebeat 7.10.2, exact daily source index, scroll-compatible exact hit tracking, source filtering, Snapshot-Bulk V2 (`_mget` + two-phase `_bulk`), asset inventory tervalidasi, cardinality/checkpoint/catch-up bounded, least-privilege bulk permission, resource-capped systemd, OnFailure journal handler, TLS mandatory, deterministic escalation/state, backup installer, template, dan ISM retention.*
