# SIEM Alarm Scoring untuk Wazuh 4.14.7

Proyek ini mengubah banyak raw alert Wazuh menjadi alarm SOC per `agent.id + rule.id + bucket 1 jam`. Raw evidence `wazuh-alerts-*` hanya dibaca; state alarm dan event eskalasi ditulis ke `siem-alarm-*`.

Baseline yang didukung dan dipaksa oleh installer adalah Ubuntu single-node/all-in-one dengan `wazuh-manager`, `wazuh-indexer`, dan `wazuh-dashboard` **4.14.7**, Filebeat OSS **7.10.2**, serta Python **3.8 atau lebih baru**. Baseline Python 3.8 dipertahankan agar Ubuntu 20.04 dapat memakai interpreter sistem tanpa mengganti symlink `/usr/bin/python3` atau menambah PPA. Deployment distributed, versi patch lain, container, atau Wazuh Cloud memerlukan review tersendiri.

## Status audit

Implementasi sudah di-hardening untuk production, tetapi aktivasi tetap harus melewati staging/shadow run pada server yang spesifik. Installer:

- memvalidasi versi, service, certificate chain, Filebeat output, Python/JSON, schema aset, unit test, dan unit systemd;
- membuat backup file lama dan menolak symlink pada file terkelola;
- memasang resource limit dan lock proses;
- tidak mengaktifkan timer setelah instalasi maupun upgrade.

Engine memakai exact daily source index, `_source` allowlist, scroll serial, `_mget`, dan two-phase `_bulk`. Checkpoint hanya metadata recovery; proyek tidak membuat buffer/queue raw alert baru. Batas default adalah 100.000 raw alert dan 20.000 case unik per bucket. Batas tersebut adalah fail-safe, bukan jaminan kapasitas VM.

## Kegunaan setiap file

| File | Kegunaan | Dipasang ke server |
|---|---|---|
| `setup_siem_alarm_final.sh` | Preflight, backup, instalasi file, user Linux, systemd, logrotate | Dijalankan sebagai root |
| `siem_alarm_scoring_final.py` | Agregasi, risk scoring, checkpoint, `_mget`, dan `_bulk` | `/opt/wazuh-risk-scoring/` |
| `wazuh_field_audit_final.py` | Audit field raw alert dengan exact daily indexes | `/opt/wazuh-risk-scoring/` |
| `config.siem_alarm.example.json` | Baseline konfigurasi runtime | Disalin menjadi `config.siem_alarm.json` pada instalasi baru |
| `assets.example.json` | Contoh schema inventory aset; bukan data production | Runtime baru dimulai dengan `{}` |
| `siem_alarm_template_final.json` | Mapping dan setting `siem-alarm-*` | Dipasang satu kali oleh admin Indexer |
| `siem_alarm_ism_policy.json` | Retensi default 90 hari | Dipasang satu kali oleh admin Indexer |
| `final_checklist_siem_alarm_wazuh_4_14_7.md` | Runbook rinci, tuning, backfill, dashboard, dan rollback | Referensi operator |
| `contoh.json` | Contoh raw alert dan dokumen hasil | Tidak dipakai runtime |
| `docs/logic_agregat_siem_alarm.pdf` | Dokumen 49 halaman: topologi, flowchart, perhitungan, dummy raw Wazuh, state, dan escalation | Referensi arsitektur/SOC |
| `docs/logic_agregat_siem_alarm.tex` | Source XeLaTeX untuk membangun ulang PDF | Tidak dipakai runtime |
| `docs/examples/dummy_wazuh_alerts_rule_5710.json` | Sepuluh raw alert sintetis dalam format representatif `wazuh-alerts-*` untuk rule default SSHD 5710 | Fixture dokumentasi |
| `docs/examples/dummy_aggregation_result_rule_5710.json` | Hasil state dan escalation yang dihitung engine dari fixture rule 5710 | Fixture dokumentasi |
| `tests/` | Regression test correctness dan guardrail | Dijalankan installer sebelum mutasi |

## Aturan command

Semua command di bawah ditujukan untuk **Bash pada host Ubuntu Wazuh AIO**.

- Blok “siap tempel” tidak mempunyai placeholder dan aman dijalankan pada tahapnya.
- Password, URL yang cocok dengan SAN sertifikat, inventory agent, dan keputusan overwrite template/policy memang harus diisi atau dikonfirmasi operator.
- Jangan menempel seluruh README sebagai satu script. Jalankan per tahap dan periksa output sebelum lanjut.
- Jangan gunakan `curl -k`, `--insecure`, password di command line, runtime user `admin`, atau wildcard delete.

## 1. Validasi paket proyek

Jalankan dari folder proyek. Blok ini siap tempel:

```bash
python3 -B -m unittest discover -s tests -v
bash -n ./setup_siem_alarm_final.sh
python3 -m json.tool config.siem_alarm.example.json >/dev/null
python3 -m json.tool assets.example.json >/dev/null
python3 -m json.tool siem_alarm_template_final.json >/dev/null
python3 -m json.tool siem_alarm_ism_policy.json >/dev/null
python3 -m json.tool contoh.json >/dev/null
python3 -m json.tool docs/examples/dummy_wazuh_alerts_rule_5710.json >/dev/null
python3 -m json.tool docs/examples/dummy_aggregation_result_rule_5710.json >/dev/null
```

Semua test dan validator harus berakhir dengan exit code `0`.

## 2. Preflight server Wazuh

Jalankan di host AIO. Blok ini siap tempel:

```bash
dpkg-query -W -f='${Package} ${Version}\n' \
  wazuh-manager wazuh-indexer wazuh-dashboard filebeat
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
sudo filebeat test output
```

Output harus menunjukkan ketiga komponen sentral pada `4.14.7`, Filebeat `7.10.2`, seluruh service `active`, dan koneksi output Filebeat sukses. Installer akan mengulang pemeriksaan ini dan berhenti sebelum mutasi jika ada ketidaksesuaian.

Periksa SAN sertifikat Indexer:

```bash
sudo openssl x509 \
  -in /etc/wazuh-indexer/certs/indexer.pem \
  -noout -subject -issuer -dates -ext subjectAltName
```

Untuk AIO, README memakai URL default berikut. Jalankan sekali pada setiap shell operator:

```bash
export SIEM_INDEXER_URL='https://127.0.0.1:9200'
```

Jika `127.0.0.1` tidak tercantum pada SAN, ganti dengan hostname/IP yang tercantum. URL yang sama harus dipakai di `config.siem_alarm.json`.

## 3. Instal file

Masuk ke folder proyek yang berisi installer, lalu blok berikut siap tempel:

```bash
sudo bash ./setup_siem_alarm_final.sh
```

Jika path CA/node certificate berbeda, blok berikut sengaja memerlukan penyesuaian:

```bash
sudo \
  WAZUH_CA_SOURCE=/path/aktual/root-ca.pem \
  WAZUH_INDEXER_CERT_SOURCE=/path/aktual/indexer.pem \
  bash ./setup_siem_alarm_final.sh
```

Pastikan installer tidak mengaktifkan timer:

```bash
if sudo systemctl is-enabled --quiet siem-alarm-scoring.timer; then
  echo 'ERROR: timer tidak boleh aktif sebelum go-live.' >&2
else
  echo 'OK: timer masih nonaktif.'
fi
```

Pada instalasi baru, `/opt/wazuh-risk-scoring/assets.json` berisi `{}`. Ini disengaja agar ID contoh `001`–`004` tidak mengklasifikasikan agent production secara diam-diam.

## 4. Buat user dan role Indexer

Masuk ke Wazuh Dashboard sebagai administrator, lalu buka **Indexer Management → Security**:

1. Buat internal user `siem_alarm_service` dengan password unik.
2. Buat role `siem_alarm_runtime`.
3. Isi cluster permissions dengan `cluster_composite_ops_ro` serta permission individual `indices:data/read/scroll/clear` dan `indices:data/write/bulk*`.
4. Untuk index pattern `wazuh-alerts-*`, beri action group `read`.
5. Untuk index pattern `siem-alarm-*`, beri `read`, `index`, dan `create_index`.
6. Kosongkan tenant permissions, lalu map user `siem_alarm_service` ke role tersebut.

Jangan memberi `cluster_composite_ops`, `indices_all`, Security API, template, ISM, atau akses index Wazuh lain kepada runtime user.

Uji TLS, autentikasi, mapping role, dan hak baca pada exact daily source index.
`--user siem_alarm_service` meminta password secara interaktif:

```bash
: "${SIEM_INDEXER_URL:?export SIEM_INDEXER_URL terlebih dahulu}"
SIEM_ALERT_INDEX_DATE="$(date -u +%Y.%m.%d)"
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  "${SIEM_INDEXER_URL}/wazuh-alerts-4.x-${SIEM_ALERT_INDEX_DATE}/_count?pretty"
```

Respons harus HTTP `200`. Endpoint akar `GET /` dapat menghasilkan `403` untuk
role least-privilege ini karena runtime sengaja tidak diberi
`cluster:monitor/main`; jangan menambah permission tersebut hanya agar endpoint
akar menjadi `200`. Permission individual `indices:data/read/scroll/clear`
diperlukan pada scope cluster untuk menutup scroll context; action group `read`
pada source index sudah memenuhinya pada scope index.

## 5. Simpan secret runtime

```bash
sudoedit /etc/wazuh-risk-scoring/siem-alarm.env
```

Isi satu baris dengan password sebenarnya:

```text
WAZUH_PASS="PASSWORD_INDEXER_SEBENARNYA"
```

Jangan memakai awalan `GANTI_`/`CHANGE_`, newline, atau menyimpan password di JSON/repository. Jika password mengandung `"` atau `\`, escape sesuai syntax `EnvironmentFile` systemd.

Terapkan dan periksa permission:

```bash
sudo chown root:siem-alarm /etc/wazuh-risk-scoring/siem-alarm.env
sudo chmod 0640 /etc/wazuh-risk-scoring/siem-alarm.env
sudo stat -c '%U:%G %a %n' /etc/wazuh-risk-scoring/siem-alarm.env
```

Output terakhir harus `root:siem-alarm 640`. Engine menolak inline password dan username `admin`.

## 6. Sesuaikan konfigurasi runtime

```bash
sudoedit /opt/wazuh-risk-scoring/config.siem_alarm.json
```

Untuk baseline AIO, pertahankan nilai penting berikut dan ubah `opensearch_url` hanya bila SAN menuntut hostname lain:

```json
{
  "opensearch_url": "https://127.0.0.1:9200",
  "username": "siem_alarm_service",
  "password_env": "WAZUH_PASS",
  "verify_ssl": true,
  "ca_cert": "/opt/wazuh-risk-scoring/root-ca.pem",
  "source_index": "wazuh-alerts-4.x-{date}",
  "destination_index_prefix": "siem-alarm",
  "assets_file": "/opt/wazuh-risk-scoring/assets.json",
  "bucket_minutes": 60,
  "process_current_bucket_only": true,
  "lookback_overlap_minutes": 7,
  "max_alerts_per_bucket": 100000,
  "max_cases_per_bucket": 20000,
  "page_size": 1000,
  "mget_batch_size": 1000,
  "bulk_max_actions": 1000,
  "bulk_max_bytes": 5242880,
  "max_catchup_buckets_per_run": 2,
  "install_template": false
}
```

Cuplikan di atas menunjukkan key penting, bukan pengganti seluruh file. Jangan menghapus key lain dari config terpasang. Validasi JSON:

```bash
sudo /usr/bin/python3 -m json.tool \
  /opt/wazuh-risk-scoring/config.siem_alarm.json >/dev/null
```

`source_index` harus exact daily pattern dengan satu `{date}`. Jika Wazuh memakai custom index prefix/date routing, hentikan proses dan buktikan pola aktual terlebih dahulu.

## 7. Set asset value setiap agent

Untuk 5–25 agent, gunakan `assets.json` sebagai sumber utama. File ini berada di manager, root-owned, mudah direview, dan tidak memerlukan perubahan endpoint.

### 7.1 Daftar agent

```bash
sudo /var/ossec/bin/agent_control -l
```

Catat ID dengan leading zero dan nama persis. Sertakan `000` bila alert lokal manager ikut dinilai. Audit ulang inventory setelah re-enrollment karena ID dapat berubah atau dipakai ulang.

### 7.2 Tentukan nilai

| Nilai | Kategori wajib | Contoh umum |
|---:|---|---|
| 5 | Critical | Domain controller, database inti, firewall/VPN utama |
| 4 | High | Web/mail server production, sensor IDS penting |
| 3 | Medium | Application server internal |
| 2 | Low | Workstation atau perangkat pendukung |
| 1 | Minimal | Dev/test non-production |

Nilai adalah input risk score; kategori adalah metadata dan harus cocok persis. Jangan memberi nilai `5` ke semua agent karena hasil prioritas akan kehilangan makna.

### 7.3 Isi inventory

```bash
sudoedit /opt/wazuh-risk-scoring/assets.json
```

Contoh berikut **harus diganti dengan ID/nama/aset aktual**, jangan ditempel tanpa penyesuaian:

```json
{
  "000": {
    "agent_name": "wazuh-manager",
    "asset_value": 5,
    "asset_category": "Critical",
    "asset_type": "Wazuh Manager",
    "asset_owner": "SOC",
    "environment": "Production"
  },
  "001": {
    "agent_name": "dc-prod-01",
    "asset_value": 5,
    "asset_category": "Critical",
    "asset_type": "Domain Controller",
    "asset_owner": "Infrastructure",
    "environment": "Production"
  },
  "007": {
    "agent_name": "user-laptop-07",
    "asset_value": 2,
    "asset_category": "Low",
    "asset_type": "Workstation",
    "asset_owner": "End User Computing",
    "environment": "Office"
  }
}
```

Kunci top-level `agent.id` adalah pilihan utama. Fallback key `agent.name` didukung, tetapi ID lebih mudah diaudit. Bila `agent_name` disertakan pada entry berbasis ID, engine fail-closed jika alert mempunyai nama berbeda; ini mendeteksi inventory stale atau ID yang dipakai ulang.

### 7.4 Validasi inventory

Blok ini siap tempel setelah file diisi:

```bash
sudo chown root:siem-alarm /opt/wazuh-risk-scoring/assets.json
sudo chmod 0640 /opt/wazuh-risk-scoring/assets.json
sudo -u siem-alarm /usr/bin/python3 -B \
  /opt/wazuh-risk-scoring/siem_alarm_scoring_final.py \
  --validate-assets-only /opt/wazuh-risk-scoring/assets.json
```

Validator menolak file hilang, top-level non-object, ID berpadded, field typo, nilai non-integer/di luar `1..5`, alias ganda, kategori tidak cocok, dan metadata kosong.

Prioritas engine:

```text
assets.json[agent.id] → assets.json[agent.name]
→ agent.labels.asset.* resmi Wazuh sebagai fallback
→ default 3 / Medium dengan warning
```

Field root `labels.asset.*` dan `asset.*` tidak dipercaya karena dapat berasal dari payload log/decoder. Inventory dibaca ulang setiap run. Perubahan memengaruhi snapshot berikutnya; bucket historis yang sudah finalized hanya berubah melalui backfill terkontrol.

### 7.5 Opsi label Wazuh

Jika metadata harus ikut pada raw alert, gunakan label resmi Wazuh. Contoh local `ossec.conf` yang valid adalah top-level `<labels>` di dalam `<ossec_config>`:

```xml
<ossec_config>
  <labels>
    <label key="asset.value">4</label>
    <label key="asset.category">High</label>
    <label key="asset.type">Web Server</label>
    <label key="asset.owner">Infrastructure</label>
    <label key="asset.environment">Production</label>
  </labels>
</ossec_config>
```

Untuk production, kelola label melalui group `agent.conf` di manager, bungkus dengan `<agent_config>`, pertahankan konfigurasi existing, dan validasi temporary file sebelum aktivasi:

```bash
sudo /var/ossec/bin/verify-agent-conf \
  -f /var/ossec/etc/shared/default/agent.conf.tmp
```

Centralized config didistribusikan dan di-reload agent otomatis. Label hanya memengaruhi alert baru. Karena `assets.json` mempunyai prioritas lebih tinggi, hapus entry inventory hanya jika fallback label memang disengaja.

## 8. Pasang template dan retention policy

Tahap ini memakai admin Indexer dan merupakan perubahan cluster satu kali. Sebelum `PUT`, lakukan `GET`. Jika object sudah ada, review/diff; jangan menimpanya otomatis.

```bash
: "${SIEM_INDEXER_URL:?export SIEM_INDEXER_URL terlebih dahulu}"
sudo curl --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  "${SIEM_INDEXER_URL}/_index_template/siem-alarm-template?pretty"

sudo curl --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  "${SIEM_INDEXER_URL}/_plugins/_ism/policies/siem-alarm-retention-90d?pretty"
```

Jika `404`, object belum ada. Jika sudah ada, bandingkan dengan file proyek dan ikuti mekanisme update policy `if_seq_no`/`if_primary_term`. Setelah review, command mutasi berikut siap tempel:

```bash
: "${SIEM_INDEXER_URL:?export SIEM_INDEXER_URL terlebih dahulu}"
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  -H 'Content-Type: application/json' \
  -X PUT "${SIEM_INDEXER_URL}/_index_template/siem-alarm-template" \
  --data-binary @/opt/wazuh-risk-scoring/siem_alarm_template_final.json

sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  -H 'Content-Type: application/json' \
  -X PUT "${SIEM_INDEXER_URL}/_plugins/_ism/policies/siem-alarm-retention-90d" \
  --data-binary @/opt/wazuh-risk-scoring/siem_alarm_ism_policy.json
```

Template harus terpasang sebelum bulk pertama. Runtime config harus tetap `"install_template": false`.

## 9. Audit field raw alert

Jalankan satu kali saat beban rendah. Password diminta interaktif. Default `{date}` hanya menyentuh tanggal UTC dalam window audit—umumnya dua daily index untuk 24 jam—dan wildcard ditolak:

```bash
: "${SIEM_INDEXER_URL:?export SIEM_INDEXER_URL terlebih dahulu}"
sudo -u siem-alarm /usr/bin/python3 -B \
  /opt/wazuh-risk-scoring/wazuh_field_audit_final.py \
  --url "${SIEM_INDEXER_URL}" \
  --user siem_alarm_service \
  --verify-ssl \
  --ca-cert /opt/wazuh-risk-scoring/root-ca.pem \
  --hours 24 \
  --limit 3000 \
  --output /opt/wazuh-risk-scoring/logs/wazuh_field_audit_report.json
```

Review report untuk custom decoder fields. Bila scoring memerlukannya dan field belum ada pada allowlist default, tambahkan nama field ke `source_includes`; jangan mengganti allowlist dengan `_source: true` pada run rutin.

## 10. Run manual sebelum go-live

Blok ini siap tempel setelah role, secret, config, inventory, template, dan ISM selesai:

```bash
sudo systemd-analyze verify \
  /etc/systemd/system/siem-alarm-scoring.service \
  /etc/systemd/system/siem-alarm-scoring-failure@.service \
  /etc/systemd/system/siem-alarm-scoring.timer
sudo systemctl daemon-reload
sudo systemctl start siem-alarm-scoring.service
sudo systemctl show siem-alarm-scoring.service \
  -p Result -p ExecMainStatus -p ExecMainCode
sudo journalctl -u siem-alarm-scoring.service -n 100 --no-pager
```

Syarat lulus: `Result=success`, `ExecMainStatus=0`, tidak ada `429`, timeout, failed shard, asset mismatch/default yang tidak direncanakan, cap exceeded, atau checkpoint error.

Tunggu refresh interval destination maksimal sekitar 30 detik, lalu periksa output:

```bash
: "${SIEM_INDEXER_URL:?export SIEM_INDEXER_URL terlebih dahulu}"
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  -H 'Content-Type: application/json' \
  -X POST "${SIEM_INDEXER_URL}/siem-alarm-*/_search?pretty" \
  -d '{
    "size": 0,
    "query": {"term": {"document.type": "alarm_state"}},
    "aggs": {
      "by_agent": {
        "terms": {"field": "agent.id", "size": 100},
        "aggs": {
          "asset_source": {"terms": {"field": "asset.source", "size": 5}},
          "asset_value": {"terms": {"field": "asset.value", "size": 5}}
        }
      }
    }
  }'
```

Setiap agent yang diinventaris harus menunjukkan `asset.source=assets_json` dan nilai yang direncanakan. `agent_label` hanya valid jika fallback label dipilih. `default` harus diinvestigasi sebelum go-live.

`alarm.status=open` berarti bucket masih berjalan; `finalized` berarti snapshot bucket tertutup selesai. Field ini bukan acknowledge/resolve workflow analyst.

Jika belum ada alert pada window, run dapat sukses tanpa membuat destination index. Tunggu atau hasilkan alert uji yang aman dan ulangi; jangan aktifkan timer tanpa memverifikasi minimal satu dokumen aktual.

## 11. Aktifkan timer

Aktifkan hanya setelah seluruh validasi manual lulus:

```bash
sudo systemctl enable --now siem-alarm-scoring.timer
sudo systemctl status siem-alarm-scoring.timer --no-pager
sudo systemctl list-timers --all | grep siem-alarm
```

Periksa dua atau tiga run pertama:

```bash
sudo journalctl -u siem-alarm-scoring.service --since '30 minutes ago' --no-pager
sudo stat -c '%U:%G %a %n' /var/lib/wazuh-risk-scoring/checkpoint.json
sudo /usr/bin/python3 -m json.tool \
  /var/lib/wazuh-risk-scoring/checkpoint.json
```

`lookback_overlap_minutes=7` adalah eligibility delay. Dengan timer 5 menit, finalisasi normal terjadi pada tick sekitar boundary +10 menit, ditambah `AccuracySec`; bukan tepat +7 menit. Alert yang masuk Indexer setelah finalisasi tidak direvisi otomatis dan memerlukan replay/backfill.

Untuk margin aman, ukur end-to-end Filebeat/Indexer lag dan tetapkan SLO internal jauh di bawah eligibility delay, misalnya p99 di bawah 5 menit. Monitor juga:

- durasi run harus jauh di bawah `TimeoutStartSec=240s`;
- tidak ada `429`, timeout, shard failure, cap 100.000 alert/20.000 case, atau `MemoryMax`;
- checkpoint dan dokumen `alarm_state` terus bergerak;
- disk/heap/CPU Wazuh tidak memburuk pada jam puncak;
- rasio `asset.source=default` tetap nol untuk agent wajib inventory.

## 12. Dashboard, outage, dan rollback

Buat index pattern/data view `siem-alarm-*` dengan time field `timestamp`. Filter state adalah `document.type = alarm_state`; panel escalation memakai `document.type = alarm_escalation`.

Untuk outage panjang atau late alert, gunakan prosedur satu-bucket, boundary-aligned, dengan konfirmasi dan pemulihan status timer pada [bagian manual backfill](final_checklist_siem_alarm_wazuh_4_14_7.md#127-manual-backfill-setelah-outage). Manual backfill tidak memajukan checkpoint calendar.

Rollback normal tidak menghapus index:

```bash
sudo systemctl stop siem-alarm-scoring.timer
sudo systemctl stop siem-alarm-scoring.service
sudo systemctl disable siem-alarm-scoring.timer
```

Raw Wazuh tetap berjalan. Pilih restore code/config tanpa menghapus output, atau full rebuild melalui change control. Jangan hapus `siem-alarm-*` lalu menyalakan service dengan checkpoint lama. Lihat [rollback plan](final_checklist_siem_alarm_wazuh_4_14_7.md#21-rollback-plan).

## 13. Upgrade proyek

Installer mempertahankan config, inventory, secret, dan checkpoint existing; script/unit diperbarui dan timer tetap dinonaktifkan. Setelah upgrade:

1. baca seluruh warning migration;
2. tambahkan key baru dari config example, termasuk `max_cases_per_bucket`;
3. validasi ulang schema aset—field tambahan tidak dikenal kini ditolak;
4. periksa hash identitas checkpoint;
5. jalankan manual validation dan query aset;
6. baru enable timer.

Perubahan bucket, source/filter, dedup/rule override, atau destination prefix mengubah identitas case dan fail-closed terhadap checkpoint lama. Gunakan shadow destination atau controlled backfill; jangan hapus checkpoint hanya agar error hilang.

## Batas klaim “siap production”

Untuk 5–25 agent, jumlah agent sendiri kecil. Risiko kapasitas ditentukan EPS, burst, jumlah rule/case unik, dan cardinality evidence. Model steady-state timer 5 menit membaca sekitar `6,5 × A` raw alert per jam untuk laju `A` per bucket: current bucket dihitung ulang, lalu closed bucket difinalisasi sekali. `_mget`/bulk mengurangi request per case, tetapi tidak menghilangkan biaya scan snapshot.

Initial scroll memakai `track_total_hits=true` karena Wazuh Indexer 4.14.7
menolak threshold numerik pada scroll context. Karena itu Indexer menghitung total hit
eksak sebelum engine memeriksa `max_alerts_per_bucket`; cap tetap mencegah pagination,
agregasi, dan penulisan bucket yang terlalu besar, tetapi tidak menghilangkan biaya
exact-hit count. Masukkan biaya ini dalam shadow/load test.

Proyek dinyatakan **siap untuk staging production**, bukan otomatis terbukti kapasitasnya pada VM Anda. Go-live memerlukan shadow/load test pada traffic puncak, observasi beberapa bucket, dan rollback window. Jangan menaikkan cap, batch, paralelisme, atau cgroup limit sebelum ada hasil ukur.

## Referensi resmi

- [Wazuh 4.14.7 release notes](https://documentation.wazuh.com/current/release-notes/release-4-14-7.html)
- [Wazuh Indexer indices](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
- [Wazuh rules classification](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html)
- [Wazuh agent labels](https://documentation.wazuh.com/current/user-manual/agent/agent-management/labels.html)
- [Wazuh centralized configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)
- [OpenSearch default action groups](https://docs.opensearch.org/latest/security/access-control/default-action-groups/)
- [OpenSearch Bulk API](https://docs.opensearch.org/latest/api-reference/document-apis/bulk/)
- [OpenSearch Multi-get API](https://docs.opensearch.org/latest/api-reference/document-apis/multi-get/)

Untuk detail tuning, schema, progressive scoring, query dashboard, failure modes, backfill, dan rollback, lanjutkan ke [final checklist](final_checklist_siem_alarm_wazuh_4_14_7.md).
