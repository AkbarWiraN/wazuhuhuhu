# Dashboard SOC `siem-alarm-*` siap impor

Direktori ini berisi paket Saved Objects untuk **Wazuh Dashboard 4.14.7 / OpenSearch Dashboards 2.19.5**. Paket membuat dua dashboard:

- **SIEM Alarm SOC - Overview**: KPI, daftar event eskalasi terbaru, distribusi risiko, tren alarm, tren eskalasi, top agent, top rule, source-IP presence, dan cakupan asset inventory.
- **SIEM Alarm SOC - Triage & Investigation**: priority queue, escalation feed, noisy states, multi-source-IP states, dan indikator kelengkapan asset inventory.

Bundle memakai visualisasi agregasi klasik agar sesuai dengan plugin bawaan Wazuh Dashboard. Default time range adalah **Last 24 hours** dan refresh interval **5 menit**. Struktur artifact telah divalidasi secara statis terhadap schema dan fixture resmi tag Wazuh Dashboard `v4.14.7`; smoke import pada VM lab tetap menjadi gate wajib sebelum production.

## Isi paket

| File | Fungsi |
|---|---|
| `siem_alarm_soc_dashboard.ndjson` | Bundle utama yang diimpor ke Wazuh Dashboard |
| `siem_alarm_soc_dashboard.manifest.json` | Versi, checksum, jumlah objek, dan daftar ID exact untuk audit/rollback |
| `siem_alarm_soc_dashboard.export-request.json` | Request exact-ID untuk backup sebelum upgrade/overwrite |
| `build_soc_dashboard.py` | Generator dan validator deterministik, Python 3.8+ tanpa dependency eksternal |
| `validate_saved_objects_export.py` | Validator fail-closed untuk metadata dan exact object set hasil backup |

Bundle berisi 27 Saved Objects: 1 data view, 5 saved searches, 19 visualizations, dan 2 dashboards. Semua ID menggunakan namespace `siem-alarm-soc-v1-*` agar collision dapat diaudit sebelum impor.

## Makna angka pada dashboard

Dashboard sengaja memisahkan dua jenis dokumen:

| Panel | Dokumen yang dibaca | Makna |
|---|---|---|
| Alarm state buckets | `alarm_state` | Jumlah bucket agregat `agent.id + rule.id + jam UTC`, bukan jumlah incident yang belum ditutup |
| High/Critical dan Critical | `alarm_state` | Bucket state pada level risiko tersebut |
| Escalation events | `alarm_escalation` | Event create-only saat alarm pertama eligible atau naik level; satu alarm dapat mempunyai event Medium, High, lalu Critical |
| Latest escalated alarm events | `alarm_escalation` | Daftar event eskalasi terbaru, diurutkan `event.created` menurun; kolom default: waktu event, `rule.description`, `risk.level`, dan `agent.name` |
| Raw alerts represented | `alarm_state` berstatus `finalized` | Penjumlahan `source.raw_alert_count`; tidak pernah dijumlahkan dari dokumen escalation |
| Affected agents | `alarm_state` | Cardinality `agent.id` pada rentang waktu terpilih |
| Source-IP presence | `alarm_state` | Jumlah state document yang memuat IP pada sample terbatas, bukan frekuensi raw-event global per IP |

Semua panel data memiliki filter `document.type` eksplisit. Tanpa filter ini, field yang disalin ke dokumen escalation dapat menyebabkan double count. `alarm.status=open|finalized` adalah lifecycle bucket agregat, bukan status case analyst. Bukti otoritatif tetap berada di `wazuh-alerts-*`.

Field source IP pada schema saat ini bertipe `keyword`, dan `srcip_samples` dibatasi oleh konfigurasi sampling. Dashboard karena itu tidak mengklaim CIDR/geospatial analysis atau frekuensi raw global per IP. Untuk angka IP yang presisi, pivot ke raw alert Wazuh.

## 1. Prasyarat

Sebelum impor, pastikan:

1. `siem-alarm-*` sudah mempunyai dokumen nyata.
2. Mapping template proyek sudah terpasang sebelum index harian pertama dibuat.
3. Import dilakukan dengan account manusia/deployment khusus, bukan `siem_alarm_service`.
4. Account importer mempunyai akses Dashboard dan read pada `siem-alarm-*`; viewer juga memerlukan read data.
5. Mode multitenancy aktual sudah diperiksa. Konfigurasi production bawaan Wazuh Dashboard 4.14.7 menetapkan multitenancy `false`, tetapi deployment dapat mengubahnya.

Periksa mode pada VM:

```bash
sudo grep -nE '^[[:space:]]*opensearch_security\.multitenancy\.enabled:' \
  /etc/wazuh-dashboard/opensearch_dashboards.yml
```

- Jika nilainya `true`, Saved Objects tenant-scoped. Pilih custom shared tenant SOC secara eksplisit, berikan importer `kibana_all_write` dan viewer `kibana_all_read` pada tenant itu, lalu gunakan header `securitytenant` pada API.
- Jika nilainya `false`, menu **Switch tenants** tidak tersedia. Impor menuju default saved-object store; jangan menambahkan header `securitytenant` dan jangan mengklaim isolasi antar-tenant.

Validasi artifact dari clone proyek:

```bash
set -euo pipefail
cd ~/wazuhuhuhu/siem-alarm-
python3 dashboards/build_soc_dashboard.py --check
sha256sum dashboards/siem_alarm_soc_dashboard.ndjson
cat dashboards/siem_alarm_soc_dashboard.manifest.json
```

Output validator harus menyatakan `27 objects`, dan SHA256 harus sama dengan `artifact_sha256` pada manifest. Jangan mengimpor file jika hasil build berbeda tanpa review perubahan Git.

## 2. Impor melalui UI - metode utama

1. Login ke Wazuh Dashboard menggunakan account editor SOC.
2. Jika multitenancy `true`, pilih **custom tenant SOC yang tepat** melalui menu tenant. Jika `false`, lewati tahap ini dan gunakan default saved-object store.
3. Buka **Dashboard management / Stack Management -> Saved Objects**.
4. Pilih **Import**.
5. Pilih file `dashboards/siem_alarm_soc_dashboard.ndjson`.
6. Untuk instalasi pertama, gunakan pemeriksaan object existing dan biarkan **overwrite nonaktif**.
7. Selesaikan import hanya bila hasil menunjukkan **27 object sukses** dan tidak ada missing reference/error.
8. Buka **Dashboards** pada tenant/store yang sama, lalu buka:
   - `SIEM Alarm SOC - Overview`
   - `SIEM Alarm SOC - Triage & Investigation`

Bundle menyertakan data view deterministik berjudul `siem-alarm-*` dengan time field `timestamp`. Jika sebelumnya Anda membuat data view dengan title yang sama tetapi ID acak, kedua data view dapat muncul bersama. Hal ini tidak merusak dashboard karena semua reference bundle menunjuk ID deterministik `siem-alarm-soc-v1-data-view`. Jangan menghapus data view lama sebelum memastikan tidak ada saved search/dashboard lain yang masih mereferensikannya.

Collision dinilai berdasarkan pasangan `(type, id)`, bukan title. Pada instalasi pertama jangan memilih **Create new copies**, karena opsi itu mengganti ID dan akan membuat duplikasi baru setiap kali import. Pada upgrade bundle, lakukan backup exact-ID terlebih dahulu, baru gunakan overwrite secara terkontrol.

### Update bundle v1.0.0 ke v1.1.0

Versi `1.1.0` menambah satu saved search dan satu panel pada **SIEM Alarm SOC - Overview**: **Latest escalated alarm events**. Panel ini hanya membaca `document.type = alarm_escalation`, mengurutkan `event.created` dari terbaru ke terlama, dan menampilkan default `event.created`, `rule.description`, `risk.level`, serta `agent.name`.

Untuk dashboard yang sudah mengimpor bundle lama, gunakan **Import** ulang file NDJSON terbaru dengan **overwrite existing objects** aktif. Jangan gunakan **Create new copies** dan jangan membuat dashboard baru. Import akan memperbarui object dengan ID yang sama serta membuat satu object baru, sehingga panel tampil pada dashboard Overview yang sama.

Bundle lama berisi 26 object, sedangkan bundle ini berisi 27 object. Karena object baru belum ada sebelum upgrade, validator backup exact-ID versi baru memang tidak dapat dipakai untuk menilai backup bundle lama sebagai set 27 object. Simpan export/UI backup bundle lama terlebih dahulu; setelah upgrade selesai, backup berikutnya harus lolos validator 27 object.

### Mengubah kolom panel daftar event

Kolom panel adalah saved search, bukan field yang terkunci pada dashboard. Untuk mengubahnya:

1. Buka **Discover** dan pilih data view `siem-alarm-*`.
2. Pada menu **Open**, buka `SIEM Alarm SOC - Latest Escalated Alarm Events`.
3. Tambahkan field dengan tombol `+` atau hapus kolom yang tidak diperlukan. Filter `document.type: "alarm_escalation"` dan pengurutan `event.created` menurun harus dipertahankan.
4. Klik **Save** lalu overwrite saved search yang sama.
5. Kembali ke dashboard dan refresh. Panel akan memakai susunan kolom baru karena tetap mereferensikan saved search yang sama.

Perubahan kolom lokal akan ditimpa jika bundle proyek di-import ulang dengan overwrite. Bila susunan kolom itu ingin menjadi default permanen, ubah generator bundle lalu rebuild artifact sebelum import.

## 3. Impor melalui API - opsional untuk deployment terkontrol

API berada pada endpoint **Wazuh Dashboard**, bukan Wazuh Indexer port `9200`. Gunakan CA server Dashboard yang benar dan jangan memakai `-k`/`--insecure`.

```bash
set -euo pipefail
cd ~/wazuhuhuhu/siem-alarm-

export WAZUH_DASHBOARD_URL='https://127.0.0.1'
export WAZUH_DASHBOARD_CA='/path/to/dashboard-ca.pem'

WAZUH_DASHBOARD_MT="$(sudo awk -F: \
  '/^[[:space:]]*opensearch_security\.multitenancy\.enabled:/ {
    gsub(/[[:space:]]/, "", $2); print tolower($2); exit
  }' /etc/wazuh-dashboard/opensearch_dashboards.yml)"

case "${WAZUH_DASHBOARD_MT}" in
  true)
    export WAZUH_SOC_TENANT='SOC'
    WAZUH_TENANT_ARGS=(-H "securitytenant: ${WAZUH_SOC_TENANT}")
    ;;
  false)
    WAZUH_TENANT_ARGS=()
    ;;
  *)
    echo 'ERROR: mode multitenancy tidak ditemukan/valid' >&2
    exit 1
    ;;
esac

curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 120 \
  --cacert "${WAZUH_DASHBOARD_CA}" \
  --user soc_dashboard_deployer \
  -H 'osd-xsrf: true' \
  "${WAZUH_TENANT_ARGS[@]}" \
  -X POST \
  -F 'file=@dashboards/siem_alarm_soc_dashboard.ndjson;type=application/ndjson' \
  --output /tmp/siem-alarm-soc-import-response.json \
  --write-out 'dashboard_import_http=%{http_code}\n' \
  "${WAZUH_DASHBOARD_URL}/api/saved_objects/_import?overwrite=false"

python3 -m json.tool /tmp/siem-alarm-soc-import-response.json
python3 -c 'import json,sys; d=json.load(open("/tmp/siem-alarm-soc-import-response.json")); print("success=%s successCount=%s errors=%s" % (d.get("success"), d.get("successCount"), len(d.get("errors", [])))); sys.exit(0 if d.get("success") and d.get("successCount")==27 and not d.get("errors") else 1)'
```

Password diminta interaktif oleh `curl`; jangan menaruh password pada command line, shell history, file Git, atau URL. Header `securitytenant` hanya dikirim saat multitenancy `true` dan wajib berisi nama tenant exact. Respons import tidak boleh dianggap atomic: bila ada partial success, simpan response tersebut karena `destinationId` diperlukan untuk rollback exact object.

## 4. Backup sebelum overwrite/upgrade

Backup dilakukan pada tenant/default store yang sama dengan exact object list dari bundle. Jalankan pada shell yang masih mempunyai `WAZUH_TENANT_ARGS` dari bagian import:

```bash
set -euo pipefail
cd ~/wazuhuhuhu/siem-alarm-

umask 077
WAZUH_SOC_BACKUP="/tmp/siem-alarm-soc-before-upgrade-$(date -u +%Y%m%dT%H%M%SZ).ndjson"

curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 120 \
  --cacert "${WAZUH_DASHBOARD_CA}" \
  --user soc_dashboard_deployer \
  -H 'osd-xsrf: true' \
  -H 'Content-Type: application/json' \
  "${WAZUH_TENANT_ARGS[@]}" \
  -X POST \
  --data-binary @dashboards/siem_alarm_soc_dashboard.export-request.json \
  --output "${WAZUH_SOC_BACKUP}" \
  "${WAZUH_DASHBOARD_URL}/api/saved_objects/_export"

chmod 0600 "${WAZUH_SOC_BACKUP}"
python3 dashboards/validate_saved_objects_export.py "${WAZUH_SOC_BACKUP}"
```

Validator mewajibkan `exportedCount=27`, `missingRefCount=0`, tidak ada missing reference, dan set `(type,id)` yang identik dengan manifest; checksum saja tidak membuktikan backup lengkap. Hanya setelah validator lulus, upgrade dapat mengimpor bundle baru dengan `overwrite=true`. Ini akan menimpa modifikasi analyst pada ID proyek, sehingga change approval dan backup tidak boleh dilewati.

## 5. Validasi setelah impor

Lakukan pemeriksaan berikut pada tenant/default store tujuan:

1. Kedua dashboard dapat dibuka tanpa pesan **missing reference**.
2. Data view bundle menunjukkan title `siem-alarm-*` dan time field `timestamp`.
3. Time picker **Last 24 hours** menampilkan data; perluas rentang bila bucket uji lebih lama.
4. Refresh interval terset **5 minutes**.
5. Panel state dan escalation tidak mempunyai angka identik akibat query campuran.
6. Priority Queue hanya berisi High/Critical `alarm_state`.
7. Panel **Latest escalated alarm events** hanya berisi `alarm_escalation`, diurutkan terbaru ke terlama, dan default menampilkan `event.created`, `rule.description`, `risk.level`, serta `agent.name`.
8. Escalation Feed hanya berisi `alarm_escalation` dan menampilkan `escalation.level`, `escalation.reason`, serta `event.created`.
8. Login menggunakan account viewer SOC dan pastikan dashboard read-only tetapi seluruh panel dapat membaca data.
9. Jika multitenancy `true`, pastikan tenant lain tidak berubah. Pada kedua mode, pastikan dashboard default Wazuh tidak berubah.

Untuk tampilan bucket yang sama dengan identitas agregasi, set advanced setting `dateFormat:tz` menjadi `UTC`. Jika SOC memakai timezone browser/lokal, dokumentasikan bahwa waktu yang tampil adalah konversi dari bucket UTC.

Cross-check count 24 jam langsung ke Indexer, menggunakan account yang mempunyai read pada `siem-alarm-*`:

```bash
curl --fail --silent --show-error \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  -H 'Content-Type: application/json' \
  -X POST 'https://127.0.0.1:9200/siem-alarm-*/_search?pretty' \
  -d '{
    "size": 0,
    "query": {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}},
    "aggs": {
      "by_document_type": {"terms": {"field": "document.type"}},
      "finalized_raw_alerts": {
        "filter": {"bool": {"filter": [
          {"term": {"document.type": "alarm_state"}},
          {"term": {"alarm.status": "finalized"}}
        ]}},
        "aggs": {"represented": {"sum": {"field": "source.raw_alert_count"}}}
      }
    }
  }'
```

Perbedaan kecil dapat terjadi saat current bucket sedang diperbarui dan Dashboard refresh belum berjalan. Nilai finalized seharusnya stabil untuk rentang waktu yang sama.

## 6. Rollback aman

- Untuk instalasi pertama yang gagal sebagian, gunakan response import dan manifest untuk menghapus **hanya exact ID proyek** melalui Saved Objects UI pada tenant/default store yang sama.
- Untuk upgrade yang overwrite, impor kembali file backup exact-ID ke tenant/default store yang sama dan pilih overwrite hanya untuk object proyek.
- Bila `createNewCopies` pernah dipakai, hapus hanya `destinationId` yang tercatat pada response import.
- Jangan memakai wildcard delete, jangan menghapus `.kibana*`, dan jangan mengedit saved-object index langsung.
- Snapshot `.kibana*` adalah kontrol disaster recovery sekunder, bukan rollback rutin, karena restore dapat menimpa object tenant lain.

## 7. Rebuild setelah perubahan mapping/dashboard

```bash
cd ~/wazuhuhuhu/siem-alarm-
python3 dashboards/build_soc_dashboard.py
python3 dashboards/build_soc_dashboard.py --check
git diff -- dashboards/
```

Review perubahan ID, query, references, object count, dan checksum sebelum commit. Builder menolak aggregation field yang tidak ada di template, aggregation pada field `text`, visualisasi tanpa filter `document.type`, missing reference, serta penjumlahan raw volume pada dokumen escalation.

Referensi format dan operasi:

- [Wazuh Dashboard v4.14.7 Saved Objects API](https://github.com/wazuh/wazuh-dashboard/blob/v4.14.7/src/plugins/saved_objects/README.md)
- [Wazuh Dashboard v4.14.7 production configuration](https://github.com/wazuh/wazuh-dashboard/blob/v4.14.7/config/opensearch_dashboards.prod.yml)
- [OpenSearch Dashboard Saved Objects import](https://docs.opensearch.org/latest/dashboards/integrations/index/)
- [OpenSearch DQL](https://docs.opensearch.org/latest/dashboards/dql/)
- [OpenSearch aggregation-based visualizations](https://docs.opensearch.org/latest/dashboards/visualize/visualize-app/configuring-viz/)
- [OpenSearch multi-tenancy](https://docs.opensearch.org/latest/security/multi-tenancy/multi-tenancy-config/)
