# SIEM Alarm Scoring untuk Wazuh 4.14.7

Proyek ini mengubah banyak raw alert Wazuh menjadi alarm SOC per `agent.id + rule.id + bucket 1 jam`. Raw evidence `wazuh-alerts-*` hanya dibaca; state alarm dan event eskalasi ditulis ke `siem-alarm-*`.

Baseline yang didokumentasikan dan diuji adalah Ubuntu 20.04 single-node/all-in-one dengan `wazuh-manager`, `wazuh-indexer`, dan `wazuh-dashboard` **4.14.7**, Filebeat OSS **7.10.2**, serta Python **3.8 atau lebih baru**. Installer memaksa versi komponen Wazuh/Filebeat, Python minimum, unit AIO, dan TLS—tetapi tidak memaksa nilai `/etc/os-release`; lifecycle/security support OS tetap wajib diverifikasi operator. Baseline Python 3.8 dipertahankan agar Ubuntu 20.04 dapat memakai interpreter sistem tanpa mengganti symlink `/usr/bin/python3` atau menambah PPA. Deployment distributed, versi patch lain, container, atau Wazuh Cloud memerlukan review tersendiri.

## Status audit

Implementasi menyediakan hardening baseline untuk staging menuju production, tetapi bukan approval production otomatis. Aktivasi tetap harus melewati staging/shadow/load test pada server yang spesifik. Installer:

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
| `docs/logic_agregat_siem_alarm.pdf` | Dokumen 50 halaman: topologi, flowchart, perhitungan, dummy raw Wazuh, state, dan escalation | Referensi arsitektur/SOC |
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

## 0. Clone repository dari GitHub

Tahap ini dijalankan sebagai user administrator biasa, bukan sebagai `root`. Bila `git` belum tersedia:

```bash
sudo apt-get update
sudo apt-get install --yes git ca-certificates curl openssl
git --version
python3 --version
```

Clone branch `main`, masuk ke direktori proyek, lalu pastikan remote tidak menyimpan Personal Access Token (PAT) di URL:

```bash
if [ -e /home/administrator/wazuhuhuhu ]; then
  echo 'ERROR: /home/administrator/wazuhuhuhu sudah ada; gunakan prosedur existing clone.' >&2
else
  git clone --branch main --single-branch \
    https://github.com/AkbarWiraN/wazuhuhuhu.git \
    /home/administrator/wazuhuhuhu \
  && cd /home/administrator/wazuhuhuhu/siem-alarm- \
  && git remote set-url origin \
    https://github.com/AkbarWiraN/wazuhuhuhu.git \
  && git status --short \
  && git log -1 --oneline \
  && git rev-parse HEAD
fi
```

`git status --short` harus kosong. Jangan menulis PAT/password di URL clone, README, command line, atau file repository. Untuk repository private, autentikasikan Git menggunakan SSH key atau credential helper; URL repository tetap tidak boleh berisi token. PAT yang pernah tertanam di URL harus segera dicabut/dirotasi di GitHub.

Jika repository sudah pernah di-clone, jangan menjalankan `git clone` lagi. Perbarui secara fail-safe:

```bash
siem_update_existing_clone() {
  local siem_git_status siem_repo_root
  cd /home/administrator/wazuhuhuhu || return
  siem_repo_root="$(git rev-parse --show-toplevel)" || return
  if [ "${siem_repo_root}" != '/home/administrator/wazuhuhuhu' ]; then
    echo 'ERROR: path bukan root repository yang diharapkan.' >&2
    return 1
  fi
  git remote set-url origin \
    https://github.com/AkbarWiraN/wazuhuhuhu.git || return
  siem_git_status="$(git status --porcelain=v1 --untracked-files=all)" || return
  if [ -n "${siem_git_status}" ]; then
    echo 'ERROR: working tree tidak bersih; review output berikut dan hentikan update.' >&2
    printf '%s\n' "${siem_git_status}" >&2
    return 1
  fi
  git switch main || return
  git pull --ff-only origin main || return
  cd /home/administrator/wazuhuhuhu/siem-alarm- || return
  git log -1 --oneline || return
  git rev-parse HEAD
}

if siem_update_existing_clone; then
  echo 'OK: existing clone berhasil diperbarui secara fast-forward.'
else
  echo 'ERROR: update clone dihentikan; jangan lanjut ke installer.' >&2
fi
unset -f siem_update_existing_clone
```

Hentikan bila `git status --short` menampilkan perubahan yang belum direview. Jangan memakai `git reset --hard` untuk mengatasi working tree yang kotor.

Branch `main` boleh dipakai untuk lab. Sebelum production, freeze ke commit/tag immutable yang sudah direview; jangan menjalankan installer sebagai root hanya berdasarkan “latest main”. Catat `git rev-parse HEAD`, review diff/release, lalu gunakan SHA 40 karakter yang disetujui change control:

```bash
SIEM_APPROVED_COMMIT='ISI_SHA_40_KARAKTER_YANG_SUDAH_DIREVIEW'
if [[ ! "${SIEM_APPROVED_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'ERROR: isi SIEM_APPROVED_COMMIT dengan SHA 40 karakter yang sudah direview.' >&2
  false
elif git fetch --tags --prune origin \
  && git checkout --detach "${SIEM_APPROVED_COMMIT}" \
  && test "$(git rev-parse HEAD)" = "${SIEM_APPROVED_COMMIT}"; then
  echo 'OK: source pinned ke commit yang disetujui'
else
  echo 'ERROR: commit tidak tersedia atau tidak cocok' >&2
  false
fi
```

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
cat /etc/os-release
python3 --version
dpkg-query -W -f='${Package} ${Version}\n' \
  wazuh-manager wazuh-indexer wazuh-dashboard filebeat
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
sudo filebeat test output
sudo /var/ossec/bin/wazuh-control status
sudo /var/ossec/bin/agent_control -l
sudo ss -lntp | grep -E ':(9200|55000)'

if command -v pro >/dev/null 2>&1; then
  sudo pro status --all
  sudo pro security-status
else
  echo 'ERROR: Ubuntu Pro/ESM status tidak dapat diverifikasi.' >&2
fi
```

Output harus menunjukkan ketiga komponen sentral pada `4.14.7`, Filebeat `7.10.2`, seluruh service `active`, dan koneksi output Filebeat sukses. Installer mengulang pemeriksaan package/unit/Filebeat/TLS dan berhenti sebelum mutasi bila gagal; pemeriksaan internal daemon, agent database, serta port `55000` di atas tetap menjadi verifikasi operator tambahan.

Pada output `wazuh-control status`, daemon opsional seperti `wazuh-clusterd`, `wazuh-maild`, `wazuh-agentlessd`, atau `wazuh-integratord` boleh tidak berjalan pada AIO bila memang tidak digunakan. Yang penting tidak ada error `queue/db/wdb`, agent lokal `000` terbaca, proses inti termasuk `wazuh-db`, `wazuh-analysisd`, dan `wazuh-apid` berjalan, serta port API `55000` listen. Scorer sendiri mengakses Indexer pada `9200`, bukan Wazuh Server API `55000`; pemeriksaan API diperlukan agar Dashboard AIO juga sehat.

[Ubuntu 20.04 telah beralih dari standard security maintenance ke ESM](https://ubuntu.com/security/esm). Pada host production tahun 2026, `esm-infra`/cakupan ESM yang diperlukan harus berstatus aktif melalui Ubuntu Pro, atau OS harus di-upgrade ke release yang masih menerima standard security maintenance. Lab terisolasi boleh dipakai untuk functional test, tetapi jangan dianggap production-ready tanpa patch security aktif.

Temukan nama certificate yang benar dari konfigurasi Indexer, lalu periksa SAN-nya. Pada VM AIO yang sudah diuji, file node certificate bernama `wazuh-indexer.pem`, bukan `indexer.pem`:

```bash
sudo find /etc/wazuh-indexer/certs \
  -maxdepth 1 -type f \
  -printf '%f  owner=%u:%g  mode=%m\n'
sudo grep -nE \
  'plugins.security.ssl.http.(pemcert_filepath|pemkey_filepath|pemtrustedcas_filepath)' \
  /etc/wazuh-indexer/opensearch.yml

export WAZUH_CA_SOURCE='/etc/wazuh-indexer/certs/root-ca.pem'
export WAZUH_INDEXER_CERT_SOURCE='/etc/wazuh-indexer/certs/wazuh-indexer.pem'

sudo openssl x509 \
  -in "${WAZUH_INDEXER_CERT_SOURCE}" \
  -noout -subject -issuer -dates -ext subjectAltName
sudo openssl verify \
  -purpose sslserver \
  -CAfile "${WAZUH_CA_SOURCE}" \
  "${WAZUH_INDEXER_CERT_SOURCE}"
```

Jika `opensearch.yml` menunjukkan nama/path berbeda, ubah kedua variable di atas agar sama persis. `openssl verify` harus menghasilkan `OK`.

`WAZUH_INDEXER_CERT_SOURCE` harus menunjuk certificate publik HTTP/node dan `WAZUH_CA_SOURCE` harus menunjuk trusted CA. Jangan pernah memberi installer file `*-key.pem`, `admin-key.pem`, atau private key lain. Jangan membuka port `9200`/`55000` ke jaringan yang lebih luas hanya untuk membuat test lokal berhasil.

Untuk AIO, README memakai URL default berikut. Jalankan sekali pada setiap shell operator:

```bash
export SIEM_INDEXER_URL='https://127.0.0.1:9200'
```

Jika `127.0.0.1` tidak tercantum pada SAN, ganti dengan hostname/IP yang tercantum. URL yang sama harus dipakai di `config.siem_alarm.json`.

## 3. Instal file

Masuk ke folder proyek yang berisi installer. Untuk layout certificate VM yang sudah diuji, gunakan command berikut:

```bash
cd /home/administrator/wazuhuhuhu/siem-alarm-
: "${WAZUH_CA_SOURCE:=/etc/wazuh-indexer/certs/root-ca.pem}"
: "${WAZUH_INDEXER_CERT_SOURCE:=/etc/wazuh-indexer/certs/wazuh-indexer.pem}"
sudo env \
  WAZUH_CA_SOURCE="${WAZUH_CA_SOURCE}" \
  WAZUH_INDEXER_CERT_SOURCE="${WAZUH_INDEXER_CERT_SOURCE}" \
  bash ./setup_siem_alarm_final.sh
```

Jika path CA/node certificate berbeda, blok berikut sengaja memerlukan penyesuaian:

```bash
sudo env \
  WAZUH_CA_SOURCE=/path/aktual/root-ca.pem \
  WAZUH_INDEXER_CERT_SOURCE=/path/aktual/wazuh-indexer.pem \
  bash ./setup_siem_alarm_final.sh
```

Installer harus selesai tanpa error, membuat user Linux `siem-alarm`, menyalin file runtime, dan memasang unit systemd tanpa mengaktifkan timer. Verifikasi hasil instalasi:

```bash
sudo stat -c '%U:%G %a %n' \
  /opt/wazuh-risk-scoring \
  /opt/wazuh-risk-scoring/root-ca.pem \
  /opt/wazuh-risk-scoring/config.siem_alarm.json \
  /opt/wazuh-risk-scoring/assets.json \
  /etc/wazuh-risk-scoring/siem-alarm.env \
  /var/lib/wazuh-risk-scoring
sudo -u siem-alarm test -r \
  /opt/wazuh-risk-scoring/root-ca.pem \
  && echo 'OK: CA terbaca runtime' \
  || echo 'ERROR: CA tidak terbaca runtime'
sudo systemd-analyze verify \
  /etc/systemd/system/siem-alarm-scoring.service \
  /etc/systemd/system/siem-alarm-scoring-failure@.service \
  /etc/systemd/system/siem-alarm-scoring.timer
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

Gunakan password acak yang baru dan simpan di password manager. Command ini hanya membuat kandidat password; jangan menempelkan hasilnya ke chat atau repository:

```bash
openssl rand -hex 24
```

Masuk ke Wazuh Dashboard sebagai administrator, lalu buka **Indexer Management → Security**:

1. Buka **Internal users → Create internal user**.
2. Isi username `siem_alarm_service`, gunakan password unik tadi, lalu simpan. Backend roles boleh kosong.
3. Buka **Roles → Create role** dan beri nama `siem_alarm_runtime`.
4. Pada **Cluster permissions**, tambahkan `cluster_composite_ops_ro`, `indices:data/read/scroll/clear`, dan `indices:data/write/bulk*`.
5. Pada **Index permissions**, tambahkan index pattern `wazuh-alerts-*` dengan allowed action `read`.
6. Tambahkan index pattern kedua `siem-alarm-*` dengan allowed actions `read`, `index`, dan `create_index`.
7. Biarkan **Tenant permissions** kosong, lalu simpan role.
8. Buka kembali role `siem_alarm_runtime`, pilih tab **Mapped users**, lalu **Manage mapping**.
9. Pada bagian **Users/Internal users**, tambahkan tepat `siem_alarm_service`, lalu tekan **Map/Save**. Backend roles dan Hosts tetap kosong. Ini yang dimaksud dengan “Mapped users”; jangan memasukkannya ke Backend roles.

Mapping ini berada di **Indexer Management → Security → Roles**, bukan **Server management → Security → Roles mapping**. Jangan memberi `cluster_composite_ops`, `indices_all`, Security API, template, ISM, atau akses index Wazuh lain kepada runtime user.

Ini adalah least-privilege baseline yang sudah diuji memakai action group bawaan. Action group destination `index` tetap mencakup beberapa action update/mapping di luar write engine sehari-hari; pemecahan menjadi daftar individual yang lebih sempit hanya boleh dilakukan setelah representative live test membuktikan `_mget`, two-phase `_bulk`, bootstrap, rollover, dan retry tetap lulus.

Uji TLS, autentikasi, mapping role, hak baca exact daily source index, dan negative permission. Setiap command meminta password `siem_alarm_service` secara interaktif:

```bash
: "${SIEM_INDEXER_URL:=https://127.0.0.1:9200}"
SIEM_ALERT_INDEX_DATE="$(date -u +%Y.%m.%d)"

sudo curl --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  --output /dev/null \
  --write-out 'raw_count_http=%{http_code}\n' \
  "${SIEM_INDEXER_URL}/wazuh-alerts-4.x-${SIEM_ALERT_INDEX_DATE}/_count"

sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  --write-out '\nauthinfo_http=%{http_code}\n' \
  "${SIEM_INDEXER_URL}/_plugins/_security/authinfo?pretty"

sudo curl --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  --output /dev/null \
  --write-out 'cluster_root_http=%{http_code}\n' \
  "${SIEM_INDEXER_URL}"

sudo curl --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  --output /dev/null \
  --write-out 'security_api_http=%{http_code}\n' \
  "${SIEM_INDEXER_URL}/_plugins/_security/api/roles"
```

Hasil yang benar adalah `raw_count_http=200`, `authinfo_http=200`, dan daftar `roles` pada authinfo memuat `siem_alarm_runtime`. Investigasi bila authinfo justru memuat `all_access` atau `security_rest_api_access`. Pada role least-privilege ini `cluster_root_http=403` dan `security_api_http=403` memang diharapkan; keduanya membuktikan runtime user tidak mempunyai hak administrasi yang tidak diperlukan. Jika raw count `403`, perbaiki role atau mapping. Jika `000`, periksa CA/URL/jaringan. Jika `404`, index raw untuk tanggal UTC hari ini mungkin belum ada; buktikan nama/tanggal index aktual sebagai admin sebelum menambah permission.

Endpoint akar `GET /` menjadi `403` karena runtime sengaja tidak mempunyai `cluster:monitor/main`; jangan menambahkan permission hanya agar root menjadi `200`. Permission individual `indices:data/read/scroll/clear` diperlukan pada scope cluster untuk menutup scroll context, sedangkan action group `read` pada source memenuhi operasi read pada scope index.

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
sudo -u siem-alarm test -r \
  /etc/wazuh-risk-scoring/siem-alarm.env \
  && echo 'OK: environment file terbaca runtime' \
  || echo 'ERROR: environment file tidak terbaca runtime'
if sudo grep -qE 'GANTI_|CHANGE_' \
  /etc/wazuh-risk-scoring/siem-alarm.env; then
  echo 'ERROR: placeholder secret masih ada'
else
  SIEM_GREP_STATUS=$?
  if [ "${SIEM_GREP_STATUS}" -eq 1 ]; then
    echo 'OK: placeholder secret sudah diganti'
  else
    echo 'ERROR: environment file gagal diperiksa' >&2
  fi
  unset SIEM_GREP_STATUS
fi
```

Output command `stat` harus menunjukkan `root:siem-alarm 640`. Engine menolak inline password dan username `admin`.

Audit seluruh permission tanpa mencetak secret:

```bash
sudo stat -c '%U:%G %a %n' \
  /opt/wazuh-risk-scoring \
  /opt/wazuh-risk-scoring/logs \
  /etc/wazuh-risk-scoring \
  /var/lib/wazuh-risk-scoring \
  /opt/wazuh-risk-scoring/config.siem_alarm.json \
  /opt/wazuh-risk-scoring/assets.json \
  /opt/wazuh-risk-scoring/root-ca.pem \
  /etc/wazuh-risk-scoring/siem-alarm.env
sudo -u siem-alarm test ! -w \
  /opt/wazuh-risk-scoring/config.siem_alarm.json \
  && sudo -u siem-alarm test ! -w \
  /etc/wazuh-risk-scoring/siem-alarm.env \
  && echo 'OK: runtime tidak dapat mengubah config/env'
```

Expected directory: application dan config `root:siem-alarm 750`, logs/state `siem-alarm:siem-alarm 750`. Expected config/assets/CA/env: `root:siem-alarm 640`. Checkpoint baru muncul setelah run sukses dan harus `siem-alarm:siem-alarm 600`. Backup installer dapat berisi environment secret lama; directory backup wajib tetap `root:root 700` dan harus mengikuti retensi administrasi yang aman. Jangan menjalankan `cat` atau `source` terhadap environment file pada transcript.

Jika password runtime pernah terlihat di chat, screenshot, issue, atau transcript, rotasi sebelum production: hentikan timer/service, ubah password internal user di Dashboard, ubah hanya nilai `WAZUH_PASS` lewat `sudoedit`, kembalikan permission `0640`, jalankan run manual, lalu aktifkan timer kembali hanya jika lulus.

```bash
sudo systemctl stop siem-alarm-scoring.timer
sudo systemctl stop siem-alarm-scoring.service
# Ubah password Internal user siem_alarm_service di Dashboard terlebih dahulu.
sudoedit /etc/wazuh-risk-scoring/siem-alarm.env
sudo chown root:siem-alarm /etc/wazuh-risk-scoring/siem-alarm.env
sudo chmod 0640 /etc/wazuh-risk-scoring/siem-alarm.env
sudo systemctl reset-failed siem-alarm-scoring.service
```

Setelah rotasi, lanjutkan validasi config/assets/template/ISM. Gunakan run manual tahap 10 untuk membuktikan password baru, lalu aktifkan timer sesuai tahap 13; jangan start service sebelum prasyarat initial install selesai.

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
sudo grep -nE \
  '"(opensearch_url|username|password_env|verify_ssl|ca_cert|source_index|destination_index_prefix|install_template)"' \
  /opt/wazuh-risk-scoring/config.siem_alarm.json
sudo openssl x509 \
  -in /opt/wazuh-risk-scoring/root-ca.pem \
  -noout -subject -issuer -dates
```

`source_index` harus exact daily pattern dengan satu `{date}`. Jika Wazuh memakai custom index prefix/date routing, hentikan proses dan buktikan pola aktual terlebih dahulu.

Syaratnya: URL berupa string biasa seperti `https://127.0.0.1:9200` (bukan Markdown link), username `siem_alarm_service`, `password_env=WAZUH_PASS`, TLS verification `true`, source harian tepat, destination prefix `siem-alarm`, dan `install_template=false`.

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

Validator menolak file hilang, top-level non-object, lookup key kosong/ber-spasi di tepi, field typo, nilai nonnumerik/boolean/di luar `1..5`, alias ganda, kategori tidak cocok, dan metadata kosong. Leading zero pada ID Wazuh seperti `000` atau `001` justru benar dan harus dipertahankan.

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

Tahap ini memakai admin Indexer dan merupakan perubahan cluster satu kali. Setujui dahulu apakah retensi 90 hari sesuai kebijakan organisasi. Validasi file lokal, lalu lakukan `GET` sebelum `PUT`:

```bash
export SIEM_INDEXER_URL="${SIEM_INDEXER_URL:-https://127.0.0.1:9200}"
sudo /usr/bin/python3 -m json.tool \
  /opt/wazuh-risk-scoring/siem_alarm_template_final.json >/dev/null
sudo /usr/bin/python3 -m json.tool \
  /opt/wazuh-risk-scoring/siem_alarm_ism_policy.json >/dev/null

sudo curl --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  --write-out '\ntemplate_get_http=%{http_code}\n' \
  "${SIEM_INDEXER_URL}/_index_template/siem-alarm-template?pretty"

sudo curl --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  --write-out '\nism_get_http=%{http_code}\n' \
  "${SIEM_INDEXER_URL}/_plugins/_ism/policies/siem-alarm-retention-90d?pretty"
```

Nilai setiap hasil secara independen: jalankan hanya command create untuk object yang `GET`-nya menghasilkan `404`. Bila salah satu sudah `200`, review object tersebut dan lewati command create-nya. Parameter `create=true` mencegah template existing tertimpa tanpa sengaja:

```bash
: "${SIEM_INDEXER_URL:?export SIEM_INDEXER_URL terlebih dahulu}"
# Jalankan HANYA jika template_get_http=404.
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  -H 'Content-Type: application/json' \
  -X PUT "${SIEM_INDEXER_URL}/_index_template/siem-alarm-template?create=true" \
  --data-binary @/opt/wazuh-risk-scoring/siem_alarm_template_final.json \
  --output /dev/null \
  --write-out 'template_put_http=%{http_code}\n'

# Jalankan HANYA jika ism_get_http=404.
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  -H 'Content-Type: application/json' \
  -X PUT "${SIEM_INDEXER_URL}/_plugins/_ism/policies/siem-alarm-retention-90d" \
  --data-binary @/opt/wazuh-risk-scoring/siem_alarm_ism_policy.json \
  --output /dev/null \
  --write-out 'ism_put_http=%{http_code}\n'
```

Create pertama yang benar menghasilkan `template_put_http=200` dan `ism_put_http=201`. Jika preflight `GET` menghasilkan `200`, **jangan** jalankan blok create: review/diff response yang ditampilkan terhadap file proyek; update template harus menjadi change terpisah, sedangkan update policy ISM existing wajib memakai `if_seq_no` dan `if_primary_term` dari hasil `GET`. Jangan menghapus policy aktif hanya agar create berhasil.

Verifikasi kedua object setelah create/update yang disetujui:

```bash
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  --output /dev/null \
  --write-out 'template_verify_http=%{http_code}\n' \
  "${SIEM_INDEXER_URL}/_index_template/siem-alarm-template"

sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  --output /dev/null \
  --write-out 'ism_verify_http=%{http_code}\n' \
  "${SIEM_INDEXER_URL}/_plugins/_ism/policies/siem-alarm-retention-90d"
```

Keduanya harus `200`. Template harus terpasang sebelum bulk pertama. Runtime config harus tetap `"install_template": false`.

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

Pastikan laporan valid dan tetap terlindungi:

```bash
sudo stat -c '%U:%G %a %s %n' \
  /opt/wazuh-risk-scoring/logs/wazuh_field_audit_report.json
sudo -u siem-alarm /usr/bin/python3 -m json.tool \
  /opt/wazuh-risk-scoring/logs/wazuh_field_audit_report.json \
  >/dev/null \
  && echo 'OK: field audit report valid'
```

## 10. Run manual sebelum go-live

Blok ini siap tempel setelah role, secret, config, inventory, template, dan ISM selesai:

```bash
sudo /usr/bin/python3 -c '
import json
p = "/opt/wazuh-risk-scoring/config.siem_alarm.json"
c = json.load(open(p, encoding="utf-8"))
assert "password" not in c
assert c.get("username") == "siem_alarm_service"
assert c.get("password_env") == "WAZUH_PASS"
assert c.get("verify_ssl") is True
assert c.get("install_template") is False
print("OK: runtime credential/config policy")
'
sudo systemd-analyze verify \
  /etc/systemd/system/siem-alarm-scoring.service \
  /etc/systemd/system/siem-alarm-scoring-failure@.service \
  /etc/systemd/system/siem-alarm-scoring.timer
sudo systemctl daemon-reload
sudo systemctl reset-failed siem-alarm-scoring.service
sudo systemctl start siem-alarm-scoring.service
sudo systemctl show siem-alarm-scoring.service \
  -p Result -p ExecMainStatus -p ExecMainCode \
  -p ActiveState -p SubState
sudo journalctl -u siem-alarm-scoring.service -n 100 --no-pager
sudo tail -n 100 \
  /opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
```

Syarat lulus: `Result=success`, `ExecMainStatus=0`, tidak ada `429`, timeout, failed shard, asset mismatch/default yang tidak direncanakan, cap exceeded, atau checkpoint error. Karena service bertipe `oneshot`, `ActiveState=inactive` dan `SubState=dead` setelah run sukses adalah normal; itu bukan tanda service berhenti bekerja.

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

Hitung state dan escalation secara terpisah serta lihat lima alarm terbesar:

```bash
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  -H 'Content-Type: application/json' \
  -X POST "${SIEM_INDEXER_URL}/siem-alarm-*/_count?pretty" \
  -d '{"query":{"term":{"document.type":"alarm_state"}}}'

sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  -H 'Content-Type: application/json' \
  -X POST "${SIEM_INDEXER_URL}/siem-alarm-*/_count?pretty" \
  -d '{"query":{"term":{"document.type":"alarm_escalation"}}}'

sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  -H 'Content-Type: application/json' \
  -X POST "${SIEM_INDEXER_URL}/siem-alarm-*/_search?pretty" \
  -d '{
    "size": 5,
    "query": {"term": {"document.type": "alarm_state"}},
    "sort": [{"source.raw_alert_count": {"order": "desc"}}],
    "_source": [
      "timestamp", "alarm.id", "alarm.status", "alarm.bucket_start",
      "alarm.event_count",
      "agent.id", "agent.name", "rule.id", "rule.description",
      "source.index", "source.raw_alert_count",
      "risk.frequency_count_1h", "risk.score", "risk.level",
      "source_observed.srcip_unique_count", "source_observed.srcip_samples"
    ]
  }'
```

Untuk setiap `alarm_state`, invariant berikut harus benar:

```text
source.raw_alert_count = alarm.event_count = risk.frequency_count_1h
```

Setiap agent yang diinventaris harus menunjukkan `asset.source=assets_json` dan nilai yang direncanakan. `agent_label` hanya valid jika fallback label dipilih. `default` harus diinvestigasi sebelum go-live.

`alarm.status=open` berarti bucket masih berjalan; `finalized` berarti snapshot bucket tertutup selesai. Field ini bukan acknowledge/resolve workflow analyst.

Jika belum ada alert pada window, run dapat sukses tanpa membuat destination index. Tunggu atau hasilkan alert uji yang aman dan ulangi; jangan aktifkan timer tanpa memverifikasi minimal satu dokumen aktual.

Pada run non-kosong pertama dan pergantian tanggal UTC, daily destination mungkin belum ada. Wazuh Indexer/OpenSearch 2.19 dapat menjawab `_mget` dengan HTTP 200 tetapi memberi `error.type=index_not_found_exception` pada setiap elemen tanpa field `status`. Engine menerima kondisi ini hanya bila **semua** item batch menunjuk concrete destination index yang sama persis, menganggap seluruh state masih baru, lalu membiarkan two-phase bulk pertama membuat index melalui template yang sudah terpasang. Respons campuran, index yang tidak cocok, status yang bertentangan, atau tipe error lain tetap fail-closed. Flip ada/hilang pada retry batch yang sama juga ditolak; penghapusan eksternal di antara batch tetap operasi yang tidak didukung dan tidak dapat dibuat atomik oleh API ini.

Pesan INFO `Destination index ... does not exist yet` normal sekali pada bootstrap/day rollover. Jika muncul untuk daily index yang sebelumnya sudah berisi data, curigai penghapusan di luar prosedur: hentikan timer dan lakukan audit/controlled backfill. Jangan sekadar restart dengan checkpoint lama karena index dapat dibuat kembali tetapi history bucket yang telah lewat tetap hilang.

## 11. Verifikasi concrete index, mapping, ISM, dan checkpoint

Timer harus tetap nonaktif selama tahap ini:

```bash
if sudo systemctl is-enabled --quiet siem-alarm-scoring.timer; then
  echo 'ERROR: nonaktifkan timer sampai seluruh validasi selesai.' >&2
else
  echo 'OK: timer masih nonaktif.'
fi
```

Setelah minimal satu run manual non-kosong, periksa checkpoint. File harus dimiliki `siem-alarm:siem-alarm`, mode `600`, dan valid JSON:

```bash
sudo stat -c '%U:%G %a %s %n' \
  /var/lib/wazuh-risk-scoring/checkpoint.json
sudo /usr/bin/python3 -m json.tool \
  /var/lib/wazuh-risk-scoring/checkpoint.json >/dev/null \
  && echo 'OK: checkpoint valid'
```

Periksa concrete daily index yang baru dibuat. Blok ini memakai admin Indexer dan mengasumsikan current UTC bucket mempunyai raw alert:

```bash
: "${SIEM_INDEXER_URL:=https://127.0.0.1:9200}"
SIEM_DEST_DATE="$(date -u +%Y.%m.%d)"
SIEM_DEST_INDEX="siem-alarm-${SIEM_DEST_DATE}"

sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  "${SIEM_INDEXER_URL}/${SIEM_DEST_INDEX}/_mapping?pretty"

sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  "${SIEM_INDEXER_URL}/${SIEM_DEST_INDEX}/_settings?pretty&filter_path=*.settings.index.number_of_replicas,*.settings.index.refresh_interval"

sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user admin \
  "${SIEM_INDEXER_URL}/_plugins/_ism/explain/${SIEM_DEST_INDEX}?show_policy=true"
```

Mapping aktual wajib menunjukkan minimal `timestamp=date`, `document.type=keyword`, `alarm.id=keyword`, `alarm.event_count=integer`, `source_observed.srcip_samples=keyword`, `risk.score=float`, dan `risk.level=keyword`. Setting baseline AIO adalah `number_of_replicas=0` dan `refresh_interval=30s`. Replica nol sesuai single-node lab tetapi tidak memberi redundansi; production memerlukan keputusan availability/snapshot yang disetujui. ISM explain harus menunjukkan policy `siem-alarm-retention-90d` aktif. Jika current daily index belum ada karena run kosong, jangan membuatnya manual; tunggu raw alert uji yang aman dan ulangi service.

Untuk validasi progressive update, catat `alarm.id` dan `source.raw_alert_count` dari query di tahap 10. Pastikan ada raw alert baru dengan `agent.id + rule.id` yang sama pada bucket satu jam yang sama, jalankan service lagi, lalu ulangi query:

```bash
sudo systemctl reset-failed siem-alarm-scoring.service
sudo systemctl start siem-alarm-scoring.service
sudo systemctl show siem-alarm-scoring.service \
  -p Result -p ExecMainStatus -p ActiveState -p SubState
sudo journalctl -u siem-alarm-scoring.service -n 100 --no-pager
```

`alarm.id` harus tetap sama dan count bertambah sesuai raw alert aktual. Jika tidak ada matching raw alert baru, count yang tetap sama adalah hasil yang benar. Run ulang yang identik tidak boleh menggandakan `alarm_escalation`.

Ambil satu `alarm_state` finalized sebagai kandidat cross-check:

```bash
: "${SIEM_INDEXER_URL:?export SIEM_INDEXER_URL terlebih dahulu}"
sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  -H 'Content-Type: application/json' \
  -X POST "${SIEM_INDEXER_URL}/siem-alarm-*/_search?pretty" \
  -d '{
    "size": 1,
    "query": {"bool": {"filter": [
      {"term": {"document.type": "alarm_state"}},
      {"term": {"alarm.status": "finalized"}}
    ]}},
    "sort": [{"alarm.last_seen": {"order": "desc"}}],
    "_source": [
      "alarm.id", "alarm.bucket_start", "alarm.deduplication_mode",
      "alarm.dedup_key_fields", "agent.id", "rule.id", "source.index",
      "source.raw_alert_count", "alarm.event_count",
      "risk.frequency_count_1h"
    ]
  }'
```

Jika query belum menghasilkan hit, tunggu closed bucket pertama menjadi eligible—dengan baseline biasanya sekitar boundary +10 menit. Karena timer masih nonaktif, jalankan engine manual lagi, verifikasi sukses, tunggu refresh destination maksimal sekitar 30 detik, lalu ulangi query finalized di atas:

```bash
sudo systemctl reset-failed siem-alarm-scoring.service
sudo systemctl start siem-alarm-scoring.service
sudo systemctl show siem-alarm-scoring.service \
  -p Result -p ExecMainStatus -p ActiveState -p SubState
sudo journalctl -u siem-alarm-scoring.service -n 100 --no-pager
```

Setelah memperoleh state finalized, cross-check state tersebut langsung terhadap raw evidence. Catat `source.index`, `agent.id`, `rule.id`, `alarm.bucket_start`, dan `source.raw_alert_count`. Isi variable berikut dengan nilai aktual—contoh placeholder sengaja tidak boleh ditempel apa adanya:

```bash
: "${SIEM_INDEXER_URL:?export SIEM_INDEXER_URL terlebih dahulu}"
SIEM_RAW_INDEX='wazuh-alerts-4.x-YYYY.MM.DD'
SIEM_AGENT_ID='ID_AGENT_AKTUAL'
SIEM_RULE_ID='RULE_ID_AKTUAL'
SIEM_BUCKET_START='YYYY-MM-DDTHH:00:00Z'
SIEM_BUCKET_END="$(date -u -d "${SIEM_BUCKET_START} + 1 hour" '+%Y-%m-%dT%H:%M:%SZ')"

sudo curl --fail --silent --show-error \
  --connect-timeout 10 --max-time 60 \
  --cacert /opt/wazuh-risk-scoring/root-ca.pem \
  --user siem_alarm_service \
  -H 'Content-Type: application/json' \
  -X POST "${SIEM_INDEXER_URL}/${SIEM_RAW_INDEX}/_count?pretty&filter_path=count,_shards.failed" \
  -d "{
    \"query\": {
      \"bool\": {
        \"filter\": [
          {\"term\": {\"agent.id\": \"${SIEM_AGENT_ID}\"}},
          {\"term\": {\"rule.id\": \"${SIEM_RULE_ID}\"}},
          {\"range\": {\"timestamp\": {
            \"gte\": \"${SIEM_BUCKET_START}\",
            \"lt\": \"${SIEM_BUCKET_END}\"
          }}}
        ]
      }
    }
  }"
```

Respons wajib HTTP `200`, `_shards.failed=0`, dan nilai `count` raw harus sama dengan `source.raw_alert_count` pada state finalized tersebut untuk default deduplication mode `coarse`. Perhitungan `+ 1 hour` sesuai baseline `bucket_minutes=60`; jika ukuran bucket diubah, hitung `SIEM_BUCKET_END` menurut nilai aktual. Jika memakai rule override/dedup mode yang menambahkan `dstip`, port, protocol, file path, atau field lain ke case key, tambahkan filter exact yang sama ke query raw. Ketidaksamaan harus diinvestigasi sebelum timer diaktifkan; jangan “memperbaikinya” dengan mengedit dokumen destination atau checkpoint.

## 12. Buat index pattern dan validasi Wazuh Dashboard

`siem_alarm_service` adalah machine account tanpa permission Dashboard. Jangan gunakan account ini untuk login Dashboard dan jangan map ke `kibana_user`. Pada lab, gunakan administrator; production sebaiknya memakai account manusia terpisah dengan read-only pada `siem-alarm-*` dan permission Saved Objects sesuai mode multitenancy.

Untuk account manusia production, pisahkan role data dan akses Dashboard: cluster permission `cluster_composite_ops_ro`, index `siem-alarm-*` dengan action `read`, serta built-in `kibana_user`/hak aplikasi yang sesuai. Jika multitenancy aktif, tambahkan editor tenant dengan `kibana_all_write` atau viewer dengan `kibana_all_read` hanya pada custom tenant SOC. Jangan memberi manusia role `kibana_server`, dan jangan memberi viewer hak tulis destination. Bila account juga memakai halaman Wazuh app/Server API, map Wazuh role `readonly` secara terpisah melalui **Server management → Security → Roles mapping**; mapping Server API tidak diperlukan untuk Discover-only.

Untuk Wazuh Server role mapping tersebut, verifikasi delegasi API aktif:

```bash
sudo grep -nE '^[[:space:]]*run_as:' \
  /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
```

Nilai yang diharapkan adalah `run_as: true`. Jangan mengubahnya hanya untuk Discover; ikuti change control Wazuh RBAC bila Wazuh app memang memerlukan Server role mapping.

Periksa mode multitenancy aktual; konfigurasi production bawaan Wazuh Dashboard 4.14.7 menetapkannya `false`, walaupun deployment dapat mengubahnya:

```bash
sudo grep -nE '^[[:space:]]*opensearch_security\.multitenancy\.enabled:' \
  /etc/wazuh-dashboard/opensearch_dashboards.yml
```

Index pattern adalah Saved Object, sehingga index fisik yang sudah ada tidak otomatis muncul di dropdown Discover. Jika multitenancy `true`, object disimpan per tenant; jika `false`, object masuk default saved-object store dan menu **Switch tenants** tidak tersedia. Gunakan bundle siap impor pada bagian berikutnya sebagai jalur utama, atau lakukan fallback UI manual berikut:

1. Login Wazuh Dashboard sebagai administrator.
2. Bila multitenancy `true`, buka menu user kanan atas → **Switch tenants** lalu pilih custom shared SOC tenant yang disetujui. Bila `false`, lewati tahap ini.
3. Buka menu ☰ → **Dashboard management → Dashboard Management → Index Patterns**.
4. Pilih **Create index pattern**.
5. Isi tepat `siem-alarm-*`—gunakan tanda hubung, bukan underscore.
6. Pilih time field **`timestamp`**, bukan `@timestamp`, lalu simpan.
7. Buka **Explore/Discover** pada tenant/default store yang sama, pilih `siem-alarm-*`, dan set time range **Last 24 hours** atau rentang yang mencakup bucket UTC aktual.

Gunakan DQL berikut untuk dokumen state utama:

```text
document.type: "alarm_state"
```

Gunakan DQL berikut untuk event alarm/escalation create-only yang dibuat engine:

```text
document.type: "alarm_escalation"
```

Tanpa filter `document.type`, kedua tipe akan tampil bersama dan `rule.description` yang sama dapat muncul lebih dari sekali. Itu normal: `alarm_state.timestamp` adalah awal bucket satu jam, sedangkan `alarm_escalation.timestamp` adalah waktu event yang menaikkan/pertama kali memasukkan risk ke Medium, High, atau Critical. `alarm_state` diperbarui deterministik; `alarm_escalation` dibuat create-only/idempotent per `alarm.id + risk.level` oleh engine. Ini bukan storage WORM/tamper-proof: credential runtime yang kompromi tetap berisiko, sedangkan raw `wazuh-alerts-*` yang read-only bagi runtime adalah evidence otoritatif.

Tambahkan kolom Discover berikut:

```text
timestamp
document.type
alarm.id
alarm.status
alarm.event_count
alarm.first_seen
alarm.last_seen
agent.id
agent.name
rule.id
rule.level
rule.description
source.raw_alert_count
risk.score
risk.level
risk.previous_level
source_observed.srcip_unique_count
source_observed.srcip_samples
source_observed.top_srcip
asset.value
asset.category
```

Untuk membuktikan beberapa source IP tidak ditimpa menjadi satu nilai, gunakan DQL:

```text
document.type: "alarm_state" and source_observed.srcip_unique_count > 1
```

Pada case yang memang menerima IP berbeda, `srcip_unique_count` harus lebih dari satu, `srcip_samples` berisi sample deterministik, dan `top_srcip` menyimpan IP teratas beserta frekuensinya. Aggregate document memang dibatasi oleh `evidence_sample_limit` (default 20) dan `evidence_top_limit` (default 10), sehingga tidak semua IP wajib muncul di array ketika cardinality lebih besar; jumlah unik tetap dihitung dari seluruh event bucket dan raw evidence lengkap tetap berada di `wazuh-alerts-*`. Source IP tidak menjadi default case key.

Paket Dashboard SOC siap impor tersedia di [`dashboards/siem_alarm_soc_dashboard.ndjson`](dashboards/siem_alarm_soc_dashboard.ndjson). Paket ini membuat data view deterministik, lima saved search, 19 visualisasi, serta dua dashboard **SIEM Alarm SOC - Overview** dan **SIEM Alarm SOC - Triage & Investigation**. Dashboard Overview memiliki panel **Latest escalated alarm events** yang membaca `alarm_escalation`, diurutkan terbaru ke terlama, dengan kolom default `event.created`, `rule.description`, `risk.level`, dan `agent.name`. Validasi artifact sebelum impor:

```bash
cd ~/wazuhuhuhu/siem-alarm-
python3 dashboards/build_soc_dashboard.py --check
```

Lakukan import melalui **Dashboard management / Stack Management -> Saved Objects -> Import**, dengan overwrite nonaktif untuk instalasi pertama. Jika multitenancy `true`, pilih custom tenant SOC secara eksplisit; jika `false`, gunakan default saved-object store dan jangan mengirim header `securitytenant`. Seluruh tahapan permission, backup, import UI/API, verifikasi, collision handling, dan rollback exact-ID dijelaskan di [panduan Dashboard SOC](dashboards/README.md). Bundle memiliki data view sendiri dengan title `siem-alarm-*` dan time field `timestamp`; bila data view manual ber-ID acak sudah ada, title dapat terlihat dua kali tetapi reference bundle tetap menunjuk ID deterministiknya. Struktur bundle sudah divalidasi terhadap schema Wazuh Dashboard 4.14.7, tetapi hasil import `27 object sukses` pada VM lab tetap menjadi gate sebelum production.

Jika tidak memakai paket siap impor, simpan minimal dua pencarian Discover secara manual dalam tenant/default store yang sama:

1. Simpan query `document.type: "alarm_state"` sebagai **SIEM Alarm - State**.
2. Simpan query `document.type: "alarm_escalation"` sebagai **SIEM Alarm - Escalations**.

Kemudian buat Dashboard SOC manual minimal:

1. Buka **Dashboards → Create dashboard** dan simpan sebagai **SIEM Alarm Overview**.
2. Tambahkan metric **Critical** dengan filter `document.type: "alarm_state" and risk.level: "Critical"`.
3. Tambahkan metric **High** dengan filter `document.type: "alarm_state" and risk.level: "High"`.
4. Tambahkan distribusi Terms berdasarkan `risk.level` dengan filter `document.type: "alarm_state"`.
5. Tambahkan trend Date histogram berdasarkan `timestamp` dengan filter `document.type: "alarm_state"`.
6. Tambahkan saved search **SIEM Alarm - State** sebagai tabel investigasi.
7. Tambahkan saved search **SIEM Alarm - Escalations** sebagai panel eskalasi terbaru.
8. Simpan Dashboard pada tenant/default store yang sudah dipilih dan uji menggunakan account viewer SOC.

Tahap Dashboard dinyatakan selesai bila dropdown Discover menampilkan dan memilih `siem-alarm-*`, saved search bekerja, dashboard SOC dapat dibuka tanpa missing reference, panel state/escalation terpisah, dan time field bekerja. Jumlah hit bersifat dinamis; contoh 13 hit pada satu VM bukan angka kelulusan yang harus selalu sama. Rancangan panel lebih lengkap tersedia pada [final checklist bagian Dashboard SOC](final_checklist_siem_alarm_wazuh_4_14_7.md#15-dashboard-soc).

## 13. Aktifkan timer sebagai langkah terakhir

Aktifkan hanya setelah role, TLS, secret, config, assets, template, ISM, field audit, run manual, concrete mapping, checkpoint, exact raw-evidence cross-check, dan Dashboard semuanya lulus:

```bash
sudo systemctl enable --now siem-alarm-scoring.timer
sudo systemctl is-enabled siem-alarm-scoring.timer
sudo systemctl is-active siem-alarm-scoring.timer
sudo systemctl status siem-alarm-scoring.timer --no-pager -l
sudo systemctl list-timers --all | grep siem-alarm
```

Karena `Persistent=true`, timer dapat memicu service segera bila ada jadwal yang terlewat. Setelah dua atau tiga tick, periksa hasil otomatis:

```bash
sudo systemctl show siem-alarm-scoring.service \
  -p Result -p ExecMainStatus -p ExecMainCode \
  -p ActiveState -p SubState
sudo journalctl -u siem-alarm-scoring.service \
  --since '30 minutes ago' --no-pager
sudo journalctl -t siem-alarm-scoring -n 50 --no-pager
sudo stat -c '%U:%G %a %s %n' \
  /var/lib/wazuh-risk-scoring/checkpoint.json
sudo /usr/bin/python3 -m json.tool \
  /var/lib/wazuh-risk-scoring/checkpoint.json >/dev/null
```

Output failure-handler yang kosong adalah normal bila belum pernah gagal. `lookback_overlap_minutes=7` adalah eligibility delay. Dengan timer 5 menit, finalisasi normal terjadi pada tick sekitar boundary +10 menit, ditambah `AccuracySec`; bukan tepat +7 menit. Alert yang masuk Indexer setelah finalisasi tidak direvisi otomatis dan memerlukan replay/backfill.

Untuk margin aman, ukur end-to-end Filebeat/Indexer lag dan tetapkan SLO internal jauh di bawah eligibility delay, misalnya p99 di bawah 5 menit. Monitor juga:

- durasi run harus jauh di bawah `TimeoutStartSec=240s`;
- tidak ada `429`, timeout, shard failure, cap 100.000 alert/20.000 case, atau `MemoryMax`;
- checkpoint dan dokumen `alarm_state` terus bergerak;
- disk/heap/CPU Wazuh tidak memburuk pada jam puncak;
- rasio `asset.source=default` tetap nol untuk agent wajib inventory.

Failure handler bawaan hanya menulis event `daemon.crit` ke journal lokal. Production wajib menambahkan monitoring eksternal untuk status timer/service, tag `siem-alarm-scoring`, usia checkpoint, dan heartbeat dokumen agar kegagalan pipeline tidak menjadi silent failure.

## 14. Kriteria akhir “selesai”

Deployment VM lokal selesai secara fungsional bila seluruh kondisi berikut terpenuhi:

- source harian `wazuh-alerts-4.x-YYYY.MM.DD` dapat dibaca runtime user dengan HTTP `200`;
- root/Security management API tetap `403`, sedangkan authinfo `200` memuat role yang tepat;
- template dan ISM policy masing-masing dapat di-`GET` dengan HTTP `200`;
- run manual dan run timer terakhir menunjukkan `Result=success` serta `ExecMainStatus=0`;
- concrete `siem-alarm-YYYY.MM.DD` memakai mapping, setting, dan ISM yang benar;
- `alarm_state` dan, bila threshold tercapai, `alarm_escalation` dapat dicari;
- invariant internal dan satu exact raw-evidence count cross-check benar; rerun tidak membuat escalation duplikat;
- checkpoint valid, owner/mode benar, dan bergerak setelah run sukses;
- Dashboard pada tenant/default store yang dipilih menampilkan data view `siem-alarm-*` dengan time field `timestamp`, saved search, serta dashboard SOC tanpa missing reference.

VM lokal yang lulus daftar ini siap untuk soak/shadow/load test. Itu belum otomatis membuktikan kapasitas production.

## 15. Troubleshooting cepat

| Gejala | Arti dan tindakan |
|---|---|
| HTTP `000` | Tidak ada respons HTTP. Periksa pesan `curl`, URL, TCP `9200`, DNS, dan TLS; ini bukan bukti error RBAC. |
| `curl (60)` | CA chain, SAN, atau masa berlaku certificate tidak cocok. Perbaiki URL/certificate; jangan memakai `-k`. |
| `curl (77)` | CA path hilang/tidak terbaca/tidak valid. Gunakan `sudo curl` untuk test operator dan buktikan `siem-alarm` dapat membaca CA; jangan longgarkan permission key/certificate. |
| HTTP `401` | Username/password salah atau sudah dirotasi. Hentikan timer, sinkronkan internal user dan environment file. |
| HTTP `403` | Autentikasi berhasil tetapi tidak berwenang. Normal untuk root/Security API runtime; tidak normal untuk source count atau search destination. |
| HTTP `404` | Object/index belum ada. Normal untuk template/ISM sebelum create, destination sebelum run non-kosong, atau source date tanpa raw index. Diagnosis object exact; jangan membuat/menghapus secara buta. |
| HTTP `400` | Request/schema tidak valid atau ada incompatibility versi. Baca response body dan journal. |
| HTTP `409` | Konflik create/update. Policy ISM existing memerlukan sequence/primary-term; jangan delete untuk menghindari konflik. |
| HTTP `429` | Indexer menolak karena pressure. Biarkan timer nonaktif, periksa heap/load/retry; jangan langsung menaikkan cap atau batch. |

Command diagnosis read-only:

```bash
sudo systemctl status \
  wazuh-manager wazuh-indexer wazuh-dashboard filebeat \
  --no-pager -l
sudo /var/ossec/bin/wazuh-control status
sudo ss -lntp | grep -E ':(9200|55000)\b'
sudo journalctl -u wazuh-manager -u wazuh-indexer \
  -u wazuh-dashboard -n 150 --no-pager
sudo journalctl -u siem-alarm-scoring.service -n 150 --no-pager
sudo tail -n 100 /var/ossec/logs/api.log
sudo tail -n 100 \
  /opt/wazuh-risk-scoring/logs/siem_alarm_scoring.log
```

Pesan Dashboard `[API connection] 3002 ...:55000 unreachable` merujuk Wazuh Server API, bukan Indexer atau role `siem_alarm_runtime`. Scorer hanya memakai HTTPS `9200`. Perbaiki kesehatan `wazuh-apid`/`wazuh-db` secara terpisah; reboot yang membuatnya normal kembali tidak menggantikan pemeriksaan akar masalah bila gangguan berulang.

## 16. Outage dan rollback

Untuk outage panjang atau late alert, gunakan prosedur satu-bucket, boundary-aligned, dengan konfirmasi dan pemulihan status timer pada [bagian manual backfill](final_checklist_siem_alarm_wazuh_4_14_7.md#127-manual-backfill-setelah-outage). Manual backfill tidak memajukan checkpoint calendar.

Rollback normal tidak menghapus index:

```bash
sudo systemctl stop siem-alarm-scoring.timer
sudo systemctl stop siem-alarm-scoring.service
sudo systemctl disable siem-alarm-scoring.timer
sudo systemctl is-active siem-alarm-scoring.timer || true
sudo systemctl is-enabled siem-alarm-scoring.timer || true
```

Raw Wazuh tetap berjalan. Pilih restore code/config tanpa menghapus output, atau full rebuild melalui change control. Jangan hapus `siem-alarm-*` lalu menyalakan service dengan checkpoint lama. Lihat [rollback plan](final_checklist_siem_alarm_wazuh_4_14_7.md#21-rollback-plan).

## 17. Upgrade proyek

Installer mempertahankan config, inventory, secret, dan checkpoint existing; script/unit diperbarui dan timer tetap dinonaktifkan. Jalankan upgrade terkontrol:

Isi `SIEM_APPROVED_COMMIT` dengan SHA 40 karakter yang sudah direview/di-approve; prosedur sengaja menolak latest `main` yang belum dipin:

```bash
SIEM_APPROVED_COMMIT='ISI_SHA_40_KARAKTER_YANG_SUDAH_DIREVIEW'

siem_upgrade_project() {
  local siem_git_status
  if [[ ! "${SIEM_APPROVED_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
    echo 'ERROR: SIEM_APPROVED_COMMIT belum berisi SHA valid yang direview.' >&2
    return 1
  fi

  sudo systemctl stop siem-alarm-scoring.timer || return
  sudo systemctl stop siem-alarm-scoring.service || return

  cd /home/administrator/wazuhuhuhu || return
  git remote set-url origin \
    https://github.com/AkbarWiraN/wazuhuhuhu.git || return
  siem_git_status="$(git status --porcelain=v1 --untracked-files=all)" || return
  if [ -n "${siem_git_status}" ]; then
    echo 'ERROR: working tree tidak bersih; upgrade dibatalkan.' >&2
    printf '%s\n' "${siem_git_status}" >&2
    return 1
  fi

  git fetch --tags --prune origin main || return
  git cat-file -e "${SIEM_APPROVED_COMMIT}^{commit}" || return
  git checkout --detach "${SIEM_APPROVED_COMMIT}" || return
  test "$(git rev-parse HEAD)" = "${SIEM_APPROVED_COMMIT}" || return
  cd /home/administrator/wazuhuhuhu/siem-alarm- || return
  git log -1 --oneline || return
  git rev-parse HEAD || return

  /usr/bin/python3 -B -m unittest discover -s tests -v || return
  bash -n ./setup_siem_alarm_final.sh || return

  sudo env \
    WAZUH_CA_SOURCE=/etc/wazuh-indexer/certs/root-ca.pem \
    WAZUH_INDEXER_CERT_SOURCE=/etc/wazuh-indexer/certs/wazuh-indexer.pem \
    bash ./setup_siem_alarm_final.sh
}

if siem_upgrade_project; then
  echo 'OK: source dan file runtime berhasil di-upgrade; timer tetap nonaktif.'
else
  echo 'ERROR: upgrade berhenti; review error sebelum melanjutkan.' >&2
fi
unset -f siem_upgrade_project
unset SIEM_APPROVED_COMMIT
```

Prosedur di atas berhenti bila working tree kotor, SHA belum disetujui, fetch/checkout gagal, test gagal, atau installer gagal. Setelah installer, baca seluruh warning migration, tambahkan key baru dari config example, validasi assets/config, lalu ulangi tahap 8–14. Jangan langsung meng-enable timer.

Perubahan bucket, source/filter, dedup/rule override, atau destination prefix mengubah identitas case dan fail-closed terhadap checkpoint lama. Gunakan shadow destination atau controlled backfill; jangan hapus checkpoint hanya agar error hilang.

## Batas klaim “siap production”

Untuk 5–25 agent, jumlah agent sendiri kecil. Risiko kapasitas ditentukan EPS, burst, jumlah rule/case unik, dan cardinality evidence. Model steady-state timer 5 menit membaca sekitar `6,5 × A` raw alert per jam untuk laju `A` per bucket: current bucket dihitung ulang, lalu closed bucket difinalisasi sekali. `_mget`/bulk mengurangi request per case, tetapi tidak menghilangkan biaya scan snapshot.

Initial scroll memakai `track_total_hits=true` karena Wazuh Indexer 4.14.7
menolak threshold numerik pada scroll context. Karena itu Indexer menghitung total hit
eksak sebelum engine memeriksa `max_alerts_per_bucket`; cap tetap mencegah pagination,
agregasi, dan penulisan bucket yang terlalu besar, tetapi tidak menghilangkan biaya
exact-hit count. Masukkan biaya ini dalam shadow/load test.

Proyek dinyatakan **siap untuk staging production**, bukan otomatis terbukti kapasitasnya pada VM Anda. Go-live memerlukan OS yang masih menerima security updates melalui dukungan yang berlaku, source yang dipin ke revisi ter-review, persetujuan retensi/snapshot, monitoring eksternal, shadow/load test pada traffic puncak, observasi beberapa bucket, dan rollback window. Jangan menaikkan cap, batch, paralelisme, atau cgroup limit sebelum ada hasil ukur.

## Referensi resmi

- [Wazuh 4.14.7 release notes](https://documentation.wazuh.com/current/release-notes/release-4-14-7.html)
- [Wazuh Indexer indices](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
- [Wazuh rules classification](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html)
- [Wazuh agent labels](https://documentation.wazuh.com/current/user-manual/agent/agent-management/labels.html)
- [Wazuh centralized configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)
- [Ubuntu Expanded Security Maintenance](https://ubuntu.com/security/esm)
- [Ubuntu Pro CLI status reference](https://documentation.ubuntu.com/pro-client/en/latest/references/commands/)
- [OpenSearch default action groups](https://docs.opensearch.org/latest/security/access-control/default-action-groups/)
- [OpenSearch authentication information API](https://docs.opensearch.org/latest/api-reference/security/authentication/auth-info/)
- [OpenSearch index patterns](https://docs.opensearch.org/latest/dashboards/management/index-patterns/)
- [OpenSearch multi-tenancy](https://docs.opensearch.org/latest/security/multi-tenancy/tenant-index/)
- [OpenSearch ISM API](https://docs.opensearch.org/latest/im-plugin/ism/api/)
- [OpenSearch Bulk API](https://docs.opensearch.org/latest/api-reference/document-apis/bulk/)
- [OpenSearch Multi-get API](https://docs.opensearch.org/latest/api-reference/document-apis/multi-get/)

Untuk detail tuning, schema, progressive scoring, query dashboard, failure modes, backfill, dan rollback, lanjutkan ke [final checklist](final_checklist_siem_alarm_wazuh_4_14_7.md).
