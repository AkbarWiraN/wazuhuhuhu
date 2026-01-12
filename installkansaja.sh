#!/bin/bash

# =================================================================
# WAZUH ALL-IN-ONE AUTO-INSTALLER (SPECIFIC VERSION 4.14)
# =================================================================

if [ "$EUID" -ne 0 ]; then 
  echo "Harap jalankan dengan: sudo su"
  exit
fi

# 1. Deteksi IP Publik
IP_ADDR=$(curl -s https://ifconfig.me)
if [ -z "$IP_ADDR" ]; then
    IP_ADDR=$(hostname -I | awk '{print $1}')
fi

echo "-------------------------------------------------------"
echo "MEMULAI INSTALASI WAZUH VERSI 4.14"
echo "IP Publik: $IP_ADDR"
echo "-------------------------------------------------------"

# 2. Persiapan Folder dan Tools
apt-get update -y
apt-get install -y curl tar wget libcap2-bin binutils

# 3. Download Wazuh Installation Assistant Versi 4.14
echo "[1/4] Mengunduh Wazuh Assistant 4.14..."
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh

# 4. Download & Modifikasi config.yml
echo "[2/4] Mengunduh dan mengonfigurasi config.yml..."
curl -sO https://packages.wazuh.com/4.14/config.yml

# Mengganti placeholder IP di config.yml dengan IP Publik VPS Anda
# Ini memastikan sertifikat SSL valid untuk IP VPS Anda
sed -i "s/<indexer-node-ip>/$IP_ADDR/g" config.yml
sed -i "s/<wazuh-manager-ip>/$IP_ADDR/g" config.yml
sed -i "s/<dashboard-node-ip>/$IP_ADDR/g" config.yml

# 5. Jalankan Instalasi All-in-One
echo "[3/4] Menjalankan instalasi komponen 4.14..."
# Gunakan flag -a untuk All-in-one dan -c untuk config file
bash wazuh-install.sh -a -c config.yml

# 6. Firewall & Kredensial
echo "[4/4] Finalisasi..."
if command -v ufw >/dev/null; then
    ufw allow 443/tcp && ufw allow 1514/tcp && ufw allow 1515/tcp && ufw reload
fi

echo "-------------------------------------------------------"
echo "INSTALASI WAZUH 4.14 SELESAI!"
echo "-------------------------------------------------------"
echo "URL: https://$IP_ADDR"
echo "User: admin"
echo -n "Password: "
tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -w "admin" | awk '{print $2}'
echo "-------------------------------------------------------"
