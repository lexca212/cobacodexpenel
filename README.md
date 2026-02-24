# Linux Admin Panel (Web)

Panel administrasi Linux berbasis web (tanpa dependency eksternal) sesuai kebutuhan Anda: install webserver/database, file manager, config checker, firewall, hardening, log management, crontab, dashboard, dan monitoring.

## Fitur Utama

### 1) Dashboard
- Ringkasan sistem: hostname, waktu, kernel, uptime, package manager
- Snapshot resource (load, memory, disk)
- Snapshot service aktif

### 2) Install Webserver & Database
- Shortcut install: **Nginx**, **Apache**, **MariaDB**, **PostgreSQL**
- Install package custom
- Auto deteksi package manager: `apt-get`, `dnf`, `yum`, `pacman`

### 3) Files
- Lihat isi file (`read`) dan list direktori (`list`)
- Akses dibatasi ke base directory `PANEL_FILES_BASE` (default `/etc`)

### 4) Config Webserver
- Validasi konfigurasi `nginx -t`
- Validasi konfigurasi Apache (`apachectl configtest` / `httpd -t`)

### 5) Firewall
- Cek status firewall (`ufw` / `firewalld` / `iptables`)
- Shortcut allow `80/tcp` dan `443/tcp`

### 6) Security Hardening
- Audit firewall, SSH, dan Fail2Ban
- Tombol update patch sistem
- Hardening dasar SSH (`PermitRootLogin no`, `PasswordAuthentication no`)

### 7) Log Management
- Tail log file (`tail -n 120`)
- Lihat `journalctl`

### 8) Crontab
- Menampilkan isi `crontab -l`

### 9) Monitoring
- CPU/load, RAM, disk
- Top proses CPU dan memory
- Port/koneksi aktif serta network interface

## Menjalankan aplikasi web

```bash
python3 web_panel.py
```

Lalu buka browser ke:

```text
http://localhost:8080
```

## Konfigurasi host/port dan file base

```bash
PANEL_HOST=0.0.0.0 PANEL_PORT=8080 PANEL_FILES_BASE=/etc python3 web_panel.py
```

## Catatan
- Jalankan sebagai **root** agar aksi install/update/hardening/firewall berjalan normal.
- Tool ini menjalankan command sistem secara langsung, gunakan hanya di server yang Anda kontrol.
