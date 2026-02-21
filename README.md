# Linux Admin Panel (Web)

Sesuai request, ini adalah **versi web** untuk panel administrasi Linux.

## Fitur Utama

### 1) Instalasi aplikasi
- Install cepat: **Nginx**, **Docker**, **Git**, **HTOP**
- Install package custom
- Auto deteksi package manager: `apt-get`, `dnf`, `yum`, `pacman`

### 2) Monitoring server
- Informasi sistem (hostname, kernel, uptime, waktu)
- CPU/load, RAM, disk
- Top proses berdasarkan CPU & memory
- Port/koneksi aktif dan interface jaringan

### 3) Keamanan
- Audit firewall (`ufw` / `firewalld` / `iptables`)
- Audit konfigurasi SSH (`sshd_config`)
- Status Fail2Ban
- Tombol update patch sistem

## Menjalankan aplikasi web

```bash
python3 web_panel.py
```

Lalu buka browser ke:

```text
http://localhost:8080
```

## Konfigurasi host/port

Bisa diubah pakai environment variable:

```bash
PANEL_HOST=0.0.0.0 PANEL_PORT=8080 python3 web_panel.py
```

## Catatan
- Jalankan sebagai **root** agar aksi install/update berhasil.
- Tool ini menjalankan command sistem secara langsung, jadi gunakan di server yang Anda kontrol.
