#!/usr/bin/env python3
"""Linux Admin Panel - Web Version (no external dependencies)."""

from __future__ import annotations

import html
import os
import re
import shutil
import socket
import subprocess
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

HOST = os.getenv("PANEL_HOST", "0.0.0.0")
PORT = int(os.getenv("PANEL_PORT", "8080"))
MAX_OUTPUT = 16000
SAFE_PACKAGE_RE = re.compile(r"^[a-zA-Z0-9.+_-]+$")
SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9._/-]+$")
DEFAULT_BASE_DIR = os.getenv("PANEL_FILES_BASE", "/etc")


def detect_pkg_manager() -> str:
    for manager in ("apt-get", "dnf", "yum", "pacman"):
        if shutil.which(manager):
            return manager
    return "unknown"


def run_command(cmd: list[str], timeout: int = 45) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        output = output.strip() or "(no output)"
        if len(output) > MAX_OUTPUT:
            output = output[:MAX_OUTPUT] + "\n... output truncated ..."
        return proc.returncode, output
    except Exception as exc:  # pylint: disable=broad-except
        return 1, f"Error menjalankan command: {exc}"


def build_install_command(package: str) -> list[str] | None:
    manager = detect_pkg_manager()
    if manager == "apt-get":
        return ["apt-get", "install", "-y", package]
    if manager == "dnf":
        return ["dnf", "install", "-y", package]
    if manager == "yum":
        return ["yum", "install", "-y", package]
    if manager == "pacman":
        return ["pacman", "-S", "--noconfirm", package]
    return None


def resolve_safe_path(user_path: str, base_dir: str = DEFAULT_BASE_DIR) -> Path | None:
    if not user_path or not SAFE_FILENAME_RE.match(user_path):
        return None
    base = Path(base_dir).resolve()
    target = (base / user_path.lstrip("/")).resolve()
    if base == target or base in target.parents:
        return target
    return None


def collect_dashboard() -> dict[str, str]:
    sections: dict[str, str] = {}
    sections["Ringkasan Sistem"] = "\n".join(
        [
            f"Hostname: {socket.gethostname()}",
            f"Time: {datetime.now().isoformat(sep=' ', timespec='seconds')}",
            f"Kernel: {run_command(['uname', '-r'])[1]}",
            f"Uptime: {run_command(['uptime', '-p'])[1]}",
            f"Package manager: {detect_pkg_manager()}",
        ]
    )
    sections["Resource"] = run_command(["bash", "-lc", "uptime && echo '---' && free -h && echo '---' && df -hT | head -n 20"])[1]
    sections["Service snapshot"] = run_command(["bash", "-lc", "systemctl list-units --type=service --state=running | head -n 30"])[1]
    return sections


def collect_monitoring() -> dict[str, str]:
    sections: dict[str, str] = {}
    sections["CPU/Load"] = run_command(["uptime"])[1]
    sections["Memory"] = run_command(["free", "-h"])[1]
    sections["Disk"] = run_command(["df", "-hT"])[1]
    sections["Top CPU Process"] = run_command(["bash", "-lc", "ps aux --sort=-%cpu | head -n 15"])[1]
    sections["Top Memory Process"] = run_command(["bash", "-lc", "ps aux --sort=-%mem | head -n 15"])[1]
    net_cmd = ["bash", "-lc", "ss -tulpen | head -n 40 || netstat -tulpen | head -n 40"]
    sections["Ports & Connections"] = run_command(net_cmd)[1]
    sections["Network Interfaces"] = run_command(["bash", "-lc", "ip -brief a || ifconfig"])[1]
    return sections


def collect_security() -> dict[str, str]:
    sections: dict[str, str] = {}
    fw_cmd = [
        "bash",
        "-lc",
        "if command -v ufw >/dev/null 2>&1; then ufw status verbose; "
        "elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state && firewall-cmd --list-all; "
        "elif command -v iptables >/dev/null 2>&1; then iptables -L -n -v; "
        "else echo 'Firewall utility tidak ditemukan'; fi",
    ]
    sections["Firewall"] = run_command(fw_cmd)[1]

    ssh_check = run_command(
        [
            "bash",
            "-lc",
            "if [ -f /etc/ssh/sshd_config ]; then "
            "rg -n '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port)' /etc/ssh/sshd_config; "
            "else echo '/etc/ssh/sshd_config tidak ditemukan'; fi",
        ]
    )[1]
    sections["SSH Audit"] = ssh_check + "\n\nRekomendasi:\n- PermitRootLogin no\n- PasswordAuthentication no\n- Gunakan SSH key"

    fail2ban = run_command(
        ["bash", "-lc", "if command -v fail2ban-client >/dev/null 2>&1; then fail2ban-client status; else echo 'Fail2Ban belum terpasang'; fi"]
    )[1]
    sections["Fail2Ban"] = fail2ban
    return sections


def section_blocks(sections: dict[str, str]) -> str:
    return "".join(f"<h3>{html.escape(name)}</h3><pre>{html.escape(text)}</pre>" for name, text in sections.items())


def page(content: str, title: str = "Linux Admin Panel Web") -> bytes:
    html_page = f"""<!doctype html>
<html lang=\"id\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }}
    .container {{ max-width: 1100px; margin: 24px auto; padding: 0 16px; }}
    .card {{ background: #1e293b; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
    h1,h2,h3 {{ margin-top: 0; }}
    button {{ background: #2563eb; color: white; border: none; border-radius: 6px; padding: 10px 14px; cursor: pointer; margin: 4px 4px 0 0; }}
    button:hover {{ background: #1d4ed8; }}
    input, select, textarea {{ padding: 8px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #e2e8f0; }}
    pre {{ white-space: pre-wrap; background: #020617; border-radius: 8px; padding: 12px; overflow-x: auto; }}
    .row {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
    .warn {{ color: #fbbf24; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; }}
    a {{ color: #93c5fd; }}
  </style>
</head>
<body>
<div class=\"container\">{content}</div>
</body></html>"""
    return html_page.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def _send(self, content: bytes, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/":
            self._send(page("<h1>404</h1><p>Halaman tidak ditemukan.</p>"), HTTPStatus.NOT_FOUND)
            return

        mgr = detect_pkg_manager()
        root_warn = "" if os.geteuid() == 0 else "<p class='warn'>⚠️ Jalankan sebagai root agar aksi install/update bisa sukses.</p>"
        content = f"""
        <h1>Linux Admin Panel (Web)</h1>
        <p>Panel admin Linux berbasis web untuk <b>webserver</b>, <b>database</b>, <b>file manager</b>, <b>config checker</b>, <b>firewall</b>, <b>security hardening</b>, <b>log</b>, <b>cron</b>, dan <b>dashboard</b>.</p>
        {root_warn}

        <div class=\"card\"> 
          <h2>Dashboard</h2>
          <form method=\"post\" action=\"/dashboard\"><button type=\"submit\">Refresh Dashboard</button></form>
        </div>

        <div class=\"grid\">
          <div class=\"card\">
            <h2>Install Webserver & Database</h2>
            <p>Package manager: <b>{html.escape(mgr)}</b></p>
            <form method=\"post\" action=\"/install\" class=\"row\">
              <button name=\"package\" value=\"nginx\">Install Nginx</button>
              <button name=\"package\" value=\"apache2\">Install Apache</button>
              <button name=\"package\" value=\"mariadb-server\">Install MariaDB</button>
              <button name=\"package\" value=\"postgresql\">Install PostgreSQL</button>
            </form>
            <form method=\"post\" action=\"/install\" class=\"row\" style=\"margin-top:8px\">
              <input name=\"package\" required placeholder=\"custom package\" />
              <button type=\"submit\">Install</button>
            </form>
          </div>

          <div class=\"card\">
            <h2>Files</h2>
            <p>Base direktori: <code>{html.escape(DEFAULT_BASE_DIR)}</code></p>
            <form method=\"post\" action=\"/files\" class=\"row\">
              <input name=\"path\" placeholder=\"nginx/nginx.conf\" required />
              <button type=\"submit\" name=\"action\" value=\"read\">Lihat File</button>
              <button type=\"submit\" name=\"action\" value=\"list\">List Folder</button>
            </form>
          </div>

          <div class=\"card\">
            <h2>Config Webserver</h2>
            <form method=\"post\" action=\"/config\" class=\"row\">
              <button type=\"submit\" name=\"target\" value=\"nginx\">Test Nginx Config</button>
              <button type=\"submit\" name=\"target\" value=\"apache\">Test Apache Config</button>
            </form>
          </div>

          <div class=\"card\">
            <h2>Firewall</h2>
            <form method=\"post\" action=\"/firewall\" class=\"row\">
              <button type=\"submit\" name=\"action\" value=\"status\">Status</button>
              <button type=\"submit\" name=\"action\" value=\"allow80\">Allow 80/tcp</button>
              <button type=\"submit\" name=\"action\" value=\"allow443\">Allow 443/tcp</button>
            </form>
          </div>

          <div class=\"card\">
            <h2>Security Hardening</h2>
            <form method=\"post\" action=\"/security\" class=\"row\">
              <button type=\"submit\" name=\"action\" value=\"audit\">Audit</button>
              <button type=\"submit\" name=\"action\" value=\"patch\">Patch Sistem</button>
              <button type=\"submit\" name=\"action\" value=\"harden\">Apply Hardening Dasar</button>
            </form>
          </div>

          <div class=\"card\">
            <h2>Log Management</h2>
            <form method=\"post\" action=\"/logs\" class=\"row\">
              <input name=\"log\" placeholder=\"/var/log/syslog\" />
              <button type=\"submit\" name=\"action\" value=\"tail\">Tail Log</button>
              <button type=\"submit\" name=\"action\" value=\"journal\">Journalctl</button>
            </form>
          </div>

          <div class=\"card\">
            <h2>Crontab</h2>
            <form method=\"post\" action=\"/cron\" class=\"row\">
              <button type=\"submit\" name=\"action\" value=\"list\">List Crontab</button>
            </form>
          </div>

          <div class=\"card\">
            <h2>Monitoring</h2>
            <form method=\"post\" action=\"/monitor\"><button type=\"submit\">Refresh Monitoring</button></form>
          </div>
        </div>
        """
        self._send(page(content))

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        form = parse_qs(raw)

        if self.path == "/install":
            package = (form.get("package", [""])[0] or "").strip()
            if not package or not SAFE_PACKAGE_RE.match(package):
                self._send(page("<h2>Input package tidak valid.</h2><a href='/'>Kembali</a>"), HTTPStatus.BAD_REQUEST)
                return
            cmd = build_install_command(package)
            if cmd is None:
                self._send(page("<h2>Package manager tidak didukung.</h2><a href='/'>Kembali</a>"), HTTPStatus.BAD_REQUEST)
                return
            code, out = run_command(cmd, timeout=180)
            result = f"<h2>Install package: {html.escape(package)}</h2><p>Exit code: {code}</p><pre>{html.escape(out)}</pre><a href='/'>Kembali</a>"
            self._send(page(result, "Hasil Instalasi"))
            return

        if self.path == "/dashboard":
            blocks = section_blocks(collect_dashboard())
            self._send(page(f"<h2>Dashboard</h2>{blocks}<a href='/'>Kembali</a>", "Dashboard"))
            return

        if self.path == "/monitor":
            blocks = section_blocks(collect_monitoring())
            self._send(page(f"<h2>Monitoring Server</h2>{blocks}<a href='/'>Kembali</a>", "Monitoring"))
            return

        if self.path == "/files":
            action = (form.get("action", ["read"])[0] or "read").strip()
            user_path = (form.get("path", [""])[0] or "").strip()
            safe_path = resolve_safe_path(user_path)
            if safe_path is None:
                self._send(page("<h2>Path tidak valid.</h2><a href='/'>Kembali</a>"), HTTPStatus.BAD_REQUEST)
                return

            if action == "list":
                code, out = run_command(["bash", "-lc", f"ls -lah {safe_path}"])
                self._send(page(f"<h2>List Folder: {html.escape(str(safe_path))}</h2><p>Exit code: {code}</p><pre>{html.escape(out)}</pre><a href='/'>Kembali</a>", "Files"))
                return
            if action == "read":
                code, out = run_command(["bash", "-lc", f"sed -n '1,200p' {safe_path}"])
                self._send(page(f"<h2>File: {html.escape(str(safe_path))}</h2><p>Exit code: {code}</p><pre>{html.escape(out)}</pre><a href='/'>Kembali</a>", "Files"))
                return

        if self.path == "/config":
            target = (form.get("target", ["nginx"])[0] or "nginx").strip()
            checks = {
                "nginx": ["bash", "-lc", "nginx -t"],
                "apache": ["bash", "-lc", "apachectl configtest || httpd -t"],
            }
            cmd = checks.get(target)
            if cmd is None:
                self._send(page("<h2>Target config tidak valid.</h2><a href='/'>Kembali</a>"), HTTPStatus.BAD_REQUEST)
                return
            code, out = run_command(cmd)
            self._send(page(f"<h2>Config Test: {html.escape(target)}</h2><p>Exit code: {code}</p><pre>{html.escape(out)}</pre><a href='/'>Kembali</a>", "Config"))
            return

        if self.path == "/firewall":
            action = (form.get("action", ["status"])[0] or "status").strip()
            cmd_map = {
                "status": ["bash", "-lc", "ufw status verbose || firewall-cmd --list-all || iptables -L -n -v"],
                "allow80": ["bash", "-lc", "ufw allow 80/tcp || firewall-cmd --permanent --add-service=http"],
                "allow443": ["bash", "-lc", "ufw allow 443/tcp || firewall-cmd --permanent --add-service=https"],
            }
            cmd = cmd_map.get(action)
            if cmd is None:
                self._send(page("<h2>Aksi firewall tidak valid.</h2><a href='/'>Kembali</a>"), HTTPStatus.BAD_REQUEST)
                return
            code, out = run_command(cmd)
            self._send(page(f"<h2>Firewall: {html.escape(action)}</h2><p>Exit code: {code}</p><pre>{html.escape(out)}</pre><a href='/'>Kembali</a>", "Firewall"))
            return

        if self.path == "/security":
            action = (form.get("action", ["audit"])[0] or "audit").strip()
            extra = ""
            if action == "patch":
                manager = detect_pkg_manager()
                update_cmd = {
                    "apt-get": ["bash", "-lc", "apt-get update && apt-get upgrade -y"],
                    "dnf": ["dnf", "upgrade", "-y"],
                    "yum": ["yum", "update", "-y"],
                    "pacman": ["pacman", "-Syu", "--noconfirm"],
                }.get(manager)
                if update_cmd:
                    code, out = run_command(update_cmd, timeout=300)
                    extra = f"<h3>Patch Update</h3><p>Exit code: {code}</p><pre>{html.escape(out)}</pre>"
            if action == "harden":
                harden_cmd = [
                    "bash",
                    "-lc",
                    "if [ -f /etc/ssh/sshd_config ]; then "
                    "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s) && "
                    "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && "
                    "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && "
                    "systemctl restart sshd || systemctl restart ssh; "
                    "else echo 'sshd_config tidak ditemukan'; fi",
                ]
                code, out = run_command(harden_cmd)
                extra = f"<h3>Hardening</h3><p>Exit code: {code}</p><pre>{html.escape(out)}</pre>"

            blocks = section_blocks(collect_security())
            self._send(page(f"<h2>Audit Keamanan</h2>{extra}{blocks}<a href='/'>Kembali</a>", "Keamanan"))
            return

        if self.path == "/logs":
            action = (form.get("action", ["tail"])[0] or "tail").strip()
            log_path = (form.get("log", ["/var/log/syslog"])[0] or "/var/log/syslog").strip()
            if action == "journal":
                code, out = run_command(["bash", "-lc", "journalctl -n 120 --no-pager"])
            else:
                if not SAFE_FILENAME_RE.match(log_path):
                    self._send(page("<h2>Path log tidak valid.</h2><a href='/'>Kembali</a>"), HTTPStatus.BAD_REQUEST)
                    return
                code, out = run_command(["bash", "-lc", f"tail -n 120 {log_path}"])
            self._send(page(f"<h2>Logs: {html.escape(action)}</h2><p>Exit code: {code}</p><pre>{html.escape(out)}</pre><a href='/'>Kembali</a>", "Logs"))
            return

        if self.path == "/cron":
            code, out = run_command(["bash", "-lc", "crontab -l || echo 'Crontab kosong atau tidak tersedia'"], timeout=25)
            self._send(page(f"<h2>Crontab</h2><p>Exit code: {code}</p><pre>{html.escape(out)}</pre><a href='/'>Kembali</a>", "Crontab"))
            return

        self._send(page("<h1>404</h1><p>Endpoint tidak ditemukan.</p>"), HTTPStatus.NOT_FOUND)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[web-panel] {self.address_string()} - {fmt % args}")


def main() -> None:
    server = HTTPServer((HOST, PORT), Handler)
    print(f"Linux Admin Panel Web berjalan di http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
