"""
ATS Network Monitor — On-Site Agent
=====================================
Deploy one copy of this folder to a machine at each client site.
Runs every 5 minutes (Windows Task Scheduler / cron / TrueNAS VM cron).

Capabilities:
  - Ping all known devices, update status in SharePoint
  - ARP scan subnet for new/unknown devices
  - Log status-change events + send email alerts
  - Poll Pi-hole API for stats (if configured for this client)
  - Report to ATS_Devices and ATS_Events SharePoint lists

Usage:
    pip install requests msal ping3 scapy
    python agent.py --client AMBIT
    python agent.py --client AMBIT --once       # run once then exit
    python agent.py --client AMBIT --discover   # force ARP scan even if disabled

Setup for Windows Task Scheduler:
    Action: python C:\\ATS\\network-monitor\\agent\\agent.py --client AMBIT
    Trigger: Every 5 minutes, run whether user is logged on or not
"""

import sys
import os
import argparse
import json
import socket
import subprocess
import time
import datetime
import logging
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import requests
import msal
from config import (
    TENANT_ID, CLIENT_ID, CLIENT_SECRET,
    GRAPH_BASE, SHAREPOINT_SITE_NAME, SHAREPOINT_HOST,
    LIST_CLIENTS, LIST_DEVICES, LIST_EVENTS,
    PING_COUNT, PING_TIMEOUT_SEC, ALERT_ON_DOWN_MIN,
    ARP_SCAN_ENABLED, PIHOLE_API_ENABLED, PIHOLE_STATS_INTERVAL_MIN,
    ALERTS_ENABLED, ALERT_EMAIL_TO, ALERT_EMAIL_FROM,
    GITHUB_TOKEN, GITHUB_REPO, GITHUB_BRANCH, GITHUB_DATA_DIR,
)

# ── Logging ────────────────────────────────────────────────────────────────
log_dir = Path(__file__).parent / "logs"
log_dir.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_dir / "agent.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("ats-agent")


# ── Auth ───────────────────────────────────────────────────────────────────

_token_cache = {"token": None, "expires": 0}

def get_token():
    if time.time() < _token_cache["expires"] - 60:
        return _token_cache["token"]
    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        client_credential=CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        raise RuntimeError(f"Auth failed: {result.get('error_description')}")
    _token_cache["token"] = result["access_token"]
    _token_cache["expires"] = time.time() + result.get("expires_in", 3600)
    return _token_cache["token"]


def hdrs():
    return {"Authorization": f"Bearer {get_token()}", "Content-Type": "application/json"}


# ── SharePoint helpers ─────────────────────────────────────────────────────

_site_id_cache = None

def get_site_id():
    global _site_id_cache
    if _site_id_cache:
        return _site_id_cache
    url = f"{GRAPH_BASE}/sites/{SHAREPOINT_HOST}:/sites/{SHAREPOINT_SITE_NAME}"
    r = requests.get(url, headers=hdrs())
    r.raise_for_status()
    _site_id_cache = r.json()["id"]
    return _site_id_cache


def sp_get(list_name, filter_str=None):
    site = get_site_id()
    url = f"{GRAPH_BASE}/sites/{site}/lists/{list_name}/items?expand=fields"
    if filter_str:
        url += f"&$filter={filter_str}"
    items = []
    while url:
        r = requests.get(url, headers=hdrs())
        r.raise_for_status()
        data = r.json()
        items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return items


def sp_update(list_name, item_id, fields):
    site = get_site_id()
    url = f"{GRAPH_BASE}/sites/{site}/lists/{list_name}/items/{item_id}/fields"
    r = requests.patch(url, headers=hdrs(), json=fields)
    r.raise_for_status()


def sp_create(list_name, fields):
    site = get_site_id()
    url = f"{GRAPH_BASE}/sites/{site}/lists/{list_name}/items"
    r = requests.post(url, headers=hdrs(), json={"fields": fields})
    r.raise_for_status()
    return r.json()


# ── Ping ───────────────────────────────────────────────────────────────────

def ping(ip: str) -> tuple[bool, float]:
    """Returns (is_alive, avg_ms). Cross-platform."""
    param = "-n" if sys.platform == "win32" else "-c"
    timeout_param = "-w" if sys.platform == "win32" else "-W"
    timeout_val = str(PING_TIMEOUT_SEC * 1000) if sys.platform == "win32" else str(PING_TIMEOUT_SEC)
    cmd = ["ping", param, str(PING_COUNT), timeout_param, timeout_val, ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=PING_TIMEOUT_SEC * PING_COUNT + 3)
        alive = result.returncode == 0
        # Parse avg latency from output
        avg_ms = 0.0
        output = result.stdout
        if sys.platform == "win32":
            for line in output.splitlines():
                if "Average" in line or "average" in line:
                    parts = line.split("=")
                    if len(parts) > 1:
                        try:
                            avg_ms = float(parts[-1].replace("ms", "").strip())
                        except ValueError:
                            pass
        else:
            for line in output.splitlines():
                if "min/avg/max" in line or "rtt" in line:
                    parts = line.split("/")
                    if len(parts) >= 5:
                        try:
                            avg_ms = float(parts[4])
                        except (ValueError, IndexError):
                            pass
        return alive, avg_ms
    except subprocess.TimeoutExpired:
        return False, 0.0
    except Exception as e:
        log.warning(f"Ping error for {ip}: {e}")
        return False, 0.0


# ── ARP scan (find new devices) ────────────────────────────────────────────

def arp_scan(subnet: str) -> list[dict]:
    """
    Scan subnet and return list of {ip, mac, hostname} dicts.
    Uses 'arp -a' (available on Windows + Linux without root).
    For deeper scanning, scapy ARP is used if available.
    """
    discovered = []
    try:
        # Try scapy first (more reliable)
        from scapy.all import ARP, Ether, srp
        import ipaddress
        net = ipaddress.ip_network(subnet, strict=False)
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
        answered, _ = srp(packet, timeout=3, verbose=False)
        for sent, received in answered:
            discovered.append({
                "ip": received.psrc,
                "mac": received.hwsrc.upper(),
                "hostname": _reverse_dns(received.psrc),
            })
    except ImportError:
        # Fall back to arp -a (reads existing ARP cache)
        log.info("scapy not available, using arp -a cache")
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0].strip("()")
                    mac = parts[1] if len(parts) > 1 else ""
                    if _is_valid_ip(ip):
                        discovered.append({
                            "ip": ip,
                            "mac": mac.upper().replace("-", ":"),
                            "hostname": _reverse_dns(ip),
                        })
        except Exception as e:
            log.warning(f"arp scan failed: {e}")
    return discovered


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def _is_valid_ip(s: str) -> bool:
    try:
        parts = s.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


# ── Pi-hole stats ──────────────────────────────────────────────────────────

def get_pihole_stats(pihole_ip: str, api_token: str) -> dict:
    """Poll Pi-hole API v5/v6 for summary stats."""
    try:
        # Pi-hole v5 API
        url = f"http://{pihole_ip}/admin/api.php?summary&auth={api_token}"
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        data = r.json()
        return {
            "dns_queries_today": data.get("dns_queries_today", 0),
            "ads_blocked_today": data.get("ads_blocked_today", 0),
            "ads_percentage": round(float(data.get("ads_percentage_today", 0)), 1),
            "domains_blocked": data.get("domains_being_blocked", 0),
            "status": data.get("status", "unknown"),
        }
    except Exception as e:
        log.warning(f"Pi-hole API error ({pihole_ip}): {e}")
        return {}


# ── Alerts ─────────────────────────────────────────────────────────────────

def send_alert_email(subject: str, body: str):
    if not ALERTS_ENABLED or not ALERT_EMAIL_FROM:
        return
    try:
        site = get_site_id()
        # Use Graph API to send mail
        url = f"{GRAPH_BASE}/users/{ALERT_EMAIL_FROM}/sendMail"
        payload = {
            "message": {
                "subject": subject,
                "body": {"contentType": "Text", "content": body},
                "toRecipients": [{"emailAddress": {"address": ALERT_EMAIL_TO}}],
            }
        }
        r = requests.post(url, headers=hdrs(), json=payload)
        if r.status_code == 202:
            log.info(f"Alert email sent: {subject}")
        else:
            log.warning(f"Alert email failed: {r.status_code} {r.text}")
    except Exception as e:
        log.warning(f"send_alert_email error: {e}")


# ── GitHub Pages Data Export ───────────────────────────────────────────────

def _gh_headers():
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _gh_get_sha(path):
    """Return (sha, exists) for a file on the gh-pages branch."""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{path}?ref={GITHUB_BRANCH}"
    r = requests.get(url, headers=_gh_headers(), timeout=10)
    if r.status_code == 200:
        return r.json().get("sha"), True
    return None, False


def _gh_put(path, content_str, commit_msg):
    """Create or update a file on the gh-pages branch."""
    import base64
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{path}"
    sha, exists = _gh_get_sha(path)
    payload = {
        "message": commit_msg,
        "content": base64.b64encode(content_str.encode()).decode(),
        "branch": GITHUB_BRANCH,
    }
    if sha:
        payload["sha"] = sha
    r = requests.put(url, headers=_gh_headers(), json=payload, timeout=15)
    return r.status_code in (200, 201)


def publish_to_github(client_fields, devices, events):
    """Push client JSON data to gh-pages/data/ for the static PWA."""
    if not GITHUB_TOKEN:
        return
    client_code = client_fields.get("ClientCode", "UNKNOWN")
    now_iso = datetime.datetime.utcnow().isoformat() + "Z"

    # ── 1. Client-specific data file ─────────────────────────────────────
    client_json = json.dumps({
        "client":  client_fields,
        "devices": devices,
        "events":  sorted(events, key=lambda e: e.get("EventTime",""), reverse=True)[:100],
        "updated": now_iso,
    }, default=str, indent=2)

    path = f"{GITHUB_DATA_DIR}/{client_code}.json"
    if _gh_put(path, client_json, f"agent: {client_code} data {now_iso[:16]}"):
        log.info(f"GitHub: published {path}")
    else:
        log.warning(f"GitHub: failed to publish {path}")

    # ── 2. Update clients index (clients.json) ────────────────────────────
    idx_path = f"{GITHUB_DATA_DIR}/clients.json"
    sha, exists = _gh_get_sha(idx_path)
    existing = []
    if exists:
        import base64
        r = requests.get(
            f"https://api.github.com/repos/{GITHUB_REPO}/contents/{idx_path}?ref={GITHUB_BRANCH}",
            headers=_gh_headers(), timeout=10)
        if r.status_code == 200:
            try:
                existing = json.loads(base64.b64decode(r.json()["content"]).decode())
            except Exception:
                existing = []
    # Upsert this client's summary
    summary = {k: client_fields.get(k) for k in
        ("ClientCode","Title","GatewayIP","Subnet","LogoUrl","QuickLinksJson","PortalKey")}
    summary["updated"] = now_iso
    existing = [c for c in existing if c.get("ClientCode") != client_code]
    existing.append(summary)
    if _gh_put(idx_path, json.dumps(existing, default=str, indent=2),
               f"agent: update clients index"):
        log.info("GitHub: clients.json updated")


# ── Core agent logic ───────────────────────────────────────────────────────

def run_cycle(client_code: str, force_discover: bool = False):
    log.info(f"=== Cycle start: {client_code} ===")
    now = datetime.datetime.utcnow().isoformat() + "Z"

    # 1. Load client config from SharePoint
    clients = sp_get(LIST_CLIENTS, f"fields/ClientCode eq '{client_code}'")
    if not clients:
        log.error(f"Client '{client_code}' not found in {LIST_CLIENTS}")
        return
    client = clients[0]["fields"]
    subnet     = client.get("Subnet", "")
    pihole_ip  = client.get("PiholeIP", "")
    pihole_tok = client.get("PiholeToken", "")

    # 2. Load known devices for this client
    devices = sp_get(LIST_DEVICES, f"fields/ClientCode eq '{client_code}'")
    log.info(f"  Loaded {len(devices)} known devices")

    known_ips = {d["fields"].get("IPAddress"): d for d in devices}

    # 3. Ping known devices
    status_changes = []
    for item in devices:
        fields = item["fields"]
        ip     = fields.get("IPAddress", "").strip()
        name   = fields.get("Title", ip)
        if not ip:
            continue

        prev_status = fields.get("Status", "Unknown")
        alive, avg_ms = ping(ip)
        new_status = "Online" if alive else "Offline"

        update_fields = {
            "Status":        new_status,
            "ResponseMsAvg": round(avg_ms, 1),
        }
        if alive:
            update_fields["LastSeen"] = now

        sp_update(LIST_DEVICES, item["id"], update_fields)

        if prev_status != new_status:
            log.info(f"  STATUS CHANGE: {name} ({ip})  {prev_status} → {new_status}")
            status_changes.append({
                "device": name, "ip": ip,
                "old": prev_status, "new": new_status,
                "item_id": item["id"],
            })

            # Log event
            sp_create(LIST_EVENTS, {
                "Title":       f"{client_code}-{name} went {new_status}",
                "ClientCode":  client_code,
                "DeviceTitle": name,
                "EventType":   "StatusChange",
                "OldStatus":   prev_status,
                "NewStatus":   new_status,
                "EventTime":   now,
                "IsResolved":  new_status == "Online",
                "AlertSent":   False,
                "Details":     f"IP: {ip}  Avg latency: {avg_ms:.1f}ms",
            })

            # Send email alert for offline events
            if new_status == "Offline":
                send_alert_email(
                    f"[ATS ALERT] {client_code} — {name} is OFFLINE",
                    f"Device: {name}\nIP: {ip}\nClient: {client_code}\nTime (UTC): {now}\n\n"
                    f"Previous status: {prev_status}\nCheck the ATS dashboard for details.",
                )

    # 4. ARP scan for new devices
    if (ARP_SCAN_ENABLED or force_discover) and subnet:
        log.info(f"  ARP scanning {subnet}...")
        found = arp_scan(subnet)
        for host in found:
            if host["ip"] not in known_ips:
                log.info(f"  NEW DEVICE: {host['ip']} ({host['mac']}) {host['hostname']}")
                sp_create(LIST_DEVICES, {
                    "Title":       host["hostname"] or host["ip"],
                    "ClientCode":  client_code,
                    "IPAddress":   host["ip"],
                    "MACAddress":  host["mac"],
                    "Status":      "Online",
                    "LastSeen":    now,
                    "DeviceType":  "Other",
                    "Notes":       "Auto-discovered by ATS agent",
                })
                sp_create(LIST_EVENTS, {
                    "Title":       f"New device discovered: {host['ip']}",
                    "ClientCode":  client_code,
                    "DeviceTitle": host["hostname"] or host["ip"],
                    "EventType":   "NewDevice",
                    "NewStatus":   "Online",
                    "EventTime":   now,
                    "IsResolved":  True,
                    "Details":     f"MAC: {host['mac']}  Hostname: {host['hostname']}",
                })

    # 5. Pi-hole stats
    if PIHOLE_API_ENABLED and pihole_ip:
        log.info(f"  Polling Pi-hole at {pihole_ip}...")
        stats = get_pihole_stats(pihole_ip, pihole_tok)
        if stats:
            # Store stats in the Pi-hole device row (DeviceType=RPi/Portal)
            pihole_devices = [
                d for d in devices
                if d["fields"].get("IPAddress") == pihole_ip
            ]
            if pihole_devices:
                sp_update(LIST_DEVICES, pihole_devices[0]["id"], {
                    "Notes": (
                        f"Pi-hole | Queries today: {stats['dns_queries_today']} | "
                        f"Blocked: {stats['ads_blocked_today']} ({stats['ads_percentage']}%) | "
                        f"Status: {stats['status']} | Updated: {now}"
                    )
                })
            log.info(f"  Pi-hole: {stats['ads_blocked_today']} ads blocked today ({stats['ads_percentage']}%)")

    log.info(f"=== Cycle done: {len(status_changes)} status changes ===\n")

    # ── 6. Publish to GitHub Pages (static JSON for PWA) ──────────────────
    try:
        # Re-fetch devices and events for publish (includes updates from this cycle)
        pub_devices = sp_get(LIST_DEVICES, f"fields/ClientCode eq '{client_code}'")
        pub_events  = sp_get(LIST_EVENTS,  f"fields/ClientCode eq '{client_code}'")
        pub_devices_fields = [d["fields"] for d in pub_devices]
        pub_events_fields  = [e["fields"] for e in pub_events]
        publish_to_github(client, pub_devices_fields, pub_events_fields)
    except Exception as e:
        log.warning(f"GitHub publish error: {e}")


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ATS Network Monitor Agent")
    parser.add_argument("--client",   required=True, help="Client code (e.g. AMBIT)")
    parser.add_argument("--once",     action="store_true", help="Run one cycle and exit")
    parser.add_argument("--discover", action="store_true", help="Force ARP scan")
    args = parser.parse_args()

    if args.once or args.discover:
        run_cycle(args.client, force_discover=args.discover)
    else:
        # Continuous mode (fall back if Task Scheduler isn't configured)
        import time as _time
        from config import SCAN_INTERVAL_MIN
        while True:
            try:
                run_cycle(args.client)
            except Exception as e:
                log.error(f"Cycle error: {e}", exc_info=True)
            _time.sleep(SCAN_INTERVAL_MIN * 60)


if __name__ == "__main__":
    main()
