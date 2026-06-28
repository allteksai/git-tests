"""
ATS Network Monitor — Central Configuration
============================================
All tenant-specific values live here.
To rebrand (e.g. sdausa → atsusa), update SHAREPOINT_TENANT_NAME below.
Everything else reads from this file — agent, backup, and PWA env vars.

Setup:
  1. Register an App in Azure AD (see docs/azure-app-setup.md)
  2. Fill in CLIENT_ID, CLIENT_SECRET, TENANT_ID
  3. Update SHAREPOINT_TENANT_NAME to match your M365 URL
  4. Run: python sharepoint-setup/create_lists.py
"""

# ── Azure AD App Registration ──────────────────────────────────────────────
# App needs SharePoint permissions: Sites.ReadWrite.All, Files.ReadWrite.All
TENANT_ID     = "30d5f620-b716-466d-abc9-53d4bd3710cd"          # Azure AD tenant ID (GUID)
CLIENT_ID     = "fa19ca7f-d44b-49bf-ac2b-da5911f9c42a"          # App registration client ID
CLIENT_SECRET = "OEk8Q~LbmQ99J2a6RelwysX-sZPtPxzmC.Jkkb-O"      # App registration client secret

# ── SharePoint ─────────────────────────────────────────────────────────────
# Change this ONE line when rebranding sdausa → atsusa (or any future rename)
SHAREPOINT_TENANT_NAME = "atsusa"         # e.g. atsusa → atsusa.sharepoint.com
SHAREPOINT_SITE_NAME   = "ATSNetMonitor"  # SharePoint site name (create once)

# Derived URLs — do not edit these directly
SHAREPOINT_HOST     = f"{SHAREPOINT_TENANT_NAME}.sharepoint.com"
SHAREPOINT_SITE_URL = f"https://{SHAREPOINT_HOST}/sites/{SHAREPOINT_SITE_NAME}"
GRAPH_BASE          = "https://graph.microsoft.com/v1.0"

# ── SharePoint List Names ──────────────────────────────────────────────────
LIST_CLIENTS  = "ATS_Clients"
LIST_DEVICES  = "ATS_Devices"
LIST_EVENTS   = "ATS_Events"
DOCLIB_NAME   = "ATS_DeviceFiles"

# ── Agent Behavior ─────────────────────────────────────────────────────────
PING_COUNT        = 2       # ICMP pings per device per cycle
PING_TIMEOUT_SEC  = 1       # seconds to wait per ping
SCAN_INTERVAL_MIN = 5       # how often the agent runs (via Task Scheduler / cron)
ARP_SCAN_ENABLED  = True    # discover new devices on subnet automatically
ALERT_ON_DOWN_MIN = 10      # alert if device offline > N minutes

# ── Backup Settings ────────────────────────────────────────────────────────
BACKUP_SCHEDULE   = "02:00"     # daily backup time (local to agent machine)
BACKUP_KEEP_DAYS  = 90          # retain configs for N days in SharePoint
SSH_TIMEOUT_SEC   = 15

# ── Pi-hole Integration (optional per site) ────────────────────────────────
# Set per-client in the ATS_Clients SharePoint list (PiholeIP field)
# Agent reads that field and polls the Pi-hole API automatically
PIHOLE_API_ENABLED = True
PIHOLE_STATS_INTERVAL_MIN = 15   # how often to pull Pi-hole stats

# ── Notification (optional) ───────────────────────────────────────────────
# Email alerts via Microsoft Graph (uses same app registration above)
ALERT_EMAIL_TO    = "martianable@gmail.com"
ALERT_EMAIL_FROM  = ""          # your M365 mailbox (e.g. marty@atsusa.com)
ALERTS_ENABLED    = True

# ── GitHub Pages Data Export ───────────────────────────────────────────────
# After each scan cycle, agent pushes JSON data files to gh-pages branch.
# The PWA reads these static files instead of calling SharePoint directly.
# Create a GitHub PAT at: https://github.com/settings/tokens
#   Permissions needed: Contents (read & write) on the ats-network-monitor repo
GITHUB_TOKEN      = "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"          # ← paste your GitHub PAT here
GITHUB_REPO       = "allteksai/ats-network-monitor"
GITHUB_BRANCH     = "gh-pages"
GITHUB_DATA_DIR   = "data"      # files written to /data/ on the branch
