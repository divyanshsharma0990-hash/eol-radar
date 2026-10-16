"""EOL Radar - end-of-life / end-of-support lookup (part of the VulnPulse suite).

Public data only: endoflife.date API. No asset or internal data is needed.
"""
import base64
import difflib
import html
import io
import re
from datetime import date, datetime
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
st.set_page_config(page_title="EOL Radar | Lifecycle Check", page_icon="📡", layout="wide")

API = "https://endoflife.date/api"
APPROACH_DAYS = 90

SUITE = [
    ("VulnPulse", "https://vulnpulse-intel-app.streamlit.app/", "fa-heart-pulse"),
    ("Risk Calc", "https://div-cve-risk-calc.streamlit.app/", "fa-calculator"),
    ("PatchPilot", "https://patchpilot.streamlit.app/", "fa-paper-plane"),
]
LINKEDIN = "https://www.linkedin.com/in/divyansh-sharma-8113b5113"

# Official lifecycle pages (shown for vendors endoflife.date covers thinly)
VENDOR_LINKS = {
    "Microsoft": "https://learn.microsoft.com/lifecycle/",
    "Cisco": "https://www.cisco.com/c/en/us/products/eos-eol-listing.html",
    "Palo Alto": "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary",
    "VMware / Broadcom": "https://lifecycle.vmware.com/",
    "Juniper": "https://support.juniper.net/support/eol/",
    "Check Point": "https://www.checkpoint.com/support-services/support-life-cycle-policy/",
    "F5": "https://support.f5.com/csp/article/K5903",
}

# normalised name -> (endoflife.date slug, version prefix to prepend)
ALIASES = {
    "windows-server": ("windows-server", ""),
    "win-server": ("windows-server", ""),
    "windows-10": ("windows", "10"),
    "windows-11": ("windows", "11"),
    "esxi": ("esxi", ""),
    "vmware-esxi": ("esxi", ""),
    "ubuntu": ("ubuntu", ""),
    "debian": ("debian", ""),
    "rhel": ("rhel", ""),
    "red-hat-enterprise-linux": ("rhel", ""),
    "centos": ("centos", ""),
    "almalinux": ("almalinux", ""),
    "rocky-linux": ("rocky-linux", ""),
    "oracle-linux": ("oracle-linux", ""),
    "sles": ("sles", ""),
    "amazon-linux": ("amazon-linux", ""),
    "macos": ("macos", ""),
    "mysql": ("mysql", ""),
    "postgresql": ("postgresql", ""),
    "postgres": ("postgresql", ""),
    "mariadb": ("mariadb", ""),
    "mongodb": ("mongodb", ""),
    "redis": ("redis", ""),
    "nginx": ("nginx", ""),
    "tomcat": ("tomcat", ""),
    "python": ("python", ""),
    "nodejs": ("nodejs", ""),
    "node-js": ("nodejs", ""),
    "php": ("php", ""),
    "dotnet": ("dotnet", ""),
    "kubernetes": ("kubernetes", ""),
}

# endoflife.date slug -> (vendor, plain product name, type). Shown in tables so anyone can read them.
PRODUCT_INFO = {
    "windows": ("Microsoft", "Windows", "Operating System"),
    "windows-server": ("Microsoft", "Windows Server", "Operating System"),
    "esxi": ("VMware (Broadcom)", "ESXi", "Hypervisor / OS"),
    "ubuntu": ("Canonical", "Ubuntu", "Operating System"),
    "debian": ("Debian Project", "Debian", "Operating System"),
    "rhel": ("Red Hat", "Red Hat Enterprise Linux", "Operating System"),
    "centos": ("CentOS Project", "CentOS", "Operating System"),
    "almalinux": ("AlmaLinux OS Foundation", "AlmaLinux", "Operating System"),
    "rocky-linux": ("Rocky Enterprise Software Foundation", "Rocky Linux", "Operating System"),
    "oracle-linux": ("Oracle", "Oracle Linux", "Operating System"),
    "sles": ("SUSE", "SUSE Linux Enterprise Server", "Operating System"),
    "amazon-linux": ("Amazon (AWS)", "Amazon Linux", "Operating System"),
    "macos": ("Apple", "macOS", "Operating System"),
    "mysql": ("Oracle", "MySQL", "Database"),
    "postgresql": ("PostgreSQL Global Development Group", "PostgreSQL", "Database"),
    "mariadb": ("MariaDB Foundation", "MariaDB", "Database"),
    "mongodb": ("MongoDB Inc.", "MongoDB", "Database"),
    "redis": ("Redis Ltd.", "Redis", "Database"),
    "nginx": ("F5 (NGINX)", "NGINX", "Web server"),
    "tomcat": ("Apache Software Foundation", "Apache Tomcat", "Application server"),
    "python": ("Python Software Foundation", "Python", "Programming runtime"),
    "nodejs": ("OpenJS Foundation", "Node.js", "Programming runtime"),
    "php": ("The PHP Group", "PHP", "Programming runtime"),
    "dotnet": ("Microsoft", ".NET", "Programming runtime"),
    "kubernetes": ("CNCF (Kubernetes)", "Kubernetes", "Container platform"),
}

# Windows edition codes used by endoflife.date
WIN_EDITION = {
    "e": "Enterprise/Education",
    "w": "Home/Pro",
    "e-lts": "Enterprise LTSC",
    "iot-lts": "IoT Enterprise LTSC",
    "lts": "LTSC",
}

STATUS_COLOR = {
    "Supported": "#22c55e",
    "Security-only": "#38bdf8",
    "Approaching EOL": "#f59e0b",
    "EOL": "#ef4444",
    "Not found": "#94a3b8",
}

STATUS_ADVICE = {
    "EOL": (
        "No more security patches. Every new CVE stays open permanently.",
        "Upgrade to a supported release; if not possible now, isolate from the internet, "
        "restrict network access, use virtual patching (IPS/WAF) and ask the vendor about paid extended support.",
    ),
    "Approaching EOL": (
        "Patches stop soon. Plan the upgrade before the date or risk going unpatched.",
        "Raise a change/upgrade plan now, schedule testing, and budget for extended support as a fallback.",
    ),
    "Security-only": (
        "Only security fixes are shipped. No bug fixes or new features.",
        "Keep patching monthly and start planning the move to a fully supported release.",
    ),
    "Supported": (
        "Still receives vendor fixes.",
        "Keep patching on your normal cycle. Re-check this version before its end-of-life date.",
    ),
    "Not found": (
        "Could not match this product/version in the data source.",
        "Check the vendor's official lifecycle page (links in the FAQ tab).",
    ),
}

# Column names used everywhere (plain English, so non-technical readers can follow)
C_VENDOR, C_PRODUCT, C_TYPE, C_VERSION = "Vendor", "OS / Product", "Type", "Version"
C_RELDATE, C_LATEST = "Release date", "Latest version"
C_SUPPORT, C_EOL, C_EXT = "Full support ends", "Security updates end (EOL)", "Paid extended support"
C_LEFT, C_STATUS, C_UPGRADE, C_NOTE = "Time left", "Status", "Upgrade to", "Note"

# ----------------------------------------------------------------------------
# Look & feel (same suite style: full page, bg.jpeg, glass cards, By Div footer)
# ----------------------------------------------------------------------------
def bg_image() -> str:
    p = Path(__file__).parent / "bg.jpeg"
    if p.exists():
        b64 = base64.b64encode(p.read_bytes()).decode()
        return f"url('data:image/jpeg;base64,{b64}')"
    return "linear-gradient(135deg,#050b1f,#0a1f44 55%,#06122b)"


CSS = """
<style>
@import url('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css');
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html, body, [class*="css"], .stApp { font-family: 'Inter', 'Segoe UI', sans-serif; }
.stApp {
  background: linear-gradient(rgba(4,10,28,.80), rgba(4,10,28,.88)), __BG__;
  background-size: cover; background-position: center; background-attachment: fixed;
  color: #f1f6ff;
}
header[data-testid="stHeader"], #MainMenu, footer { display: none !important; }
.block-container { max-width: 100% !important; padding: 1rem 2.2rem 4.2rem !important; }
.stApp p, .stApp label, .stApp li, .stApp span { color: #f1f6ff; }
.stApp label p { font-weight: 600; font-size: .95rem; }
.topbar { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:.6rem;
  padding:.7rem 1.1rem; margin-bottom:.9rem; border-radius:14px;
  background: rgba(8,20,48,.72); border:1px solid rgba(80,160,255,.28); backdrop-filter: blur(6px); }
.brand { font-size:1.45rem; font-weight:700; color:#fff; }
.brand i { color:#38bdf8; margin-right:.5rem; }
.brand small { font-size:.82rem; font-weight:400; color:#bcd2f3; margin-left:.6rem; }
.nav a { color:#cfe3ff !important; text-decoration:none; margin-left:.5rem; padding:.35rem .8rem;
  border:1px solid rgba(80,160,255,.35); border-radius:999px; font-size:.86rem; display:inline-block; }
.nav a:hover { background: rgba(56,189,248,.18); border-color:#38bdf8; }
.nav a i { margin-right:.4rem; color:#38bdf8; }
.card { background: rgba(6,16,40,.84); border:1px solid rgba(80,160,255,.25);
  border-radius:14px; padding:.9rem 1.1rem; margin:.5rem 0; backdrop-filter: blur(6px); }
.card h4 { margin:0 0 .5rem 0; color:#fff; font-size:1.02rem; }
.card h4 i { color:#38bdf8; margin-right:.45rem; }
table.t { width:100%; border-collapse:collapse; font-size:.93rem; }
table.t th { text-align:left; background: #12305f; color:#ffffff; font-weight:600; padding:.5rem .65rem;
  border-bottom:1px solid rgba(80,160,255,.35); position:sticky; top:0; }
table.t td { padding:.4rem .6rem; border-bottom:1px solid rgba(80,160,255,.14); vertical-align:top; color:#f1f6ff; }
table.t td.l { color:#bcd2f3; white-space:nowrap; width:1%; }
table.t tr:hover td { background: rgba(56,189,248,.06); }
table.t a { color:#8fdcff !important; }
.badge { display:inline-block; padding:.12rem .6rem; border-radius:999px; font-weight:600; font-size:.8rem; color:#04101f; }
.stats { display:flex; gap:.6rem; flex-wrap:wrap; margin:.4rem 0; }
.stat { flex:1 1 120px; padding:.55rem .8rem; border-radius:12px; background: rgba(6,16,40,.84);
  border:1px solid rgba(80,160,255,.25); }
.stat b { font-size:1.35rem; display:block; color:#fff; }
.stat span { font-size:.85rem; color:#bcd2f3; }
.scroll { max-height: 430px; overflow:auto; border-radius:10px; }
[data-testid="stTextInputRootElement"], [data-testid="stTextInputRootElement"] > div,
[data-testid="stTextAreaRootElement"], [data-testid="stTextAreaRootElement"] > div,
div[data-baseweb="input"], div[data-baseweb="base-input"], div[data-baseweb="textarea"],
.stSelectbox div[data-baseweb="select"] > div {
  background: #0a1a3a !important; background-color: #0a1a3a !important;
  border-color: rgba(120,180,255,.55) !important; border-radius: 10px !important; }
[data-testid="stTextInputRootElement"]:focus-within, div[data-baseweb="input"]:focus-within,
div[data-baseweb="base-input"]:focus-within, div[data-baseweb="textarea"]:focus-within {
  border-color: #38bdf8 !important; box-shadow: 0 0 0 2px rgba(56,189,248,.35) !important; }
.stTextInput input, .stTextArea textarea {
  background: transparent !important; color: #f8fbff !important; -webkit-text-fill-color: #f8fbff !important;
  caret-color: #fff; font-size: 1rem !important; }
.stTextInput input:-webkit-autofill, .stTextInput input:-webkit-autofill:hover, .stTextInput input:-webkit-autofill:focus {
  -webkit-box-shadow: 0 0 0 1000px #0a1a3a inset !important; -webkit-text-fill-color: #f8fbff !important; }
.stTextInput input::placeholder, .stTextArea textarea::placeholder {
  color: #9fbbe6 !important; -webkit-text-fill-color: #9fbbe6 !important; opacity: 1 !important; }
[data-testid="stFileUploader"] section, [data-testid="stFileUploaderDropzone"] {
  background: #0a1a3a !important; border: 1.5px dashed rgba(120,180,255,.65) !important; border-radius: 12px !important; }
[data-testid="stFileUploaderDropzone"] *, [data-testid="stFileUploader"] small, [data-testid="stFileUploader"] span {
  color: #e6f0ff !important; }
[data-testid="stFileUploaderDropzone"] small { color: #9fbbe6 !important; }
[data-testid="stFileUploaderDropzone"] button, [data-testid="stFileUploader"] button {
  background: linear-gradient(90deg,#0ea5e9,#2563eb) !important; color: #fff !important; border: 0 !important;
  border-radius: 10px !important; font-weight: 600 !important; }
[data-testid="stFileUploaderDropzone"] button *, [data-testid="stFileUploader"] button * { color: #fff !important; }
[data-testid="stFileUploaderFile"], [data-testid="stFileUploaderFile"] * { color: #f1f6ff !important; }
[data-testid="stFileUploaderDropzone"] svg { fill: #8fdcff !important; color: #8fdcff !important; }
[data-testid="stFileUploader"], [data-testid="stFileUploader"] div, [data-testid="stFileUploader"] section,
[data-testid="stFileUploader"] small { background-color: #0a1a3a !important; }
[data-testid="stFileUploader"] section { border: 1.5px dashed rgba(120,180,255,.65) !important; border-radius: 12px !important; }
[data-testid="stFileUploader"] button { background: linear-gradient(90deg,#0ea5e9,#2563eb) !important; color:#fff !important; border:0 !important; }
[data-testid="stFileUploader"] button * { background: transparent !important; color:#fff !important; }
.stButton > button, .stDownloadButton > button { background: linear-gradient(90deg,#0ea5e9,#2563eb); color:#fff;
  border:0; border-radius:10px; font-weight:600; }
.stButton > button:hover, .stDownloadButton > button:hover { filter:brightness(1.12); color:#fff; }
button[data-baseweb="tab"] { color:#bcd2f3 !important; font-weight:600; }
button[data-baseweb="tab"][aria-selected="true"] { color:#fff !important; }
div[data-testid="stExpander"] { background: rgba(6,16,40,.84); border:1px solid rgba(80,160,255,.25); border-radius:12px; }
div[data-testid="stExpander"] summary p { color:#fff; font-weight:600; }
.foot { position:fixed; left:0; right:0; bottom:0; z-index:99; text-align:center; padding:.5rem;
  background: rgba(4,10,28,.88); border-top:1px solid rgba(80,160,255,.25); font-size:.9rem; color:#bcd2f3; }
.foot a { color:#38bdf8 !important; margin-left:.45rem; font-size:1.15rem; vertical-align:middle; }
@media (max-width: 700px) { .block-container { padding: .6rem .7rem 4rem !important; } .brand small { display:none; } }
</style>
"""


def esc(x) -> str:
    return html.escape("" if x is None else str(x))


def badge(status: str) -> str:
    return f'<span class="badge" style="background:{STATUS_COLOR.get(status, "#94a3b8")}">{esc(status)}</span>'


def table(headers, rows, label_first=False) -> str:
    """Build an HTML table on a single line (no indentation, so markdown won't treat it as code)."""
    head = "".join(f"<th>{esc(h)}</th>" for h in headers) if headers else ""
    body = ""
    for r in rows:
        cells = ""
        for i, c in enumerate(r):
            cls = ' class="l"' if (label_first and i % 2 == 0) else ""
            cells += f"<td{cls}>{c}</td>"
        body += f"<tr>{cells}</tr>"
    thead = f"<thead><tr>{head}</tr></thead>" if headers else ""
    return f'<table class="t">{thead}<tbody>{body}</tbody></table>'


def card(title: str, icon: str, inner: str) -> str:
    return f'<div class="card"><h4><i class="fa-solid {icon}"></i>{esc(title)}</h4>{inner}</div>'


# ----------------------------------------------------------------------------
# Data layer
# ----------------------------------------------------------------------------
def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")


@st.cache_data(ttl=6 * 3600, show_spinner=False)
def all_products():
    try:
        r = requests.get(f"{API}/all.json", timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception:
        return []


@st.cache_data(ttl=6 * 3600, show_spinner=False)
def release_data(slug: str):
    try:
        r = requests.get(f"{API}/{slug}.json", timeout=15)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def resolve(name: str):
    """Return (slug or None, version prefix, suggestions)."""
    n = norm(name)
    if n in ALIASES:
        slug, pre = ALIASES[n]
        return slug, pre, []
    prods = all_products()
    if n in prods:
        return n, "", []
    hits = [p for p in prods if n and (n in p or p in n)]
    close = difflib.get_close_matches(n, prods, n=5, cutoff=0.6)
    sugg = list(dict.fromkeys(hits[:5] + close))
    return None, "", sugg


def product_info(slug: str):
    """(vendor, plain product name, type) for a slug; falls back gracefully for unknown products."""
    if slug in PRODUCT_INFO:
        return PRODUCT_INFO[slug]
    return "Not listed", slug.replace("-", " ").title(), "Software"


def friendly_version(slug: str, c: dict) -> str:
    """Turn the raw release code (e.g. '11-26h2-e') into something a non-technical reader understands."""
    cyc = str(c.get("cycle", ""))
    if slug == "windows":
        parts = cyc.split("-")
        major, rest = parts[0], parts[1:]
        build = ""
        if rest and re.match(r"^(\d{2}h\d|\d{4})$", rest[0], re.I):
            build, rest = rest[0].upper(), rest[1:]
        edition = ""
        if rest:
            key = "-".join(rest).lower()
            edition = WIN_EDITION.get(key, " ".join(rest).upper())
        text = " ".join(x for x in [major, build] if x)
        return text + (f" ({edition})" if edition else "")
    words = [w.upper() if re.match(r"^(r|sp)\d+$", w, re.I) else w for w in cyc.split("-")]
    return " ".join(words) + (" (LTS)" if c.get("lts") else "")


def split_free_text(text: str):
    """'Windows Server 2012 R2' -> ('windows server', '2012 r2') using known aliases."""
    n = norm(text)
    for key in sorted(ALIASES, key=len, reverse=True):
        if n == key or n.startswith(key + "-"):
            return key, n[len(key):].strip("-")
    parts = text.rsplit(" ", 1)
    return (parts[0], parts[1]) if len(parts) == 2 else (text, "")


def match_cycle(data, version: str):
    v = norm(str(version).lstrip("vV"))
    if not v:
        return None
    cs = [(norm(c.get("cycle", "")), c) for c in data]
    for k, c in cs:
        if k == v:
            return c
    pref = sorted([(k, c) for k, c in cs if k and v.startswith(k + "-")], key=lambda x: -len(x[0]))
    if pref:
        return pref[0][1]
    for k, c in cs:
        if k.startswith(v):
            return c
    return None


def parse_d(x):
    if isinstance(x, str):
        try:
            return datetime.strptime(x[:10], "%Y-%m-%d").date()
        except ValueError:
            return None
    return None


def lifecycle(c: dict) -> dict:
    today = date.today()
    eol, sup = c.get("eol"), c.get("support")
    ed, sd = parse_d(eol), parse_d(sup)
    if ed:
        d = (ed - today).days
        if d < 0:
            return dict(status="EOL", days=d, text=f"Ended {-d} days ago", eol_date=ed)
        if d <= APPROACH_DAYS:
            return dict(status="Approaching EOL", days=d, text=f"{d} days left", eol_date=ed)
        if sd and sd < today:
            return dict(status="Security-only", days=d, text=f"{d} days to EOL", eol_date=ed)
        return dict(status="Supported", days=d, text=f"{d} days to EOL", eol_date=ed)
    if eol is True:
        return dict(status="EOL", days=None, text="Ended (date not published)", eol_date=None)
    if sd and sd < today:
        return dict(status="Security-only", days=None, text="No EOL date announced", eol_date=None)
    return dict(status="Supported", days=None, text="No EOL date announced", eol_date=None)


def date_text(v, ended_if_true=True) -> str:
    """Support/EOL field -> readable text."""
    if isinstance(v, str):
        return v
    if v is True and ended_if_true:
        return "Ended"
    return "-"


def upgrade_target(slug: str, data) -> str:
    supported = []
    for wanted in ("Supported", "Security-only", "Approaching EOL"):  # best available choice first
        supported = [c for c in data if lifecycle(c)["status"] == wanted]
        if supported:
            break
    if not supported:
        return "-"
    lts = [c for c in supported if c.get("lts")]
    pick = (lts or supported)[0]
    _, name, _ = product_info(slug)
    latest = pick.get("latest")
    return f"{name} {friendly_version(slug, pick)}" + (f" (latest version {latest})" if latest else "")


def check(product: str, version: str) -> dict:
    """One product+version -> flat result dict (used by lookup and bulk)."""
    base = {C_VENDOR: "-", C_PRODUCT: product, C_TYPE: "-", C_VERSION: version or "-", C_STATUS: "Not found",
            C_RELDATE: "-", C_LATEST: "-", C_SUPPORT: "-", C_EOL: "-", C_EXT: "-", C_LEFT: "-",
            C_UPGRADE: "-", C_NOTE: ""}
    slug, pre, sugg = resolve(product)
    if not slug:
        base[C_NOTE] = ("Did you mean: " + ", ".join(sugg)) if sugg else "Product not in data source"
        return base
    vendor, name, kind = product_info(slug)
    base.update({C_VENDOR: vendor, C_PRODUCT: name, C_TYPE: kind})
    data = release_data(slug)
    if not data:
        base[C_NOTE] = "Data source unavailable"
        return base
    if not str(version).strip():
        base[C_NOTE] = "No version given. Use the Lookup tab with an empty version to list all versions"
        return base
    ver = f"{pre}-{version}".strip("-") if pre else version
    c = match_cycle(data, ver)
    if not c:
        known = ", ".join(friendly_version(slug, x) for x in data[:8])
        base[C_NOTE] = f"Version not matched. Known versions: {known}"
        return base
    lc = lifecycle(c)
    ext = c.get("extendedSupport")
    base.update({
        C_STATUS: lc["status"],
        C_VERSION: friendly_version(slug, c),
        C_RELDATE: str(c.get("releaseDate") or "-"),
        C_LATEST: str(c.get("latest") or "-"),
        C_SUPPORT: date_text(c.get("support")),
        C_EOL: str(lc["eol_date"]) if lc["eol_date"] else ("Ended" if c.get("eol") is True else "n/a"),
        C_EXT: str(ext) if isinstance(ext, str) else "-",
        C_LEFT: lc["text"],
        C_UPGRADE: upgrade_target(slug, data) if lc["status"] != "Supported" else "Already on a supported version",
        C_NOTE: "", "_slug": slug,
    })
    return base


# ----------------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------------
st.markdown(CSS.replace("__BG__", bg_image()), unsafe_allow_html=True)

nav = "".join(
    f'<a href="{u}" target="_blank"><i class="fa-solid {ic}"></i>{n}</a>' for n, u, ic in SUITE
)
st.markdown(
    f'<div class="topbar"><div class="brand"><i class="fa-solid fa-satellite-dish"></i>EOL Radar'
    f'<small>End-of-life and end-of-support check, public data only</small></div>'
    f'<div class="nav">{nav}</div></div>',
    unsafe_allow_html=True,
)

tab_look, tab_bulk, tab_faq = st.tabs(["🔎 Lookup", "📦 Bulk check", "❓ FAQ"])

# ---- Lookup ----------------------------------------------------------------
REL_COLS = [C_VENDOR, C_PRODUCT, C_VERSION, C_RELDATE, C_LATEST, C_SUPPORT, C_EOL, C_EXT, C_STATUS, C_LEFT]


def releases_df(slug: str, data) -> pd.DataFrame:
    vendor, name, _ = product_info(slug)
    rows = []
    for c in data:
        lc = lifecycle(c)
        ext = c.get("extendedSupport")
        rows.append({
            C_VENDOR: vendor,
            C_PRODUCT: name,
            C_VERSION: friendly_version(slug, c),
            C_RELDATE: str(c.get("releaseDate") or "-"),
            C_LATEST: str(c.get("latest") or "-"),
            C_SUPPORT: date_text(c.get("support")),
            C_EOL: str(lc["eol_date"]) if lc["eol_date"] else ("Ended" if c.get("eol") is True else "n/a"),
            C_EXT: str(ext) if isinstance(ext, str) else "-",
            C_STATUS: lc["status"],
            C_LEFT: lc["text"],
        })
    return pd.DataFrame(rows, columns=REL_COLS)


def show_all_releases(product: str):
    """Product only (no version): list every version with its lifecycle status."""
    slug, pre, sugg = resolve(product)
    if not slug:
        msg = ("Did you mean: " + ", ".join(sugg)) if sugg else "Product not found in the data source"
        st.markdown(card("No match", "fa-circle-question", table(None, [[esc(msg)]])), unsafe_allow_html=True)
        return
    data = release_data(slug)
    if not data:
        st.error("Data source unavailable right now. Try again in a minute.")
        return
    if pre:
        data = [c for c in data if norm(c.get("cycle", "")).startswith(norm(pre))] or data
    df = releases_df(slug, data)
    vendor, name, kind = product_info(slug)
    full_name = f"{name} {pre}".strip()

    counts = df[C_STATUS].value_counts()
    stats = "".join(
        f'<div class="stat"><b style="color:{STATUS_COLOR[k]}">{int(counts.get(k, 0))}</b><span>{k}</span></div>'
        for k in ["Supported", "Security-only", "Approaching EOL", "EOL"]
    )
    st.markdown(f'<div class="stats">{stats}</div>', unsafe_allow_html=True)

    f1, f2 = st.columns([4, 1])
    flt = f1.radio("Show", ["All", "Supported", "Security-only", "Approaching EOL", "EOL"],
                   horizontal=True, label_visibility="collapsed", key="rel_filter")
    shown = df if flt == "All" else df[df[C_STATUS] == flt]
    f2.download_button("Download CSV", df.to_csv(index=False).encode(), f"{slug}_versions.csv", "text/csv")

    rows = []
    for _, r in shown.iterrows():
        rows.append([esc(r[c]) if c != C_STATUS else badge(r[c]) for c in REL_COLS])
    if not rows:
        rows = [[esc("No versions with this status")] + [""] * (len(REL_COLS) - 1)]
    inner = (f'<div class="scroll">{table(REL_COLS, rows)}</div>'
             f'<div style="margin-top:.5rem;font-size:.82rem">Source: '
             f'<a href="https://endoflife.date/{esc(slug)}" target="_blank" style="color:#7dd3fc">'
             f'endoflife.date/{esc(slug)}</a>. Type a version above to check just one.</div>')
    title = f"{vendor} {full_name} ({kind}) - EOL status: showing {len(shown)} of {len(df)} versions"
    st.markdown(card(title, "fa-list", inner), unsafe_allow_html=True)


def show_single(product: str, version: str):
    with st.spinner("Checking lifecycle data..."):
        res = check(product, version)
    if res[C_STATUS] == "Not found":
        st.markdown(card("No match", "fa-circle-question", table(None, [[esc(res[C_NOTE])]])),
                    unsafe_allow_html=True)
        return
    rows = [
        [C_VENDOR, esc(res[C_VENDOR]), C_PRODUCT, esc(res[C_PRODUCT])],
        [C_VERSION, esc(res[C_VERSION]), C_STATUS, badge(res[C_STATUS])],
        [C_RELDATE, esc(res[C_RELDATE]), C_LEFT, esc(res[C_LEFT])],
        [C_SUPPORT, esc(res[C_SUPPORT]), C_EOL, esc(res[C_EOL])],
        [C_EXT, esc(res[C_EXT]), C_LATEST, esc(res[C_LATEST])],
        [C_UPGRADE, esc(res[C_UPGRADE]), C_TYPE, esc(res[C_TYPE])],
    ]
    title = f"{res[C_VENDOR]} {res[C_PRODUCT]} {res[C_VERSION]} ({res[C_TYPE]}) - EOL status"
    st.markdown(card(title, "fa-satellite-dish", table(None, rows, label_first=True)),
                unsafe_allow_html=True)

    risk, action = STATUS_ADVICE[res[C_STATUS]]
    with st.expander("Why this status and what to do"):
        st.markdown(table(["Topic", "Detail"], [
            ["Risk", esc(risk)], ["Action", esc(action)],
            ["Check CVEs", f'<a href="{SUITE[0][1]}" target="_blank">VulnPulse</a> for this product'],
            ["Score a CVE", f'<a href="{SUITE[1][1]}" target="_blank">Risk Calc</a>'],
            ["Patch plan", f'<a href="{SUITE[2][1]}" target="_blank">PatchPilot</a>'
             + (" (no patch exists for EOL versions, use for the upgrade path)" if res[C_STATUS] == "EOL" else "")],
            ["Source", f'<a href="https://endoflife.date/{esc(res.get("_slug"))}" target="_blank">'
                       f'endoflife.date/{esc(res.get("_slug"))}</a>'],
        ], label_first=True), unsafe_allow_html=True)

    slug = res["_slug"]
    data = release_data(slug) or []
    with st.expander(f"All versions of {res[C_PRODUCT]}"):
        rel = []
        for c in data[:40]:
            lc = lifecycle(c)
            rel.append([esc(friendly_version(slug, c)), esc(c.get("releaseDate") or "-"), esc(c.get("latest") or "-"),
                        esc(lc["eol_date"] or "n/a"), badge(lc["status"])])
        st.markdown(
            f'<div class="scroll">{table([C_VERSION, C_RELDATE, C_LATEST, C_EOL, C_STATUS], rel)}</div>',
            unsafe_allow_html=True)


with tab_look:
    c1, c2, c3 = st.columns([3, 2, 1])
    product = c1.text_input("Product", placeholder="Windows Server, ESXi, Ubuntu, Cisco IOS XE ...")
    version = c2.text_input("Version (optional)", placeholder="Leave empty to list all versions")
    c3.markdown("<div style='height:1.85rem'></div>", unsafe_allow_html=True)
    if c3.button("Check", use_container_width=True):
        if product.strip():
            st.session_state["lk"] = (product.strip(), version.strip())
        else:
            st.session_state.pop("lk", None)
            st.warning("Enter a product name first.")

    lk = st.session_state.get("lk")
    if lk:
        if lk[1]:
            show_single(*lk)
        else:
            show_all_releases(lk[0])

# ---- Bulk ------------------------------------------------------------------
with tab_bulk:
    guide = table(["Way to add items", "How to write it", "Example"], [
        ["Paste with a comma", "product, version", "Windows Server, 2012 R2"],
        ["Paste as plain text", "product and version together", "Windows Server 2012 R2"],
        ["Upload a CSV", "two columns named product and version", "product,version"],
        ["All versions of one product", "use the Lookup tab and leave Version empty", "Windows"],
    ])
    st.markdown(card("How to add your list (a version is needed here)", "fa-list-check", guide),
                unsafe_allow_html=True)
    b1, b2 = st.columns([3, 2])
    text = b1.text_area("Paste items, one per line", height=170,
                        placeholder="Windows Server, 2012 R2\nESXi, 6.7\nUbuntu, 18.04\nMySQL, 5.7")
    up = b2.file_uploader("Or upload a CSV file", type=["csv"])
    b2.download_button("Download sample CSV",
                       "product,version\nWindows Server,2012 R2\nESXi,6.7\nUbuntu,18.04\nMySQL,5.7\n",
                       "eol_radar_sample.csv", "text/csv")

    if st.button("Scan all"):
        items = []
        if up is not None:
            try:
                df_in = pd.read_csv(up)
                df_in.columns = [c.strip().lower() for c in df_in.columns]
                for _, r in df_in.iterrows():
                    v = "" if pd.isna(r.get("version")) else str(r.get("version")).strip()
                    items.append((str(r.get("product", "")).strip(), v))
            except Exception as e:
                st.error(f"Could not read CSV: {e}")
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            if "," in line or "\t" in line:
                p, v = (re.split(r"[,\t]", line, maxsplit=1) + [""])[:2]
                items.append((p.strip(), v.strip()))
            else:
                items.append(split_free_text(line))
        items = [(p, v) for p, v in items if p]
        if not items:
            st.warning("Nothing to scan.")
        else:
            prog = st.progress(0.0)
            out = []
            for i, (p, v) in enumerate(items):
                out.append(check(p, v))
                prog.progress((i + 1) / len(items))
            prog.empty()
            df = pd.DataFrame(out).drop(columns=["_slug"], errors="ignore")
            order = {"EOL": 0, "Approaching EOL": 1, "Security-only": 2, "Not found": 3, "Supported": 4}
            st.session_state["bulk_df"] = df.sort_values(C_STATUS, key=lambda s: s.map(order)).reset_index(drop=True)

    df = st.session_state.get("bulk_df")
    if df is not None:
        counts = df[C_STATUS].value_counts()
        stats = "".join(
            f'<div class="stat"><b style="color:{STATUS_COLOR[k]}">{int(counts.get(k, 0))}</b><span>{k}</span></div>'
            for k in ["EOL", "Approaching EOL", "Security-only", "Supported", "Not found"]
        )
        st.markdown(f'<div class="stats">{stats}</div>', unsafe_allow_html=True)

        cols = [C_VENDOR, C_PRODUCT, C_VERSION, C_STATUS, C_EOL, C_LEFT, C_UPGRADE, C_NOTE]
        rows = [[esc(r[c]) if c != C_STATUS else badge(r[c]) for c in cols] for _, r in df.iterrows()]
        title = f"EOL status of {len(df)} items checked (vendor, OS / product and version)"
        st.markdown(card(title, "fa-table-list", f'<div class="scroll">{table(cols, rows)}</div>'),
                    unsafe_allow_html=True)

        d1, d2, _ = st.columns([1, 1, 4])
        d1.download_button("Download CSV", df.to_csv(index=False).encode(), "eol_radar.csv", "text/csv")
        buf = io.BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as xw:
            df.to_excel(xw, index=False, sheet_name="EOL Radar")
        d2.download_button("Download Excel", buf.getvalue(), "eol_radar.xlsx",
                           "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

# ---- FAQ -------------------------------------------------------------------
with tab_faq:
    faq = [
        ("What is EOL / EOS?",
         "End of Life (EOL) means the vendor stops shipping security fixes. End of Support (EOS) usually means "
         "active support (bug fixes, help) has ended. Some products have both dates."),
        ("What do the statuses mean?",
         "Supported: still patched. Security-only: only security fixes. Approaching EOL: under 90 days left. "
         "EOL: no more patches. Not found: no match in the data source."),
        ("What do the table columns mean?",
         "Vendor: the company that makes it. OS / Product: the software name. Version: the version you run. "
         "Release date: when that version first came out. Latest version: the newest build number released for it. "
         "Full support ends: bug fixes and help end. Security updates end (EOL): the last day it gets security "
         "patches. Paid extended support: optional paid patches after that date."),
        ("What does a Windows version like '11 25H2 (Home/Pro)' mean?",
         "11 is the Windows generation. 25H2 is the second yearly update of 2025. The brackets show the edition: "
         "Home/Pro or Enterprise/Education. Each edition has its own end date."),
        ("Where does the data come from?",
         '<a href="https://endoflife.date" target="_blank">endoflife.date</a> public API (no key needed). '
         "It is community-maintained, so confirm critical decisions on the vendor page."),
        ("Do I need to share asset or company data?",
         "No. Only a product name and version are used. Nothing is stored."),
        ("How do I write versions?",
         "Use the version line: 2012 R2, 6.7, 18.04, 8.0. A full build like 8.0.35 also works for most products."),
        ("My product is not found. What now?",
         "Try the exact name from the suggestions shown, or check the official vendor pages listed below."),
        ("What if my product is EOL?",
         "Upgrade first. If you cannot yet: isolate it, limit network access, add virtual patching and ask about extended support."),
        ("Does a patch exist for EOL products?",
         "Usually not. Paid extended support (for example Microsoft ESU) is the exception."),
        ("How does this connect to the other apps?",
         "VulnPulse shows CVEs, Risk Calc ranks them, PatchPilot gives the patch plan, and EOL Radar tells you when "
         "there is nothing left to patch."),
    ]
    st.markdown(card("Frequently asked questions", "fa-circle-question",
                     table(["Question", "Answer"], [[f"<b>{esc(q)}</b>", a if "<a " in a else esc(a)] for q, a in faq])),
                unsafe_allow_html=True)
    vend = [[esc(k), f'<a href="{v}" target="_blank">{esc(v)}</a>'] for k, v in VENDOR_LINKS.items()]
    st.markdown(card("Official lifecycle pages", "fa-link", table(["Vendor", "Link"], vend)),
                unsafe_allow_html=True)

st.markdown(
    f'<div class="foot">By Div<a href="{LINKEDIN}" target="_blank" aria-label="LinkedIn">'
    f'<i class="fa-brands fa-linkedin"></i></a></div>',
    unsafe_allow_html=True,
)
