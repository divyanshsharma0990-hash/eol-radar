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
        "Keep patching on your normal cycle. Re-check this release before its EOL date.",
    ),
    "Not found": (
        "Could not match this product/version in the data source.",
        "Check the vendor's official lifecycle page (links in the FAQ tab).",
    ),
}

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
  color: #e6f0ff;
}
header[data-testid="stHeader"], #MainMenu, footer { display: none !important; }
.block-container { max-width: 100% !important; padding: 1rem 2.2rem 4.2rem !important; }
.stApp p, .stApp label, .stApp li, .stApp span { color: #e6f0ff; }
.topbar { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:.6rem;
  padding:.7rem 1.1rem; margin-bottom:.9rem; border-radius:14px;
  background: rgba(8,20,48,.72); border:1px solid rgba(80,160,255,.28); backdrop-filter: blur(6px); }
.brand { font-size:1.45rem; font-weight:700; color:#fff; }
.brand i { color:#38bdf8; margin-right:.5rem; }
.brand small { font-size:.82rem; font-weight:400; color:#9db8e0; margin-left:.6rem; }
.nav a { color:#cfe3ff !important; text-decoration:none; margin-left:.5rem; padding:.35rem .8rem;
  border:1px solid rgba(80,160,255,.35); border-radius:999px; font-size:.86rem; display:inline-block; }
.nav a:hover { background: rgba(56,189,248,.18); border-color:#38bdf8; }
.nav a i { margin-right:.4rem; color:#38bdf8; }
.card { background: rgba(8,20,48,.72); border:1px solid rgba(80,160,255,.25);
  border-radius:14px; padding:.9rem 1.1rem; margin:.5rem 0; backdrop-filter: blur(6px); }
.card h4 { margin:0 0 .5rem 0; color:#fff; font-size:1.02rem; }
.card h4 i { color:#38bdf8; margin-right:.45rem; }
table.t { width:100%; border-collapse:collapse; font-size:.86rem; }
table.t th { text-align:left; background: rgba(56,189,248,.14); color:#bfe3ff; padding:.45rem .6rem;
  border-bottom:1px solid rgba(80,160,255,.35); position:sticky; top:0; }
table.t td { padding:.4rem .6rem; border-bottom:1px solid rgba(80,160,255,.14); vertical-align:top; color:#e6f0ff; }
table.t td.l { color:#9db8e0; white-space:nowrap; width:1%; }
table.t tr:hover td { background: rgba(56,189,248,.06); }
table.t a { color:#7dd3fc !important; }
.badge { display:inline-block; padding:.12rem .6rem; border-radius:999px; font-weight:600; font-size:.8rem; color:#04101f; }
.stats { display:flex; gap:.6rem; flex-wrap:wrap; margin:.4rem 0; }
.stat { flex:1 1 120px; padding:.55rem .8rem; border-radius:12px; background: rgba(8,20,48,.72);
  border:1px solid rgba(80,160,255,.25); }
.stat b { font-size:1.35rem; display:block; color:#fff; }
.stat span { font-size:.78rem; color:#9db8e0; }
.scroll { max-height: 430px; overflow:auto; border-radius:10px; }
.stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] > div {
  background: rgba(6,16,40,.9) !important; color:#e6f0ff !important;
  border:1px solid rgba(80,160,255,.38) !important; border-radius:10px !important; }
.stButton > button, .stDownloadButton > button { background: linear-gradient(90deg,#0ea5e9,#2563eb); color:#fff;
  border:0; border-radius:10px; font-weight:600; }
.stButton > button:hover, .stDownloadButton > button:hover { filter:brightness(1.12); color:#fff; }
button[data-baseweb="tab"] { color:#9db8e0 !important; font-weight:600; }
button[data-baseweb="tab"][aria-selected="true"] { color:#fff !important; }
div[data-testid="stExpander"] { background: rgba(8,20,48,.72); border:1px solid rgba(80,160,255,.25); border-radius:12px; }
div[data-testid="stExpander"] summary p { color:#fff; font-weight:600; }
.foot { position:fixed; left:0; right:0; bottom:0; z-index:99; text-align:center; padding:.5rem;
  background: rgba(4,10,28,.88); border-top:1px solid rgba(80,160,255,.25); font-size:.9rem; color:#9db8e0; }
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


def upgrade_target(data):
    supported = [c for c in data if lifecycle(c)["status"] == "Supported"]
    if not supported:
        return "-"
    lts = [c for c in supported if c.get("lts")]
    pick = (lts or supported)[0]
    latest = pick.get("latest")
    return f"{pick.get('cycle')}" + (f" (latest {latest})" if latest else "")


def check(product: str, version: str) -> dict:
    """One product+version -> flat result dict (used by lookup and bulk)."""
    base = dict(Product=product, Version=version, Status="Not found", Release="-", Released="-",
                **{"Support ends": "-", "EOL date": "-", "Time left": "-", "Latest patch": "-",
                   "Extended support": "-", "Upgrade to": "-", "Note": ""})
    slug, pre, sugg = resolve(product)
    if not slug:
        base["Note"] = "Did you mean: " + ", ".join(sugg) if sugg else "Product not in data source"
        return base
    data = release_data(slug)
    if not data:
        base["Note"] = "Data source unavailable"
        return base
    if not str(version).strip():
        base["Note"] = "No version given. Use the Lookup tab with an empty version to list all releases"
        return base
    ver = f"{pre}-{version}".strip("-") if pre else version
    c = match_cycle(data, ver)
    if not c:
        base["Note"] = f"Version not matched. Known releases: {', '.join(str(x.get('cycle')) for x in data[:8])}"
        return base
    lc = lifecycle(c)
    ext = c.get("extendedSupport")
    sup = c.get("support")
    base.update({
        "Status": lc["status"], "Release": str(c.get("cycle")), "Released": str(c.get("releaseDate") or "-"),
        "Support ends": str(sup) if isinstance(sup, str) else ("Ended" if sup is True else "-"),
        "EOL date": str(lc["eol_date"]) if lc["eol_date"] else "n/a",
        "Time left": lc["text"], "Latest patch": str(c.get("latest") or "-"),
        "Extended support": str(ext) if isinstance(ext, str) else "-",
        "Upgrade to": upgrade_target(data) if lc["status"] != "Supported" else "Already on a supported release",
        "Note": "", "_slug": slug,
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
def releases_df(data) -> pd.DataFrame:
    rows = []
    for c in data:
        lc = lifecycle(c)
        sup, ext = c.get("support"), c.get("extendedSupport")
        rows.append({
            "Release": str(c.get("cycle")),
            "Released": str(c.get("releaseDate") or "-"),
            "Latest": str(c.get("latest") or "-"),
            "Support ends": str(sup) if isinstance(sup, str) else ("Ended" if sup is True else "-"),
            "EOL date": str(lc["eol_date"]) if lc["eol_date"] else ("Ended" if c.get("eol") is True else "n/a"),
            "Extended support": str(ext) if isinstance(ext, str) else "-",
            "Status": lc["status"],
            "Time left": lc["text"],
        })
    return pd.DataFrame(rows)


def show_all_releases(product: str):
    """Product only (no version): list every release with its lifecycle status."""
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
    df = releases_df(data)

    counts = df["Status"].value_counts()
    stats = "".join(
        f'<div class="stat"><b style="color:{STATUS_COLOR[k]}">{int(counts.get(k, 0))}</b><span>{k}</span></div>'
        for k in ["Supported", "Security-only", "Approaching EOL", "EOL"]
    )
    st.markdown(f'<div class="stats">{stats}</div>', unsafe_allow_html=True)

    f1, f2 = st.columns([4, 1])
    flt = f1.radio("Show", ["All", "Supported", "Security-only", "Approaching EOL", "EOL"],
                   horizontal=True, label_visibility="collapsed", key="rel_filter")
    shown = df if flt == "All" else df[df["Status"] == flt]
    f2.download_button("Download CSV", df.to_csv(index=False).encode(), f"{slug}_releases.csv", "text/csv")

    cols = ["Release", "Released", "Latest", "Support ends", "EOL date", "Extended support", "Status", "Time left"]
    rows = []
    for _, r in shown.iterrows():
        rows.append([esc(r[c]) if c != "Status" else badge(r[c]) for c in cols])
    if not rows:
        rows = [[esc("No releases with this status")] + [""] * (len(cols) - 1)]
    inner = (f'<div class="scroll">{table(cols, rows)}</div>'
             f'<div style="margin-top:.5rem;font-size:.82rem">Source: '
             f'<a href="https://endoflife.date/{esc(slug)}" target="_blank" style="color:#7dd3fc">'
             f'endoflife.date/{esc(slug)}</a>. Type a version above to check one release.</div>')
    st.markdown(card(f"{slug}: {len(shown)} of {len(df)} releases", "fa-list", inner), unsafe_allow_html=True)


def show_single(product: str, version: str):
    with st.spinner("Checking lifecycle data..."):
        res = check(product, version)
    if res["Status"] == "Not found":
        st.markdown(card("No match", "fa-circle-question", table(None, [[esc(res["Note"])]])),
                    unsafe_allow_html=True)
        return
    rows = [
        ["Product", esc(res["Product"]), "Matched release", esc(res["Release"])],
        ["Status", badge(res["Status"]), "Time left", esc(res["Time left"])],
        ["Released", esc(res["Released"]), "Active support ends", esc(res["Support ends"])],
        ["EOL date", esc(res["EOL date"]), "Extended support", esc(res["Extended support"])],
        ["Latest patch", esc(res["Latest patch"]), "Upgrade to", esc(res["Upgrade to"])],
    ]
    st.markdown(card("Lifecycle result", "fa-satellite-dish", table(None, rows, label_first=True)),
                unsafe_allow_html=True)

    risk, action = STATUS_ADVICE[res["Status"]]
    with st.expander("Why this status and what to do"):
        st.markdown(table(["Topic", "Detail"], [
            ["Risk", esc(risk)], ["Action", esc(action)],
            ["Check CVEs", f'<a href="{SUITE[0][1]}" target="_blank">VulnPulse</a> for this product'],
            ["Score a CVE", f'<a href="{SUITE[1][1]}" target="_blank">Risk Calc</a>'],
            ["Patch plan", f'<a href="{SUITE[2][1]}" target="_blank">PatchPilot</a>'
             + (" (no patch exists for EOL releases, use for the upgrade path)" if res["Status"] == "EOL" else "")],
            ["Source", f'<a href="https://endoflife.date/{esc(res.get("_slug"))}" target="_blank">'
                       f'endoflife.date/{esc(res.get("_slug"))}</a>'],
        ], label_first=True), unsafe_allow_html=True)

    data = release_data(res["_slug"]) or []
    with st.expander("All releases of this product"):
        rel = []
        for c in data[:40]:
            lc = lifecycle(c)
            rel.append([esc(c.get("cycle")), esc(c.get("releaseDate") or "-"), esc(c.get("latest") or "-"),
                        esc(lc["eol_date"] or "n/a"), badge(lc["status"])])
        st.markdown(f'<div class="scroll">{table(["Release", "Released", "Latest", "EOL", "Status"], rel)}</div>',
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
    st.markdown(
        "<div class='card'><h4><i class='fa-solid fa-list-check'></i>Paste or upload</h4>"
        "One item per line as <b>product, version</b> (or just <b>Windows Server 2012 R2</b>). "
        "CSV upload needs <b>product</b> and <b>version</b> columns. A version is needed here; "
        "to see all versions of a product use the Lookup tab.</div>",
        unsafe_allow_html=True,
    )
    b1, b2 = st.columns([3, 2])
    text = b1.text_area("Items", height=150, label_visibility="collapsed",
                        placeholder="Windows Server, 2012 R2\nESXi, 6.7\nUbuntu, 18.04\nMySQL, 5.7")
    up = b2.file_uploader("CSV", type=["csv"], label_visibility="collapsed")

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
            st.session_state["bulk_df"] = df.sort_values("Status", key=lambda s: s.map(order)).reset_index(drop=True)

    df = st.session_state.get("bulk_df")
    if df is not None:
        counts = df["Status"].value_counts()
        stats = "".join(
            f'<div class="stat"><b style="color:{STATUS_COLOR[k]}">{int(counts.get(k, 0))}</b><span>{k}</span></div>'
            for k in ["EOL", "Approaching EOL", "Security-only", "Supported", "Not found"]
        )
        st.markdown(f'<div class="stats">{stats}</div>', unsafe_allow_html=True)

        cols = ["Product", "Version", "Status", "EOL date", "Time left", "Upgrade to", "Note"]
        rows = [[esc(r["Product"]), esc(r["Version"]), badge(r["Status"]), esc(r["EOL date"]),
                 esc(r["Time left"]), esc(r["Upgrade to"]), esc(r["Note"])] for _, r in df.iterrows()]
        st.markdown(f'<div class="card scroll">{table(cols, rows)}</div>', unsafe_allow_html=True)

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
        ("Where does the data come from?",
         '<a href="https://endoflife.date" target="_blank">endoflife.date</a> public API (no key needed). '
         "It is community-maintained, so confirm critical decisions on the vendor page."),
        ("Do I need to share asset or company data?",
         "No. Only a product name and version are used. Nothing is stored."),
        ("How do I write versions?",
         "Use the release line: 2012 R2, 6.7, 18.04, 8.0. A full build like 8.0.35 also works for most products."),
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