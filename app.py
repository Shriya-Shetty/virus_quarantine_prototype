"""
Quarantine & Treatment Centre Tracker  v2  (single-file Streamlit + SQLite)

ROLES (RBAC)
  nurse         : temperature round (card per patient, one-tap save, undo)
  doctor        : doctor rounds (visit blocked until temp exists), confirm discharge / record death
  receptionist  : front desk - admissions, waitlist, bed map, discharge notices
  supervisor    : head-doctor view - dashboard, reports, audit (read-only)
  admin         : front desk + dashboard + reports + users & settings

RULES
  Fever day      : any reading that day >= fever threshold (default 38.0 C)
  No-fever day   : >= 1 reading that day, all below threshold
  Missing day    : breaks the streak
  Discharge-ready: streak >= required days (default 3)
  Mortality      : deaths / (deaths + cured), rolling 30 days, benchmark 15%

Run locally :  streamlit run app.py
Deploy      :  push app.py + requirements.txt to GitHub -> share.streamlit.io
NOTE: SQLite on Streamlit Community Cloud is ephemeral (resets on reboot).
"""
import hashlib
import hmac
import html
import os
import random
import secrets as pysecrets
import sqlite3
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Quarantine Centre Tracker", page_icon="🏥", layout="wide")

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
TZ = ZoneInfo("Asia/Kolkata")
DB_PATH = os.environ.get("DB_PATH", "quarantine_v2.db")
TOTAL_BEDS = 74
BENCHMARK = 0.15

ROLE_INFO = {
    "nurse": ("Nurse", "🩹", "Records daily temperatures"),
    "doctor": ("Doctor", "🩺", "Visits patients, treats, confirms discharge"),
    "receptionist": ("Front Desk", "🛎️", "Admissions, waitlist, beds"),
    "supervisor": ("Supervisor", "📋", "Head-doctor view: KPIs, reports, audit"),
    "admin": ("Admin", "🛠️", "Front desk, reports, users & settings"),
}
ROLES = list(ROLE_INFO)
DEFAULT_PASSWORDS = {r: f"{r}123" for r in ROLES}
DEFAULT_USERS = [
    ("nurse1", "Nurse Priya", "nurse"),
    ("nurse2", "Nurse Arjun", "nurse"),
    ("doctor1", "Dr. Rao", "doctor"),
    ("doctor2", "Dr. Mehta", "doctor"),
    ("frontdesk1", "Meera (Front Desk)", "receptionist"),
    ("supervisor1", "Dr. Iyer (Head)", "supervisor"),
    ("admin1", "Admin Kavita", "admin"),
]
TREATMENTS = ["Hydration / IV fluids", "Antipyretic", "Antiviral course", "Oxygen support",
              "Antibiotics (secondary infection)", "Continue monitoring", "Isolation continues"]

CSS = """
<style>
#MainMenu, footer {visibility: hidden;}
.block-container {padding-top: 1.2rem; max-width: 1280px;}
.hero {background: linear-gradient(120deg,#0f766e 0%,#0ea5e9 100%); color:#fff;
       padding: 18px 24px; border-radius: 16px; margin-bottom: 16px;}
.hero h2 {margin:0; color:#fff; font-size:1.6rem;}
.hero p {margin:4px 0 0; opacity:.92;}
.chip {display:inline-block; padding:2px 10px; border-radius:999px; font-size:.74rem; font-weight:600; margin-right:4px;}
.chip.green {background:rgba(22,163,74,.16); color:#16a34a;}
.chip.amber {background:rgba(245,158,11,.20); color:#d97706;}
.chip.red   {background:rgba(220,38,38,.16); color:#dc2626;}
.chip.blue  {background:rgba(14,165,233,.16); color:#0284c7;}
.chip.gray  {background:rgba(100,116,139,.20); color:#64748b;}
.muted {opacity:.65; font-size:.82rem;}
.bedgrid {display:grid; grid-template-columns:repeat(auto-fill,minmax(92px,1fr)); gap:8px;}
.bed {border-radius:10px; padding:6px 9px; font-size:.74rem; line-height:1.25; border:1px solid rgba(100,116,139,.28);}
.bed b {font-size:.86rem;}
.bed.free {background:rgba(22,163,74,.14);} .bed.occ {background:rgba(100,116,139,.12);}
.bed.fever {background:rgba(220,38,38,.18);} .bed.ready {background:rgba(14,165,233,.22);}
div[data-testid="stMetric"] {background:rgba(100,116,139,.08); padding:10px 14px; border-radius:12px;}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


def now() -> datetime:
    return datetime.now(TZ)


def today() -> date:
    return now().date()


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def esc(x) -> str:
    return html.escape(str(x))


def chip(text: str, color: str = "gray") -> str:
    return f'<span class="chip {color}">{esc(text)}</span>'


def hero(title: str, subtitle: str = ""):
    st.markdown(f'<div class="hero"><h2>{esc(title)}</h2><p>{esc(subtitle)}</p></div>', unsafe_allow_html=True)


def fmt_t(x) -> str:
    return "–" if x is None or pd.isna(x) else f"{x:.1f}°C"


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY, name TEXT, role TEXT, salt TEXT, pw_hash TEXT, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS beds(id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS patients(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER, contact TEXT, admit_date TEXT,
  bed_id TEXT, status TEXT DEFAULT 'admitted', closed_at TEXT);
CREATE TABLE IF NOT EXISTS waitlist(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER, contact TEXT,
  priority TEXT, added_at TEXT, status TEXT DEFAULT 'waiting');
CREATE TABLE IF NOT EXISTS readings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, value REAL,
  recorded_by TEXT, recorded_at TEXT, day TEXT);
CREATE TABLE IF NOT EXISTS visits(
  id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, doctor TEXT,
  visited_at TEXT, day TEXT, notes TEXT, treatment TEXT);
CREATE TABLE IF NOT EXISTS discharges(
  id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, eligible_since TEXT,
  confirmed_by TEXT, outcome TEXT, closed_at TEXT,
  admin_ack INTEGER DEFAULT 0, ack_by TEXT, ack_at TEXT);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, username TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS ix_read ON readings(patient_id, day);
CREATE INDEX IF NOT EXISTS ix_visit ON visits(patient_id, day);
"""
DEFAULT_SETTINGS = {"fever_threshold": "38.0", "critical_temp": "40.0", "required_days": "3", "include_today": "0"}


def hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000).hex()


def configured_password(role: str) -> str:
    try:
        return st.secrets["passwords"][role]
    except Exception:
        return DEFAULT_PASSWORDS[role]


def make_user(conn, username, name, role, password):
    salt = pysecrets.token_hex(16)
    conn.execute("INSERT OR REPLACE INTO users VALUES (?,?,?,?,?,1)",
                 (username, name, role, salt, hash_pw(password, salt)))


@st.cache_resource
def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    for k, v in DEFAULT_SETTINGS.items():
        conn.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (k, v))
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        for u, n, r in DEFAULT_USERS:
            make_user(conn, u, n, r, configured_password(r))
        conn.commit()
        seed_demo(conn)
    conn.commit()
    return conn


def qdf(sql, params=()):
    return pd.read_sql_query(sql, get_conn(), params=params)


def run(sql, params=()):
    c = get_conn()
    cur = c.execute(sql, params)
    c.commit()
    return cur


def one(sql, params=()):
    r = get_conn().execute(sql, params).fetchone()
    return r[0] if r else None


def setting(key, cast=str):
    return cast(one("SELECT value FROM settings WHERE key=?", (key,)))


def me() -> dict:
    return st.session_state.user


def audit(action: str, detail: str = "", username: str | None = None):
    if username is None:
        username = me()["username"] if st.session_state.get("user") else "system"
    run("INSERT INTO audit(ts,username,action,detail) VALUES (?,?,?,?)", (iso(now()), username, action, detail))


def require(*roles):
    """Server-side RBAC guard used by every write action and page."""
    u = st.session_state.get("user")
    if not u or u["role"] not in roles:
        audit("access_denied", f"needs {roles}")
        st.error("🚫 You do not have permission for this action.")
        st.stop()


# --------------------------------------------------------------------------
# Demo data
# --------------------------------------------------------------------------
FIRST = ["Aarav", "Vihaan", "Aditya", "Ishaan", "Rohan", "Kabir", "Arjun", "Sai", "Ananya", "Diya", "Isha",
         "Meera", "Priya", "Riya", "Saanvi", "Tara", "Neha", "Kavya", "Rahul", "Sneha"]
LAST = ["Sharma", "Patel", "Iyer", "Nair", "Reddy", "Khan", "Gupta", "Desai", "Joshi", "Menon", "Kulkarni",
        "Singh", "Verma", "Shah", "Pillai", "Bose"]


def seed_demo(conn: sqlite3.Connection):
    rnd = random.Random(7)
    for t in ["readings", "visits", "discharges", "patients", "waitlist", "beds", "audit"]:
        conn.execute(f"DELETE FROM {t}")
    for i in range(1, TOTAL_BEDS + 1):
        conn.execute("INSERT INTO beds VALUES (?)", (f"B{i:02d}",))
    t0 = today()

    def ts(d: date, h=None):
        h = h if h is not None else rnd.randint(7, 11)
        return iso(datetime(d.year, d.month, d.day, h, rnd.randint(0, 59), tzinfo=TZ))

    def nm():
        return f"{rnd.choice(FIRST)} {rnd.choice(LAST)}"

    def temp(fever):
        return round(rnd.uniform(38.2, 40.4) if fever else rnd.uniform(36.4, 37.6), 1)

    for i in range(1, TOTAL_BEDS + 1):
        admit = t0 - timedelta(days=rnd.randint(0, 9))
        pid = conn.execute(
            "INSERT INTO patients(name,age,contact,admit_date,bed_id,status) VALUES (?,?,?,?,?, 'admitted')",
            (nm(), rnd.randint(8, 82), f"98{rnd.randint(10000000, 99999999)}", admit.isoformat(), f"B{i:02d}")).lastrowid
        recover = rnd.randint(2, 9)
        d = admit
        while d < t0:
            if rnd.random() > 0.06:
                conn.execute("INSERT INTO readings(patient_id,value,recorded_by,recorded_at,day) VALUES (?,?,?,?,?)",
                             (pid, temp((d - admit).days < recover), rnd.choice(["nurse1", "nurse2"]), ts(d), d.isoformat()))
            d += timedelta(days=1)
        if rnd.random() < 0.5:
            conn.execute("INSERT INTO readings(patient_id,value,recorded_by,recorded_at,day) VALUES (?,?,?,?,?)",
                         (pid, temp((t0 - admit).days < recover), rnd.choice(["nurse1", "nurse2"]), ts(t0, 8), t0.isoformat()))
            if rnd.random() < 0.4:
                conn.execute("INSERT INTO visits(patient_id,doctor,visited_at,day,notes,treatment) VALUES (?,?,?,?,?,?)",
                             (pid, "doctor1", ts(t0, 11), t0.isoformat(), "Stable", "Hydration / IV fluids, Continue monitoring"))
    for _ in range(70):
        cd = t0 - timedelta(days=rnd.randint(0, 29))
        admit = cd - timedelta(days=rnd.randint(4, 12))
        dead = rnd.random() < 0.13
        pid = conn.execute(
            "INSERT INTO patients(name,age,contact,admit_date,bed_id,status,closed_at) VALUES (?,?,?,?,NULL,?,?)",
            (nm(), rnd.randint(8, 82), "", admit.isoformat(), "deceased" if dead else "discharged", ts(cd, 14))).lastrowid
        elig = None if dead else (cd - timedelta(days=rnd.randint(0, 1))).isoformat()
        conn.execute("INSERT INTO discharges(patient_id,eligible_since,confirmed_by,outcome,closed_at,admin_ack) VALUES (?,?,?,?,?,1)",
                     (pid, elig, "doctor1", "deceased" if dead else "cured", ts(cd, 14)))
    for pr in ["High", "Normal", "Normal", "High", "Normal"]:
        conn.execute("INSERT INTO waitlist(name,age,contact,priority,added_at) VALUES (?,?,?,?,?)",
                     (nm(), rnd.randint(8, 82), f"97{rnd.randint(10000000, 99999999)}", pr, iso(now())))
    conn.commit()


# --------------------------------------------------------------------------
# Business logic
# --------------------------------------------------------------------------
def calc_streak(mx: dict, admit: str, thr: float, include_today: bool):
    """mx: {day_iso: max_temp}. Returns (streak_len, no_fever_days newest-first)."""
    a = date.fromisoformat(admit)
    d = today() if include_today else today() - timedelta(days=1)
    days = []
    while d >= a:
        k = d.isoformat()
        if k not in mx:
            if d == today():
                d -= timedelta(days=1)
                continue
            break
        if mx[k] >= thr:
            break
        days.append(d)
        d -= timedelta(days=1)
    return len(days), days


def all_daily_max() -> dict:
    out = {}
    for pid, day, mx in get_conn().execute("SELECT patient_id, day, MAX(value) FROM readings GROUP BY patient_id, day"):
        out.setdefault(pid, {})[day] = mx
    return out


def streak_info(pid: int, admit: str):
    mx = dict(get_conn().execute("SELECT day, MAX(value) FROM readings WHERE patient_id=? GROUP BY day", (pid,)).fetchall())
    return calc_streak(mx, admit, setting("fever_threshold", float), setting("include_today", int) == 1)


def board() -> pd.DataFrame:
    """One row per admitted patient: today's task state + clinical flags."""
    df = qdf("""
        SELECT p.id, p.name AS patient, p.age, p.bed_id, p.admit_date,
          (SELECT COUNT(*) FROM readings r WHERE r.patient_id=p.id AND r.day=:d) AS n_read,
          (SELECT value FROM readings r WHERE r.patient_id=p.id AND r.day=:d ORDER BY recorded_at DESC, id DESC LIMIT 1) AS last_temp,
          (SELECT MAX(value) FROM readings r WHERE r.patient_id=p.id AND r.day=:d) AS max_today,
          (SELECT id FROM readings r WHERE r.patient_id=p.id AND r.day=:d ORDER BY recorded_at DESC, id DESC LIMIT 1) AS last_read_id,
          (SELECT recorded_by FROM readings r WHERE r.patient_id=p.id AND r.day=:d ORDER BY recorded_at DESC, id DESC LIMIT 1) AS last_read_by,
          (SELECT recorded_by FROM readings r WHERE r.patient_id=p.id AND r.day=:d ORDER BY recorded_at ASC, id ASC LIMIT 1) AS measured_by,
          (SELECT recorded_at FROM readings r WHERE r.patient_id=p.id AND r.day=:d ORDER BY recorded_at ASC, id ASC LIMIT 1) AS measured_at,
          (SELECT COUNT(*) FROM visits v WHERE v.patient_id=p.id AND v.day=:d) AS n_visit,
          (SELECT treatment FROM visits v WHERE v.patient_id=p.id AND v.day=:d ORDER BY id DESC LIMIT 1) AS treatment
        FROM patients p WHERE p.status='admitted' ORDER BY p.bed_id
    """, {"d": today().isoformat()})
    thr, crit = setting("fever_threshold", float), setting("critical_temp", float)
    req, inc = setting("required_days", int), setting("include_today", int) == 1
    mxall = all_daily_max()
    streaks, trends = [], []
    for r in df.itertuples():
        mx = mxall.get(r.id, {})
        streaks.append(calc_streak(mx, r.admit_date, thr, inc)[0])
        last = sorted(mx.items())[-4:]
        trends.append(" → ".join(f"{v:.1f}" for _, v in last) or "no data")
    df["streak"] = streaks
    df["trend"] = trends
    df["eligible"] = df.streak >= req
    df["fever_now"] = df.last_temp.notna() & (df.last_temp >= thr)
    df["critical"] = df.max_today.notna() & (df.max_today >= crit)
    df["day_no"] = df.admit_date.apply(lambda a: (today() - date.fromisoformat(a)).days + 1)
    df["status"] = df.apply(lambda r: "done" if r.n_visit > 0 else ("ready" if r.n_read > 0 else "pending"), axis=1)
    return df


def record_temp(pid: int, value: float, extra: bool):
    require("nurse")
    if not 34.0 <= value <= 43.0:
        st.error("Temperature must be between 34.0 and 43.0 °C.")
        return False
    run("INSERT INTO readings(patient_id,value,recorded_by,recorded_at,day) VALUES (?,?,?,?,?)",
        (pid, value, me()["username"], iso(now()), today().isoformat()))
    audit("record_temp", f"patient={pid} value={value}" + (" (extra)" if extra else ""))
    return True


def record_visit(pid: int, treatment: str, notes: str):
    require("doctor")
    if one("SELECT COUNT(*) FROM readings WHERE patient_id=? AND day=?", (pid, today().isoformat())) == 0:
        audit("visit_blocked", f"patient={pid} no temperature yet")
        return False
    run("INSERT INTO visits(patient_id,doctor,visited_at,day,notes,treatment) VALUES (?,?,?,?,?,?)",
        (pid, me()["username"], iso(now()), today().isoformat(), notes, treatment))
    audit("doctor_visit", f"patient={pid}")
    return True


def close_case(pid: int, outcome: str, admit: str):
    require("doctor")
    eligible_since = None
    if outcome == "cured":
        n, days = streak_info(pid, admit)
        req = setting("required_days", int)
        if n < req:
            st.error("Patient does not yet meet the discharge criterion.")
            return False
        eligible_since = days[n - req].isoformat()
    run("UPDATE patients SET status=?, closed_at=?, bed_id=NULL WHERE id=?",
        ("discharged" if outcome == "cured" else "deceased", iso(now()), pid))
    run("INSERT INTO discharges(patient_id,eligible_since,confirmed_by,outcome,closed_at) VALUES (?,?,?,?,?)",
        (pid, eligible_since, me()["username"], outcome, iso(now())))
    audit("close_case", f"patient={pid} outcome={outcome}")
    return True


def admit_patient(name: str, age: int, contact: str, bed: str):
    require("receptionist", "admin")
    if one("SELECT COUNT(*) FROM patients WHERE bed_id=? AND status='admitted'", (bed,)):
        st.error("That bed is already occupied.")
        return None
    pid = run("INSERT INTO patients(name,age,contact,admit_date,bed_id,status) VALUES (?,?,?,?,?, 'admitted')",
              (name.strip(), int(age), contact.strip(), today().isoformat(), bed)).lastrowid
    audit("admit", f"patient={pid} bed={bed}")
    return pid


def free_beds() -> list:
    return [r[0] for r in get_conn().execute(
        "SELECT id FROM beds WHERE id NOT IN (SELECT bed_id FROM patients WHERE status='admitted' AND bed_id IS NOT NULL) ORDER BY id")]


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
def do_login(username: str):
    row = get_conn().execute("SELECT username,name,role FROM users WHERE username=?", (username,)).fetchone()
    st.session_state.user = dict(row)
    audit("login", "", username=username)
    st.rerun()


def login_screen():
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        hero("🏥 Quarantine Centre Tracker", "Temperatures · Rounds · Discharges · Outcomes")
        with st.form("login"):
            u = st.text_input("Username")
            p = st.text_input("Password", type="password")
            ok = st.form_submit_button("Sign in", type="primary", use_container_width=True)
        if ok:
            row = get_conn().execute("SELECT * FROM users WHERE username=? AND active=1", (u.strip(),)).fetchone()
            if row and hmac.compare_digest(hash_pw(p, row["salt"]), row["pw_hash"]):
                do_login(row["username"])
            else:
                audit("login_failed", u, username=u or "unknown")
                st.error("Invalid username or password.")
        demo_roles = [r for r in ROLES if configured_password(r) == DEFAULT_PASSWORDS[r]]
        if demo_roles:
            # login-page-only styling: big, full-width, easy-to-read buttons
            st.markdown("""<style>
            div[data-testid="stButton"] button {min-height: 3.4rem; font-size: 1.15rem; font-weight: 600;
                border-radius: 12px; justify-content: flex-start; padding-left: 1.2rem;}
            div[data-testid="stButton"] button p {font-size: 1.15rem;}
            </style>""", unsafe_allow_html=True)
            st.markdown("#### 🚀 Quick sign-in (demo mode)")
            st.caption("Default passwords are active – tap a role to try the app.")
            for r in demo_roles:
                label, emoji, desc = ROLE_INFO[r]
                first = next(u for u, _, rr in DEFAULT_USERS if rr == r)
                if st.button(f"{emoji}  {label}  –  {desc}", key=f"q{r}", use_container_width=True):
                    do_login(first)


# --------------------------------------------------------------------------
# Pages: NURSE
# --------------------------------------------------------------------------
def page_round():
    require("nurse")
    df = board()
    total, done = len(df), int((df.n_read > 0).sum())
    hero("🌡️ Temperature Round", f"{now():%A, %d %b %Y}  ·  type a temperature, tap Save")
    st.progress(done / total if total else 0.0, text=f"Temperatures taken: {done}/{total}")

    c1, c2 = st.columns([2, 3])
    q = c1.text_input("Search", placeholder="Name or bed…", label_visibility="collapsed")
    flt = c2.radio("Show", ["Pending", "Measured", "All"], horizontal=True, label_visibility="collapsed")
    view = df
    if flt == "Pending":
        view = df[df.n_read == 0]
    elif flt == "Measured":
        view = df[df.n_read > 0]
    if q:
        view = view[view.patient.str.contains(q, case=False) | view.bed_id.str.contains(q, case=False)]
    if view.empty:
        st.success("🎉 Nothing to show here – all done!" if flt == "Pending" else "No matching patients.")
        return

    thr = setting("fever_threshold", float)
    cols = st.columns(3)
    for i, r in enumerate(view.itertuples()):
        with cols[i % 3]:
            with st.container(border=True):
                st.markdown(f"**{esc(r.bed_id)}** · {esc(r.patient)} <span class='muted'>{r.age}y · day {r.day_no}</span>",
                            unsafe_allow_html=True)
                if r.n_read == 0:
                    t = st.number_input("Temp °C", 34.0, 43.0, value=None, step=0.1, format="%.1f",
                                        key=f"t{r.id}", placeholder="e.g. 37.4", label_visibility="collapsed")
                    if st.button("💾 Save", key=f"s{r.id}", disabled=t is None, use_container_width=True, type="primary"):
                        if record_temp(int(r.id), float(t), False):
                            st.toast(f"Saved {t:.1f}°C for {r.patient}" + ("  🔥 fever" if t >= thr else ""), icon="✅")
                            st.rerun()
                else:
                    color = "red" if r.fever_now else "green"
                    st.markdown(chip(f"{fmt_t(r.last_temp)} {'Fever' if r.fever_now else 'Normal'}", color)
                                + chip(f"{r.n_read} reading(s)", "gray"), unsafe_allow_html=True)
                    st.caption(f"By {r.measured_by} at {r.measured_at[11:16]}")
                    b1, b2 = st.columns(2)
                    with b1.popover("Re-measure", use_container_width=True):
                        st.warning("Already measured today – this adds an extra reading.")
                        t2 = st.number_input("Temp °C", 34.0, 43.0, value=None, step=0.1, format="%.1f", key=f"x{r.id}")
                        if st.button("Add reading", key=f"xs{r.id}", disabled=t2 is None):
                            if record_temp(int(r.id), float(t2), True):
                                st.rerun()
                    if r.last_read_by == me()["username"] and r.n_visit == 0:
                        if b2.button("↩ Undo", key=f"u{r.id}", use_container_width=True):
                            run("DELETE FROM readings WHERE id=?", (int(r.last_read_id),))
                            audit("undo_temp", f"patient={r.id} reading={r.last_read_id}")
                            st.rerun()


# --------------------------------------------------------------------------
# Pages: DOCTOR
# --------------------------------------------------------------------------
def page_rounds():
    require("doctor")
    df = board()
    hero("🩺 Doctor Rounds", "Only patients with a recorded temperature are open for a visit")
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Ready for visit", int((df.status == "ready").sum()))
    k2.metric("Waiting for temp", int((df.status == "pending").sum()))
    k3.metric("Visited today", int((df.status == "done").sum()))
    k4.metric("Discharge-ready", int(df.eligible.sum()))

    crit = df[df.critical]
    if not crit.empty:
        st.error("🚨 Critical temperature today: " + ", ".join(f"{r.bed_id} {r.patient} ({fmt_t(r.max_today)})" for r in crit.itertuples()))

    elig = df[df.eligible]
    if not elig.empty:
        with st.container(border=True):
            st.subheader(f"🏁 Ready to discharge ({len(elig)})")
            req = setting("required_days", int)
            for r in elig.itertuples():
                a, b = st.columns([4, 1])
                a.markdown(f"**{esc(r.bed_id)}** · {esc(r.patient)} — {r.streak} consecutive no-fever days (needs {req})")
                if b.button("Confirm discharge", key=f"dc{r.id}", type="primary", use_container_width=True):
                    if close_case(int(r.id), "cured", r.admit_date):
                        st.toast(f"{r.patient} discharged – front desk notified", icon="🏁")
                        st.rerun()

    ready = df[df.status == "ready"].sort_values(["critical", "fever_now", "eligible"], ascending=False)
    pending = df[df.status == "pending"]
    done = df[df.status == "done"]
    t1, t2, t3 = st.tabs([f"Ready ({len(ready)})", f"Waiting for temp ({len(pending)})", f"Visited ({len(done)})"])

    with t1:
        if ready.empty:
            st.info("No patients are waiting for you right now.")
        cols = st.columns(2)
        for i, r in enumerate(ready.itertuples()):
            with cols[i % 2]:
                with st.container(border=True):
                    tags = chip(fmt_t(r.last_temp), "red" if r.fever_now else "green")
                    tags += chip(f"{r.streak} no-fever days", "blue" if r.streak else "gray")
                    if r.critical:
                        tags += chip("CRITICAL", "red")
                    st.markdown(f"**{esc(r.bed_id)}** · {esc(r.patient)} <span class='muted'>{r.age}y · day {r.day_no}</span><br>{tags}",
                                unsafe_allow_html=True)
                    st.caption(f"Recent daily max: {r.trend}")
                    with st.expander("Record visit"):
                        with st.form(f"vf{r.id}", clear_on_submit=True):
                            tr = st.multiselect("Treatment", TREATMENTS)
                            notes = st.text_area("Notes", height=70)
                            if st.form_submit_button("Mark visited", type="primary"):
                                if not tr and not notes.strip():
                                    st.warning("Add a treatment or a note.")
                                elif record_visit(int(r.id), ", ".join(tr), notes.strip()):
                                    st.toast(f"Visit recorded for {r.patient}", icon="🩺")
                                    st.rerun()
                                else:
                                    st.error("Blocked: temperature not recorded.")
    with t2:
        if pending.empty:
            st.success("All temperatures are in ✅")
        else:
            st.caption("Visits are blocked here until a nurse records the temperature.")
            st.dataframe(pending[["bed_id", "patient", "age", "day_no", "trend"]].rename(columns={
                "bed_id": "Bed", "patient": "Patient", "age": "Age", "day_no": "Day", "trend": "Recent daily max"}),
                hide_index=True, use_container_width=True)
    with t3:
        if done.empty:
            st.info("No visits recorded yet today.")
        else:
            st.dataframe(done[["bed_id", "patient", "last_temp", "treatment"]].rename(columns={
                "bed_id": "Bed", "patient": "Patient", "last_temp": "Temp °C", "treatment": "Treatment"}),
                hide_index=True, use_container_width=True)


# --------------------------------------------------------------------------
# Pages: PATIENT LOOKUP (all roles)
# --------------------------------------------------------------------------
def page_lookup():
    hero("🔎 Patient Lookup", "Search by name or bed – full history in one place")
    pl = qdf("SELECT id,name,bed_id,status FROM patients ORDER BY (status='admitted') DESC, id DESC LIMIT 500")
    labels = {int(r.id): f"{r.bed_id or '—'} · {r.name} · {r.status}" for r in pl.itertuples()}
    pid = st.selectbox("Patient", list(labels), format_func=labels.get, index=None, placeholder="Type to search…")
    if pid is None:
        return
    p = get_conn().execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
    thr = setting("fever_threshold", float)
    streak, _ = streak_info(pid, p["admit_date"])
    last = one("SELECT value FROM readings WHERE patient_id=? ORDER BY recorded_at DESC, id DESC LIMIT 1", (pid,))
    end = date.fromisoformat(p["closed_at"][:10]) if p["closed_at"] else today()
    stay = (end - date.fromisoformat(p["admit_date"])).days + 1
    color = {"admitted": "blue", "discharged": "green", "deceased": "red"}[p["status"]]
    st.markdown(f"### {esc(p['name'])} {chip(p['status'].title(), color)}", unsafe_allow_html=True)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Bed", p["bed_id"] or "—")
    c2.metric("Age", p["age"])
    c3.metric("Days in centre", stay)
    c4.metric("No-fever streak", f"{streak} / {setting('required_days', int)}")
    c5.metric("Last temperature", fmt_t(last))

    d = qdf("SELECT day, MAX(value) AS max_temp FROM readings WHERE patient_id=? GROUP BY day ORDER BY day", (pid,))
    if d.empty:
        st.info("No readings yet.")
    else:
        d["fever threshold"] = thr
        st.line_chart(d.set_index("day"), height=240)
    t1, t2 = st.tabs(["Readings", "Doctor visits"])
    with t1:
        st.dataframe(qdf("SELECT recorded_at AS time, value AS temp_c, recorded_by AS by FROM readings WHERE patient_id=? ORDER BY recorded_at DESC", (pid,)),
                     hide_index=True, use_container_width=True)
    with t2:
        st.dataframe(qdf("SELECT visited_at AS time, doctor, treatment, notes FROM visits WHERE patient_id=? ORDER BY visited_at DESC", (pid,)),
                     hide_index=True, use_container_width=True)

    if me()["role"] == "doctor" and p["status"] == "admitted":
        with st.expander("⚠️ Close case"):
            a, b = st.columns(2)
            if a.button("✅ Confirm discharge (cured)", disabled=streak < setting("required_days", int), use_container_width=True):
                if close_case(pid, "cured", p["admit_date"]):
                    st.rerun()
            sure = b.checkbox("I confirm this patient has died")
            if b.button("Record death", disabled=not sure, use_container_width=True):
                if close_case(pid, "deceased", p["admit_date"]):
                    st.rerun()


# --------------------------------------------------------------------------
# Pages: FRONT DESK
# --------------------------------------------------------------------------
def bed_map_html(df: pd.DataFrame) -> str:
    occ = {r.bed_id: r for r in df.itertuples()}
    out = ['<div class="bedgrid">']
    for b in [r[0] for r in get_conn().execute("SELECT id FROM beds ORDER BY id")]:
        r = occ.get(b)
        if r is None:
            out.append(f'<div class="bed free"><b>{b}</b><br>free</div>')
        else:
            cls = "ready" if r.eligible else ("fever" if r.fever_now else "occ")
            out.append(f'<div class="bed {cls}"><b>{b}</b><br>{esc(r.patient.split()[0])}<br>{esc(fmt_t(r.last_temp))}</div>')
    out.append("</div>")
    return "".join(out)


def page_frontdesk():
    require("receptionist", "admin")
    df = board()
    free = free_beds()
    wl = qdf("SELECT * FROM waitlist WHERE status='waiting' ORDER BY (priority='High') DESC, added_at")
    pend = one("SELECT COUNT(*) FROM discharges WHERE admin_ack=0") or 0
    hero("🛎️ Front Desk", "Admissions, waitlist, beds and discharge notices")
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Free beds", f"{len(free)}/{TOTAL_BEDS}")
    k2.metric("Waitlist", len(wl))
    k3.metric("Freeing soon (discharge-ready)", int(df.eligible.sum()))
    k4.metric("Discharge notices", int(pend))

    t1, t2, t3, t4 = st.tabs(["➕ Admit", f"⏳ Waitlist ({len(wl)})", "🛏️ Bed map", f"📨 Discharge notices ({pend})"])
    with t1:
        if not free:
            st.warning("No free beds. Add the patient to the waitlist.")
        else:
            if not wl.empty:
                nxt = wl.iloc[0]
                with st.container(border=True):
                    st.markdown(f"**Next on waitlist:** {esc(nxt['name'])} ({nxt['age']}y) {chip(nxt['priority'], 'red' if nxt['priority'] == 'High' else 'gray')}",
                                unsafe_allow_html=True)
                    if st.button(f"Admit to {free[0]}", type="primary"):
                        if admit_patient(nxt["name"], nxt["age"], nxt["contact"] or "", free[0]):
                            run("UPDATE waitlist SET status='admitted' WHERE id=?", (int(nxt["id"]),))
                            st.toast("Admitted from waitlist", icon="✅")
                            st.rerun()
            with st.form("admit", clear_on_submit=True):
                c1, c2 = st.columns(2)
                name = c1.text_input("Full name")
                age = c2.number_input("Age", 0, 120, 30)
                contact = c1.text_input("Contact number")
                bed = c2.selectbox("Bed", free)
                if st.form_submit_button("Admit patient", type="primary"):
                    if not name.strip():
                        st.error("Name is required.")
                    elif admit_patient(name, age, contact, bed):
                        st.toast(f"Admitted {name} to {bed}", icon="✅")
                        st.rerun()
    with t2:
        with st.form("wl_add", clear_on_submit=True):
            c1, c2, c3, c4 = st.columns([3, 1, 2, 1.4])
            n = c1.text_input("Name")
            a = c2.number_input("Age", 0, 120, 30)
            ct = c3.text_input("Contact")
            pr = c4.selectbox("Priority", ["Normal", "High"])
            if st.form_submit_button("Add to waitlist"):
                if n.strip():
                    run("INSERT INTO waitlist(name,age,contact,priority,added_at) VALUES (?,?,?,?,?)", (n.strip(), int(a), ct.strip(), pr, iso(now())))
                    audit("waitlist_add", n.strip())
                    st.rerun()
                else:
                    st.error("Name is required.")
        for r in wl.itertuples():
            a, b, c = st.columns([4, 1.4, 1])
            a.markdown(f"**{esc(r.name)}** ({r.age}y) {chip(r.priority, 'red' if r.priority == 'High' else 'gray')} <span class='muted'>{esc(r.contact or '')}</span>",
                       unsafe_allow_html=True)
            if b.button("Admit", key=f"wa{r.id}", disabled=not free):
                if admit_patient(r.name, r.age, r.contact or "", free[0]):
                    run("UPDATE waitlist SET status='admitted' WHERE id=?", (int(r.id),))
                    st.rerun()
            if c.button("✖", key=f"wr{r.id}"):
                run("UPDATE waitlist SET status='removed' WHERE id=?", (int(r.id),))
                audit("waitlist_remove", str(r.id))
                st.rerun()
    with t3:
        st.markdown(chip("free", "green") + chip("occupied", "gray") + chip("fever today", "red") + chip("discharge-ready", "blue"), unsafe_allow_html=True)
        st.markdown(bed_map_html(df), unsafe_allow_html=True)
    with t4:
        n = qdf("""SELECT d.id, p.name AS patient, d.outcome, d.confirmed_by, d.closed_at
                   FROM discharges d JOIN patients p ON p.id=d.patient_id WHERE d.admin_ack=0 ORDER BY d.closed_at DESC""")
        if n.empty:
            st.success("No pending notices.")
        for r in n.itertuples():
            a, b = st.columns([4, 1])
            a.markdown(f"{'✅' if r.outcome == 'cured' else '🕊️'} **{esc(r.patient)}** – {r.outcome} · by {esc(r.confirmed_by)} at {r.closed_at[11:16]}")
            if b.button("Acknowledge", key=f"ack{r.id}"):
                run("UPDATE discharges SET admin_ack=1, ack_by=?, ack_at=? WHERE id=?", (me()["username"], iso(now()), int(r.id)))
                audit("ack_discharge", f"discharge={r.id}")
                st.rerun()


# --------------------------------------------------------------------------
# Pages: DASHBOARD
# --------------------------------------------------------------------------
def page_dashboard():
    require("doctor", "supervisor", "admin")
    df = board()
    t = today().isoformat()
    cutoff = (today() - timedelta(days=30)).isoformat()
    hero("📊 Performance Dashboard", "Capacity, process quality and outcomes vs the 85% / 15% benchmark")

    occ = len(df)
    pend = int((df.n_read == 0).sum())
    dup = one("SELECT COALESCE(SUM(c-1),0) FROM (SELECT COUNT(*) c FROM readings WHERE day=? GROUP BY patient_id)", (t,)) or 0
    blocked = one("SELECT COUNT(*) FROM audit WHERE action='visit_blocked' AND substr(ts,1,10)=?", (t,)) or 0
    c = st.columns(5)
    c[0].metric("Occupancy", f"{occ}/{TOTAL_BEDS}")
    c[1].metric("Temp coverage today", f"{100 * (occ - pend) / occ:.0f}%" if occ else "–")
    c[2].metric("Duplicate readings", int(dup))
    c[3].metric("Blocked early visits", int(blocked))
    c[4].metric("Discharge-ready", int(df.eligible.sum()))

    out = dict(get_conn().execute("SELECT outcome, COUNT(*) FROM discharges WHERE substr(closed_at,1,10)>=? GROUP BY outcome", (cutoff,)).fetchall())
    cured, dead = out.get("cured", 0), out.get("deceased", 0)
    closed = cured + dead
    st.subheader("Treatment quality · rolling 30 days")
    if closed == 0:
        st.info("No closed cases in the last 30 days.")
    else:
        mort = dead / closed
        m1, m2, m3 = st.columns(3)
        m1.metric("Mortality", f"{mort:.1%}", f"{dead}/{closed} cases", delta_color="off")
        m2.metric("Cure rate", f"{cured / closed:.1%}", f"{cured}/{closed} cases", delta_color="off")
        m3.metric("Benchmark", f"≤ {BENCHMARK:.0%} mortality")
        st.progress(min(mort / (2 * BENCHMARK), 1.0), text=f"Mortality {mort:.1%} (the {BENCHMARK:.0%} benchmark sits at the halfway mark)")
        if mort > BENCHMARK:
            st.error(f"🚨 Mortality {mort:.1%} ({dead}/{closed}) is ABOVE the {BENCHMARK:.0%} benchmark – review treatment protocols.")
        else:
            st.success(f"Mortality {mort:.1%} ({dead}/{closed}) is within the {BENCHMARK:.0%} benchmark.")
        if closed < 20:
            st.caption("⚠️ Small sample – interpret with caution.")

    lag = one("""SELECT AVG(julianday(substr(closed_at,1,10)) - julianday(eligible_since)) FROM discharges
                 WHERE outcome='cured' AND eligible_since IS NOT NULL AND substr(closed_at,1,10)>=?""", (cutoff,))
    los = one("""SELECT AVG(julianday(substr(closed_at,1,10)) - julianday(admit_date)) FROM patients
                 WHERE closed_at IS NOT NULL AND substr(closed_at,1,10)>=?""", (cutoff,))
    s1, s2, s3 = st.columns(3)
    s1.metric("Avg discharge lag (days)", f"{lag:.1f}" if lag is not None else "–")
    s2.metric("Avg length of stay (days)", f"{los:.1f}" if los is not None else "–")
    s3.metric("Fever today (admitted)", int(df.fever_now.sum()))

    st.subheader("Patient flow · last 14 days")
    days = [(today() - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    adm = dict(get_conn().execute("SELECT admit_date, COUNT(*) FROM patients GROUP BY admit_date").fetchall())
    flow = pd.DataFrame({"Admitted": [adm.get(d, 0) for d in days], "Discharged": 0, "Deaths": 0}, index=days)
    for d, o, n in get_conn().execute("SELECT substr(closed_at,1,10), outcome, COUNT(*) FROM discharges GROUP BY 1,2"):
        if d in flow.index:
            flow.loc[d, "Discharged" if o == "cured" else "Deaths"] = n
    st.bar_chart(flow)

    a, b = st.columns(2)
    with a:
        st.subheader("Today's task status")
        st.bar_chart(df.status.map({"pending": "Needs temp", "ready": "Ready for doctor", "done": "Done"}).value_counts())
    with b:
        st.subheader("No-fever streak (admitted)")
        st.bar_chart(df.streak.value_counts().sort_index())


# --------------------------------------------------------------------------
# Pages: REPORTS & AUDIT
# --------------------------------------------------------------------------
def page_reports():
    require("supervisor", "admin")
    hero("📑 Reports & Audit", "Download data and review every action taken in the system")
    t1, t2 = st.tabs(["⬇️ Export", "🧾 Audit log"])
    with t1:
        sets = {
            "Patients": "SELECT id,name,age,contact,admit_date,bed_id,status,closed_at FROM patients",
            "Temperature readings": "SELECT r.id, p.name AS patient, r.value, r.recorded_by, r.recorded_at FROM readings r JOIN patients p ON p.id=r.patient_id",
            "Doctor visits": "SELECT v.id, p.name AS patient, v.doctor, v.visited_at, v.treatment, v.notes FROM visits v JOIN patients p ON p.id=v.patient_id",
            "Outcomes": "SELECT p.name AS patient, d.outcome, d.eligible_since, d.confirmed_by, d.closed_at FROM discharges d JOIN patients p ON p.id=d.patient_id",
        }
        for name, sql in sets.items():
            data = qdf(sql)
            a, b = st.columns([4, 1])
            a.markdown(f"**{name}** · {len(data)} rows")
            b.download_button("CSV", data.to_csv(index=False).encode(), f"{name.lower().replace(' ', '_')}.csv", "text/csv", key=f"dl{name}")
    with t2:
        df = qdf("SELECT ts, username, action, detail FROM audit ORDER BY id DESC LIMIT 2000")
        c1, c2 = st.columns(2)
        acts = c1.multiselect("Action", sorted(df.action.unique()))
        users = c2.multiselect("User", sorted(df.username.unique()))
        if acts:
            df = df[df.action.isin(acts)]
        if users:
            df = df[df.username.isin(users)]
        st.dataframe(df, hide_index=True, use_container_width=True)


# --------------------------------------------------------------------------
# Pages: ADMIN
# --------------------------------------------------------------------------
def page_admin():
    require("admin")
    hero("⚙️ Users & Settings", "Clinical rules, staff accounts and data")
    t1, t2, t3 = st.tabs(["Clinical rules", "Users", "Danger zone"])
    with t1:
        with st.form("settings"):
            c1, c2 = st.columns(2)
            thr = c1.number_input("Fever threshold (°C)", 36.5, 40.0, setting("fever_threshold", float), 0.1)
            crit = c2.number_input("Critical temperature (°C)", 38.5, 43.0, setting("critical_temp", float), 0.1)
            req = c1.number_input("No-fever days required for discharge", 1, 14, setting("required_days", int))
            inc = c2.checkbox("Count today once a reading is recorded", value=setting("include_today", int) == 1)
            if st.form_submit_button("Save", type="primary"):
                for k, v in {"fever_threshold": thr, "critical_temp": crit, "required_days": int(req), "include_today": int(inc)}.items():
                    run("INSERT OR REPLACE INTO settings VALUES (?,?)", (k, str(v)))
                audit("update_settings", f"thr={thr} crit={crit} req={req} include_today={inc}")
                st.success("Saved.")
    with t2:
        users = qdf("SELECT username, name, role, active FROM users ORDER BY role, username")
        st.dataframe(users, hide_index=True, use_container_width=True)
        with st.form("newuser", clear_on_submit=True):
            c1, c2 = st.columns(2)
            un = c1.text_input("Username")
            nm = c2.text_input("Display name")
            rl = c1.selectbox("Role", ROLES, format_func=lambda r: f"{ROLE_INFO[r][1]} {ROLE_INFO[r][0]} – {ROLE_INFO[r][2]}")
            pw = c2.text_input("Password (min 8 chars)", type="password")
            if st.form_submit_button("Create / reset user"):
                if not un.strip() or len(pw) < 8:
                    st.error("Username required; password needs at least 8 characters.")
                else:
                    make_user(get_conn(), un.strip(), nm.strip() or un.strip(), rl, pw)
                    get_conn().commit()
                    audit("upsert_user", f"{un.strip()} role={rl}")
                    st.success("User saved.")
        a, b = st.columns([3, 1])
        target = a.selectbox("Activate / deactivate", [u for u in users.username if u != me()["username"]])
        if b.button("Toggle active", use_container_width=True) and target:
            run("UPDATE users SET active = 1 - active WHERE username=?", (target,))
            audit("toggle_user", target)
            st.rerun()
    with t3:
        ok = st.checkbox("I understand this wipes all patient data and reloads demo data")
        if st.button("Reset demo data", disabled=not ok):
            seed_demo(get_conn())
            audit("reset_demo", "")
            st.success("Demo data reloaded.")


# --------------------------------------------------------------------------
# Navigation (RBAC registry) + main
# --------------------------------------------------------------------------
PAGES = {
    "🌡️ Temperature Round": (page_round, {"nurse"}),
    "🩺 Doctor Rounds": (page_rounds, {"doctor"}),
    "🛎️ Front Desk": (page_frontdesk, {"receptionist", "admin"}),
    "📊 Dashboard": (page_dashboard, {"doctor", "supervisor", "admin"}),
    "🔎 Patients": (page_lookup, set(ROLES)),
    "📑 Reports & Audit": (page_reports, {"supervisor", "admin"}),
    "⚙️ Users & Settings": (page_admin, {"admin"}),
}


def change_password_ui():
    with st.popover("🔑 Change password", use_container_width=True):
        cur = st.text_input("Current password", type="password", key="cp0")
        new = st.text_input("New password (min 8)", type="password", key="cp1")
        if st.button("Update", key="cp2"):
            row = get_conn().execute("SELECT salt, pw_hash FROM users WHERE username=?", (me()["username"],)).fetchone()
            if not hmac.compare_digest(hash_pw(cur, row["salt"]), row["pw_hash"]):
                st.error("Current password is wrong.")
            elif len(new) < 8:
                st.error("New password is too short.")
            else:
                salt = pysecrets.token_hex(16)
                run("UPDATE users SET salt=?, pw_hash=? WHERE username=?", (salt, hash_pw(new, salt), me()["username"]))
                audit("change_password", "")
                st.success("Password updated.")


def main():
    get_conn()
    if not st.session_state.get("user"):
        login_screen()
        return
    user = me()
    label, emoji, _ = ROLE_INFO[user["role"]]
    allowed = [n for n, (_, roles) in PAGES.items() if user["role"] in roles]
    with st.sidebar:
        st.markdown(f"## 🏥 Centre Tracker\n**{emoji} {user['name']}**  \n{chip(label, 'blue')}", unsafe_allow_html=True)
        choice = st.radio("Go to", allowed, label_visibility="collapsed")
        st.divider()
        b = board()
        st.caption(f"🛏️ {len(b)}/{TOTAL_BEDS} beds · ⏳ {int((b.n_read == 0).sum())} temps pending · 🏁 {int(b.eligible.sum())} discharge-ready")
        if user["role"] in ("receptionist", "admin"):
            pend = one("SELECT COUNT(*) FROM discharges WHERE admin_ack=0") or 0
            if pend:
                st.warning(f"🔔 {pend} discharge notice(s)")
        st.caption(f"{now():%d %b %Y, %H:%M} IST")
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
        change_password_ui()
        if st.button("Log out", use_container_width=True):
            audit("logout", "")
            st.session_state.clear()
            st.rerun()
    func, roles = PAGES[choice]
    if user["role"] not in roles:
        audit("access_denied", choice)
        st.error("You do not have permission to view this page.")
        return
    func()


main()
