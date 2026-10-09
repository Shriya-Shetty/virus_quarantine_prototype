"""
Quarantine & Treatment Facility Tracker  (single-file Streamlit app)

Roles (RBAC)
  nurse  : record daily temperatures, view patient trends
  doctor : see "ready for visit" patients (visit blocked until temp exists),
           record visits/treatment, confirm discharge (cured) or record death
  admin  : dashboard & KPIs, admissions/bed map, discharge desk, audit log,
           user management & settings

Business rules
  - Fever day      : any reading that day >= fever threshold (default 38.0 C)
  - No-fever day   : >= 1 reading that day, all below threshold
  - Missing day    : breaks the streak
  - Discharge-ready: streak >= required days (default 3)
  - Mortality rate : deaths / (deaths + cured) over a rolling 30-day window

Run locally :  streamlit run app.py
Deploy      :  push app.py + requirements.txt to GitHub -> share.streamlit.io
NOTE: SQLite on Streamlit Community Cloud is ephemeral (resets on reboot).
      For production swap the DB layer for Postgres/Supabase.
"""
import hashlib
import hmac
import os
import random
import secrets as pysecrets
import sqlite3
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
st.set_page_config(page_title="Quarantine Centre Tracker", page_icon="🏥", layout="wide")

TZ = ZoneInfo("Asia/Kolkata")
DB_PATH = os.environ.get("DB_PATH", "quarantine.db")
TOTAL_BEDS = 74
MORTALITY_BENCHMARK = 0.15
ROLES = ["nurse", "doctor", "admin"]

DEFAULT_PASSWORDS = {"nurse": "nurse123", "doctor": "doctor123", "admin": "admin123"}
DEFAULT_USERS = [
    ("nurse1", "Nurse Priya", "nurse"),
    ("nurse2", "Nurse Arjun", "nurse"),
    ("doctor1", "Dr. Rao", "doctor"),
    ("doctor2", "Dr. Mehta", "doctor"),
    ("admin1", "Admin Kavita", "admin"),
]


def now() -> datetime:
    return datetime.now(TZ)


def today() -> date:
    return now().date()


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Database layer
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY, name TEXT, role TEXT, salt TEXT, pw_hash TEXT);
CREATE TABLE IF NOT EXISTS beds(id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS patients(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER, admit_date TEXT,
  bed_id TEXT, status TEXT DEFAULT 'admitted', closed_at TEXT);
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
"""


def hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000).hex()


def _configured_password(role: str) -> str:
    try:
        return st.secrets["passwords"][role]
    except Exception:
        return DEFAULT_PASSWORDS[role]


@st.cache_resource
def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        for username, name, role in DEFAULT_USERS:
            salt = pysecrets.token_hex(16)
            conn.execute(
                "INSERT INTO users VALUES (?,?,?,?,?)",
                (username, name, role, salt, hash_pw(_configured_password(role), salt)),
            )
        for k, v in {"fever_threshold": "38.0", "required_days": "3", "include_today": "0"}.items():
            conn.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (k, v))
        conn.commit()
        seed_demo(conn)
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


def audit(action: str, detail: str = "", username: str | None = None):
    if username is None:
        u = st.session_state.get("user")
        username = u["username"] if u else "system"
    run("INSERT INTO audit(ts,username,action,detail) VALUES (?,?,?,?)",
        (iso(now()), username, action, detail))


# --------------------------------------------------------------------------
# Demo data
# --------------------------------------------------------------------------
FIRST = ["Aarav", "Vihaan", "Aditya", "Ishaan", "Rohan", "Kabir", "Arjun", "Sai", "Ananya", "Diya",
         "Isha", "Meera", "Priya", "Riya", "Saanvi", "Tara", "Neha", "Kavya", "Rahul", "Sneha"]
LAST = ["Sharma", "Patel", "Iyer", "Nair", "Reddy", "Khan", "Gupta", "Desai", "Joshi", "Menon",
        "Kulkarni", "Singh", "Verma", "Shah", "Pillai", "Bose"]


def seed_demo(conn: sqlite3.Connection):
    """Fill the DB with 74 admitted patients + 30 days of closed cases."""
    rnd = random.Random(7)
    for t in ["readings", "visits", "discharges", "patients", "beds", "audit"]:
        conn.execute(f"DELETE FROM {t}")
    for i in range(1, TOTAL_BEDS + 1):
        conn.execute("INSERT INTO beds VALUES (?)", (f"B{i:02d}",))
    t0 = today()

    def ts(d: date, h=None):
        h = h if h is not None else rnd.randint(7, 11)
        return iso(datetime(d.year, d.month, d.day, h, rnd.randint(0, 59), tzinfo=TZ))

    for i in range(1, TOTAL_BEDS + 1):
        admit = t0 - timedelta(days=rnd.randint(0, 9))
        pid = conn.execute(
            "INSERT INTO patients(name,age,admit_date,bed_id,status) VALUES (?,?,?,?, 'admitted')",
            (f"{rnd.choice(FIRST)} {rnd.choice(LAST)}", rnd.randint(8, 82), admit.isoformat(), f"B{i:02d}"),
        ).lastrowid
        recover_idx = rnd.randint(2, 9)
        d = admit
        while d < t0:
            if rnd.random() > 0.06:  # occasional missed measurement
                fever = (d - admit).days < recover_idx
                val = round(rnd.uniform(38.2, 39.8) if fever else rnd.uniform(36.4, 37.6), 1)
                conn.execute("INSERT INTO readings(patient_id,value,recorded_by,recorded_at,day) VALUES (?,?,?,?,?)",
                             (pid, val, rnd.choice(["nurse1", "nurse2"]), ts(d), d.isoformat()))
            d += timedelta(days=1)
        if rnd.random() < 0.5:  # today's temp already taken for ~half
            fever = (t0 - admit).days < recover_idx
            val = round(rnd.uniform(38.2, 39.8) if fever else rnd.uniform(36.4, 37.6), 1)
            conn.execute("INSERT INTO readings(patient_id,value,recorded_by,recorded_at,day) VALUES (?,?,?,?,?)",
                         (pid, val, rnd.choice(["nurse1", "nurse2"]), ts(t0, 8), t0.isoformat()))
            if rnd.random() < 0.4:
                conn.execute("INSERT INTO visits(patient_id,doctor,visited_at,day,notes,treatment) VALUES (?,?,?,?,?,?)",
                             (pid, "doctor1", ts(t0, 11), t0.isoformat(), "Stable", "Fluids, antipyretics"))

    for _ in range(70):  # historical closed cases for the mortality KPI
        closed_day = t0 - timedelta(days=rnd.randint(0, 29))
        admit = closed_day - timedelta(days=rnd.randint(4, 12))
        dead = rnd.random() < 0.13
        pid = conn.execute(
            "INSERT INTO patients(name,age,admit_date,bed_id,status,closed_at) VALUES (?,?,?,?,?,?)",
            (f"{rnd.choice(FIRST)} {rnd.choice(LAST)}", rnd.randint(8, 82), admit.isoformat(), None,
             "deceased" if dead else "discharged", ts(closed_day, 14)),
        ).lastrowid
        elig = None if dead else (closed_day - timedelta(days=rnd.randint(0, 1))).isoformat()
        conn.execute(
            "INSERT INTO discharges(patient_id,eligible_since,confirmed_by,outcome,closed_at,admin_ack) VALUES (?,?,?,?,?,1)",
            (pid, elig, "doctor1", "deceased" if dead else "cured", ts(closed_day, 14)),
        )
    conn.commit()


# --------------------------------------------------------------------------
# Business logic
# --------------------------------------------------------------------------
def streak_info(patient_id: int, admit_date: str):
    """Return (streak_length, list_of_no_fever_days newest-first)."""
    thr = setting("fever_threshold", float)
    include_today = setting("include_today", int) == 1
    mx = dict(get_conn().execute(
        "SELECT day, MAX(value) FROM readings WHERE patient_id=? GROUP BY day", (patient_id,)).fetchall())
    admit = date.fromisoformat(admit_date)
    d = today() if include_today else today() - timedelta(days=1)
    days = []
    while d >= admit:
        key = d.isoformat()
        if key not in mx:
            if d == today():  # today's reading simply not taken yet
                d -= timedelta(days=1)
                continue
            break  # missing day breaks the streak
        if mx[key] >= thr:
            break
        days.append(d)
        d -= timedelta(days=1)
    return len(days), days


def board() -> pd.DataFrame:
    """One row per admitted patient with today's task state + discharge eligibility."""
    df = qdf(
        """
        SELECT p.id, p.name AS patient, p.age, p.bed_id, p.admit_date,
          (SELECT COUNT(*) FROM readings r WHERE r.patient_id=p.id AND r.day=:d) AS n_read,
          (SELECT value FROM readings r WHERE r.patient_id=p.id AND r.day=:d ORDER BY recorded_at DESC LIMIT 1) AS last_temp,
          (SELECT recorded_by FROM readings r WHERE r.patient_id=p.id AND r.day=:d ORDER BY recorded_at ASC LIMIT 1) AS measured_by,
          (SELECT recorded_at FROM readings r WHERE r.patient_id=p.id AND r.day=:d ORDER BY recorded_at ASC LIMIT 1) AS measured_at,
          (SELECT COUNT(*) FROM visits v WHERE v.patient_id=p.id AND v.day=:d) AS n_visit
        FROM patients p WHERE p.status='admitted' ORDER BY p.bed_id
        """,
        {"d": today().isoformat()},
    )
    req = setting("required_days", int)
    res = [streak_info(r.id, r.admit_date)[0] for r in df.itertuples()]
    df["streak"] = res
    df["eligible"] = df["streak"] >= req

    def status(r):
        if r.n_visit > 0:
            return "✅ Done"
        if r.n_read > 0:
            return "🩺 Ready for doctor"
        return "⏳ Pending temp"

    df["status"] = df.apply(status, axis=1)
    return df


def close_case(patient_id: int, outcome: str, admit_date: str):
    """outcome: 'cured' or 'deceased'. Frees the bed and notifies admin."""
    user = st.session_state.user
    eligible_since = None
    if outcome == "cured":
        n, days = streak_info(patient_id, admit_date)
        req = setting("required_days", int)
        if n >= req:
            eligible_since = days[n - req].isoformat()
    run("UPDATE patients SET status=?, closed_at=?, bed_id=NULL WHERE id=?",
        ("discharged" if outcome == "cured" else "deceased", iso(now()), patient_id))
    run("INSERT INTO discharges(patient_id,eligible_since,confirmed_by,outcome,closed_at) VALUES (?,?,?,?,?)",
        (patient_id, eligible_since, user["username"], outcome, iso(now())))
    audit("close_case", f"patient={patient_id} outcome={outcome}")


# --------------------------------------------------------------------------
# Auth + RBAC
# --------------------------------------------------------------------------
def login_screen():
    st.title("🏥 Quarantine Centre Tracker")
    st.caption("Sign in with your staff account.")
    with st.form("login"):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        ok = st.form_submit_button("Sign in", type="primary")
    if ok:
        row = get_conn().execute("SELECT * FROM users WHERE username=?", (u.strip(),)).fetchone()
        if row and hmac.compare_digest(hash_pw(p, row["salt"]), row["pw_hash"]):
            st.session_state.user = {"username": row["username"], "name": row["name"], "role": row["role"]}
            audit("login", "")
            st.rerun()
        else:
            audit("login_failed", u, username=u or "unknown")
            st.error("Invalid username or password.")
    if all(_configured_password(r) == DEFAULT_PASSWORDS[r] for r in ROLES):
        with st.expander("Demo accounts (default passwords – change before real use)"):
            st.code("nurse1 / nurse123\ndoctor1 / doctor123\nadmin1 / admin123")


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------
def page_worklist():
    st.header("🌡️ Temperature Worklist")
    df = board()
    thr = setting("fever_threshold", float)
    c1, c2, c3 = st.columns(3)
    c1.metric("Admitted", len(df))
    c2.metric("Pending temp", int((df.n_read == 0).sum()))
    c3.metric("Measured today", int((df.n_read > 0).sum()))

    st.subheader("Record a temperature")
    order = df.sort_values(["n_read", "bed_id"])
    labels = {int(r.id): f"{r.bed_id} · {r.patient} · {r.status}" for r in order.itertuples()}
    with st.form("temp_form", clear_on_submit=True):
        pid = st.selectbox("Patient (pending first)", list(labels), format_func=labels.get)
        temp = st.number_input("Temperature (°C)", 34.0, 43.0, 37.0, 0.1)
        extra = st.checkbox("Already measured today – record an extra reading anyway")
        sub = st.form_submit_button("Save reading", type="primary")
    if sub:
        r = df[df.id == pid].iloc[0]
        if r.n_read > 0 and not extra:
            st.warning(f"⚠️ {r.patient} was already measured today at "
                       f"{r.measured_at[11:16]} by {r.measured_by} ({r.last_temp} °C). "
                       "Tick the box to record an extra reading.")
        else:
            run("INSERT INTO readings(patient_id,value,recorded_by,recorded_at,day) VALUES (?,?,?,?,?)",
                (pid, temp, st.session_state.user["username"], iso(now()), today().isoformat()))
            audit("record_temp", f"patient={pid} value={temp}" + (" (duplicate)" if r.n_read > 0 else ""))
            st.success(f"Saved {temp} °C for {r.patient}." + ("  🔥 Fever" if temp >= thr else ""))

    st.subheader("Today's board")
    flt = st.radio("Filter", ["All", "Pending temp", "Ready for doctor", "Done"], horizontal=True)
    view = board()
    if flt != "All":
        view = view[view.status.str.contains(flt)]
    st.dataframe(
        view[["bed_id", "patient", "age", "status", "last_temp", "n_read", "measured_by", "streak"]]
        .rename(columns={"bed_id": "Bed", "patient": "Patient", "age": "Age", "status": "Status",
                         "last_temp": "Last °C", "n_read": "# readings", "measured_by": "By",
                         "streak": "No-fever days"}),
        use_container_width=True, hide_index=True)


def page_rounds():
    st.header("🩺 Doctor Rounds")
    df = board()
    ready = df[df.status == "🩺 Ready for doctor"]
    blocked = df[df.status == "⏳ Pending temp"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Ready for visit", len(ready))
    c2.metric("Waiting on temperature", len(blocked))
    c3.metric("Visited today", int((df.status == "✅ Done").sum()))

    st.subheader("Ready for visit")
    st.dataframe(ready[["bed_id", "patient", "age", "last_temp", "streak", "eligible"]]
                 .rename(columns={"bed_id": "Bed", "patient": "Patient", "age": "Age", "last_temp": "Temp °C",
                                  "streak": "No-fever days", "eligible": "Discharge ready"}),
                 use_container_width=True, hide_index=True)

    st.subheader("Record a visit")
    todo = df[df.n_visit == 0].sort_values(["n_read", "bed_id"], ascending=[False, True])
    if todo.empty:
        st.success("All patients visited today 🎉")
        return
    labels = {int(r.id): f"{r.bed_id} · {r.patient} · {r.status}" for r in todo.itertuples()}
    pid = st.selectbox("Patient", list(labels), format_func=labels.get)
    r = df[df.id == pid].iloc[0]
    hist = qdf("SELECT recorded_at, value, recorded_by FROM readings WHERE patient_id=? ORDER BY recorded_at DESC LIMIT 12",
               (int(pid),))
    st.caption("Recent readings")
    st.dataframe(hist, hide_index=True, use_container_width=True)
    with st.form("visit_form", clear_on_submit=True):
        notes = st.text_area("Clinical notes")
        treatment = st.text_area("Treatment administered / plan")
        sub = st.form_submit_button("Mark visited", type="primary")
    if sub:
        if r.n_read == 0:
            audit("visit_blocked", f"patient={pid} no temperature yet")
            st.error("🚫 Blocked: this patient's temperature has not been recorded yet. "
                     "Ask a nurse to measure first.")
        else:
            run("INSERT INTO visits(patient_id,doctor,visited_at,day,notes,treatment) VALUES (?,?,?,?,?,?)",
                (int(pid), st.session_state.user["username"], iso(now()), today().isoformat(), notes, treatment))
            audit("doctor_visit", f"patient={pid}")
            st.success(f"Visit recorded for {r.patient}.")
            if r.eligible:
                st.info("🏁 This patient meets the discharge criterion – see *Discharge Queue*.")


def page_discharge_queue():
    st.header("🏁 Discharge Queue")
    df = board()
    req = setting("required_days", int)
    elig = df[df.eligible]
    st.write(f"Patients with **{req}+ consecutive no-fever days** (fever threshold "
             f"{setting('fever_threshold', float)} °C):")
    if elig.empty:
        st.info("No patients are eligible for discharge right now.")
    for r in elig.itertuples():
        c1, c2 = st.columns([4, 1])
        c1.markdown(f"**{r.bed_id} · {r.patient}** ({r.age}) — {r.streak} no-fever days")
        if c2.button("Confirm discharge", key=f"dc{r.id}", type="primary"):
            close_case(int(r.id), "cured", r.admit_date)
            st.success(f"{r.patient} discharged. Admin notified, bed {r.bed_id} freed.")
            st.rerun()

    st.divider()
    st.subheader("Record a death")
    with st.form("death_form"):
        opts = {int(r.id): f"{r.bed_id} · {r.patient}" for r in df.itertuples()}
        pid = st.selectbox("Patient", list(opts), format_func=opts.get)
        sure = st.checkbox("I confirm this patient has died")
        sub = st.form_submit_button("Record outcome: deceased")
    if sub:
        if not sure:
            st.warning("Tick the confirmation box first.")
        else:
            r = df[df.id == pid].iloc[0]
            close_case(int(pid), "deceased", r.admit_date)
            st.success("Outcome recorded. Bed freed.")
            st.rerun()


def page_trend():
    st.header("📈 Patient Fever Trend")
    df = qdf("SELECT id, name, bed_id FROM patients WHERE status='admitted' ORDER BY bed_id")
    if df.empty:
        st.info("No admitted patients.")
        return
    opts = {int(r.id): f"{r.bed_id} · {r.name}" for r in df.itertuples()}
    pid = st.selectbox("Patient", list(opts), format_func=opts.get)
    thr = setting("fever_threshold", float)
    d = qdf("SELECT day, MAX(value) AS max_temp FROM readings WHERE patient_id=? GROUP BY day ORDER BY day", (int(pid),))
    if d.empty:
        st.info("No readings yet.")
        return
    d["fever_threshold"] = thr
    st.line_chart(d.set_index("day"))
    adm = one("SELECT admit_date FROM patients WHERE id=?", (int(pid),))
    n, _ = streak_info(int(pid), adm)
    st.metric("Consecutive no-fever days", n)
    st.dataframe(qdf("SELECT recorded_at, value, recorded_by FROM readings WHERE patient_id=? ORDER BY recorded_at DESC",
                     (int(pid),)), hide_index=True, use_container_width=True)


def page_dashboard():
    st.header("📊 Performance Dashboard")
    df = board()
    t = today().isoformat()
    cutoff = (today() - timedelta(days=30)).isoformat()

    occ = len(df)
    pend = int((df.n_read == 0).sum())
    cov = 100 * (occ - pend) / occ if occ else 0
    dup = one("SELECT COALESCE(SUM(c-1),0) FROM (SELECT COUNT(*) c FROM readings WHERE day=? GROUP BY patient_id)", (t,)) or 0
    blocked = one("SELECT COUNT(*) FROM audit WHERE action='visit_blocked' AND substr(ts,1,10)=?", (t,)) or 0

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Occupancy", f"{occ}/{TOTAL_BEDS}")
    c2.metric("Temp coverage today", f"{cov:.0f}%")
    c3.metric("Duplicate readings today", int(dup))
    c4.metric("Blocked early visits today", int(blocked))
    c5.metric("Discharge-ready", int(df.eligible.sum()))

    out = dict(get_conn().execute(
        "SELECT outcome, COUNT(*) FROM discharges WHERE substr(closed_at,1,10)>=? GROUP BY outcome", (cutoff,)).fetchall())
    cured, dead = out.get("cured", 0), out.get("deceased", 0)
    closed = cured + dead
    st.subheader("Treatment quality (rolling 30 days)")
    if closed == 0:
        st.info("No closed cases in the last 30 days.")
    else:
        mort = dead / closed
        m1, m2, m3 = st.columns(3)
        m1.metric("Mortality rate", f"{mort:.1%}", f"{dead}/{closed} cases", delta_color="off")
        m2.metric("Cure rate", f"{cured / closed:.1%}", f"{cured}/{closed} cases", delta_color="off")
        m3.metric("Benchmark", f"≤ {MORTALITY_BENCHMARK:.0%} mortality")
        if mort > MORTALITY_BENCHMARK:
            st.error(f"🚨 Mortality {mort:.1%} ({dead}/{closed}) is above the {MORTALITY_BENCHMARK:.0%} benchmark – review treatment protocols.")
        else:
            st.success(f"Mortality {mort:.1%} ({dead}/{closed}) is within the {MORTALITY_BENCHMARK:.0%} benchmark.")
        if closed < 20:
            st.caption("⚠️ Small sample – interpret with caution.")

    lag = one("""SELECT AVG(julianday(substr(closed_at,1,10)) - julianday(eligible_since))
                 FROM discharges WHERE outcome='cured' AND eligible_since IS NOT NULL AND substr(closed_at,1,10)>=?""", (cutoff,))
    los = one("""SELECT AVG(julianday(substr(p.closed_at,1,10)) - julianday(p.admit_date))
                 FROM patients p WHERE p.closed_at IS NOT NULL AND substr(p.closed_at,1,10)>=?""", (cutoff,))
    s1, s2 = st.columns(2)
    s1.metric("Avg discharge lag (days, eligible → discharged)", f"{lag:.1f}" if lag is not None else "–")
    s2.metric("Avg length of stay (days)", f"{los:.1f}" if los is not None else "–")

    st.subheader("Today's task status")
    st.bar_chart(df.status.value_counts())


def page_beds():
    st.header("🛏️ Beds & Admissions")
    beds = qdf("""SELECT b.id AS bed, p.name AS patient, p.age, p.admit_date
                  FROM beds b LEFT JOIN patients p ON p.bed_id=b.id AND p.status='admitted' ORDER BY b.id""")
    beds["state"] = beds.patient.apply(lambda x: "🟥 Occupied" if pd.notna(x) else "🟩 Free")
    free = beds[beds.patient.isna()].bed.tolist()
    st.metric("Free beds", f"{len(free)}/{TOTAL_BEDS}")

    st.subheader("Admit a patient")
    if not free:
        st.warning("No free beds.")
    else:
        with st.form("admit", clear_on_submit=True):
            name = st.text_input("Full name")
            age = st.number_input("Age", 0, 120, 30)
            bed = st.selectbox("Bed", free)
            sub = st.form_submit_button("Admit", type="primary")
        if sub:
            if not name.strip():
                st.error("Name is required.")
            else:
                pid = run("INSERT INTO patients(name,age,admit_date,bed_id,status) VALUES (?,?,?,?, 'admitted')",
                          (name.strip(), int(age), today().isoformat(), bed)).lastrowid
                audit("admit", f"patient={pid} bed={bed}")
                st.success(f"Admitted {name} to {bed}.")
                st.rerun()
    st.subheader("Bed map")
    st.dataframe(beds[["bed", "state", "patient", "age", "admit_date"]], use_container_width=True, hide_index=True)


def page_discharge_desk():
    st.header("📨 Discharge Desk")
    df = qdf("""SELECT d.id, p.name AS patient, d.outcome, d.confirmed_by, d.closed_at
                FROM discharges d JOIN patients p ON p.id=d.patient_id
                WHERE d.admin_ack=0 ORDER BY d.closed_at DESC""")
    if df.empty:
        st.success("No pending discharge notifications.")
    for r in df.itertuples():
        c1, c2 = st.columns([4, 1])
        icon = "✅" if r.outcome == "cured" else "🕊️"
        c1.markdown(f"{icon} **{r.patient}** – {r.outcome} (confirmed by {r.confirmed_by} at {r.closed_at[:16].replace('T', ' ')})")
        if c2.button("Acknowledge", key=f"ack{r.id}"):
            run("UPDATE discharges SET admin_ack=1, ack_by=?, ack_at=? WHERE id=?",
                (st.session_state.user["username"], iso(now()), int(r.id)))
            audit("ack_discharge", f"discharge={r.id}")
            st.rerun()
    st.subheader("Recently processed")
    st.dataframe(qdf("""SELECT p.name AS patient, d.outcome, d.confirmed_by, d.closed_at, d.ack_by
                        FROM discharges d JOIN patients p ON p.id=d.patient_id
                        WHERE d.admin_ack=1 ORDER BY d.closed_at DESC LIMIT 30"""),
                 hide_index=True, use_container_width=True)


def page_audit():
    st.header("🧾 Audit Log")
    df = qdf("SELECT ts, username, action, detail FROM audit ORDER BY id DESC LIMIT 1000")
    act = st.multiselect("Filter by action", sorted(df.action.unique()))
    if act:
        df = df[df.action.isin(act)]
    st.dataframe(df, use_container_width=True, hide_index=True)


def page_admin():
    st.header("⚙️ Users & Settings")
    st.subheader("Clinical settings")
    with st.form("settings"):
        thr = st.number_input("Fever threshold (°C)", 36.5, 40.0, setting("fever_threshold", float), 0.1)
        req = st.number_input("No-fever days required for discharge", 1, 14, setting("required_days", int))
        inc = st.checkbox("Count today as a no-fever day once a reading is recorded",
                          value=setting("include_today", int) == 1)
        if st.form_submit_button("Save settings"):
            for k, v in {"fever_threshold": thr, "required_days": int(req), "include_today": int(inc)}.items():
                run("INSERT OR REPLACE INTO settings VALUES (?,?)", (k, str(v)))
            audit("update_settings", f"thr={thr} req={req} include_today={inc}")
            st.success("Saved.")

    st.subheader("Users")
    st.dataframe(qdf("SELECT username, name, role FROM users ORDER BY role, username"),
                 hide_index=True, use_container_width=True)
    with st.form("newuser", clear_on_submit=True):
        c1, c2 = st.columns(2)
        un = c1.text_input("Username")
        nm = c2.text_input("Display name")
        rl = c1.selectbox("Role", ROLES)
        pw = c2.text_input("Password (min 8 chars)", type="password")
        if st.form_submit_button("Create / reset user"):
            if not un.strip() or len(pw) < 8:
                st.error("Username required and password must be at least 8 characters.")
            else:
                salt = pysecrets.token_hex(16)
                run("INSERT OR REPLACE INTO users VALUES (?,?,?,?,?)",
                    (un.strip(), nm.strip() or un.strip(), rl, salt, hash_pw(pw, salt)))
                audit("upsert_user", f"{un.strip()} role={rl}")
                st.success("User saved.")

    st.subheader("Danger zone")
    ok = st.checkbox("I understand this wipes all patient data and reloads demo data")
    if st.button("Reset demo data", disabled=not ok):
        seed_demo(get_conn())
        audit("reset_demo", "")
        st.success("Demo data reloaded.")


# --------------------------------------------------------------------------
# RBAC page registry + main
# --------------------------------------------------------------------------
PAGES = {
    "🌡️ Worklist":         (page_worklist,        {"nurse"}),
    "🩺 Doctor Rounds":    (page_rounds,          {"doctor"}),
    "🏁 Discharge Queue":  (page_discharge_queue, {"doctor"}),
    "📈 Patient Trend":    (page_trend,           {"nurse", "doctor", "admin"}),
    "📊 Dashboard":        (page_dashboard,       {"doctor", "admin"}),
    "🛏️ Beds & Admissions": (page_beds,           {"admin"}),
    "📨 Discharge Desk":   (page_discharge_desk,  {"admin"}),
    "🧾 Audit Log":        (page_audit,           {"admin"}),
    "⚙️ Users & Settings": (page_admin,           {"admin"}),
}


def main():
    get_conn()
    user = st.session_state.get("user")
    if not user:
        login_screen()
        return

    role = user["role"]
    allowed = [n for n, (_, roles) in PAGES.items() if role in roles]
    with st.sidebar:
        st.markdown(f"### 🏥 {user['name']}\n`{role}`")
        if role == "admin":
            pending = one("SELECT COUNT(*) FROM discharges WHERE admin_ack=0") or 0
            if pending:
                st.warning(f"🔔 {pending} discharge notification(s)")
        choice = st.radio("Navigate", allowed, label_visibility="collapsed")
        st.caption(f"{now():%a %d %b %Y, %H:%M} IST")
        if st.button("Log out"):
            audit("logout", "")
            st.session_state.clear()
            st.rerun()

    func, roles = PAGES[choice]
    if role not in roles:  # server-side RBAC guard
        st.error("You do not have permission to view this page.")
        audit("access_denied", choice)
        return
    func()


main()
