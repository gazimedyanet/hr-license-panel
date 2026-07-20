from flask import Flask, request, jsonify, render_template_string, redirect, session, Response, has_request_context
import sqlite3
import csv
import io
import hashlib
import hmac
import os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "GaziMediaPanelSecret2026")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "licenses.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            hw_id TEXT NOT NULL,
            product TEXT DEFAULT 'gazi-hr',
            customer_name TEXT,
            customer_email TEXT,
            customer_phone TEXT,
            issued_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            is_revoked INTEGER DEFAULT 0,
            revoke_reason TEXT,
            last_seen TEXT,
            verify_count INTEGER DEFAULT 0,
            notes TEXT,
            package TEXT DEFAULT 'enterprise'
        )
    """)
    for col, dflt in [("package", "'enterprise'"), ("product", "'gazi-hr'")]:
        try:
            conn.execute(f"ALTER TABLE licenses ADD COLUMN {col} TEXT DEFAULT {dflt}")
            conn.commit()
        except Exception:
            pass

    # Lisans bazlı takip alanları: eski veritabanlarını bozmadan sonradan eklenir.
    # Böylece hangi lisansın ne zaman ve kim tarafından oluşturulduğu / aktifleştirildiği /
    # uzatıldığı / iptal edildiği detay ekranında ve Excel çıktısında izlenebilir.
    for col in [
        "created_by TEXT",
        "activated_at TEXT",
        "activated_by TEXT",
        "activated_ip TEXT",
        "extended_at TEXT",
        "extended_by TEXT",
        "updated_at TEXT",
        "updated_by TEXT",
        "revoked_at TEXT",
        "revoked_by TEXT",
    ]:
        try:
            conn.execute(f"ALTER TABLE licenses ADD COLUMN {col}")
            conn.commit()
        except Exception:
            pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS admin_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            detail TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Eski veritabanlarıyla uyumlu kalmak için işlem geçmişine ek takip alanları sonradan eklenir.
    # Mevcut kayıtlar bozulmaz; yeni kayıtlar daha detaylı tutulur.
    for col in [
        "username TEXT",
        "ip_address TEXT",
        "user_agent TEXT",
        "path TEXT",
        "method TEXT",
    ]:
        try:
            conn.execute(f"ALTER TABLE audit_log ADD COLUMN {col}")
            conn.commit()
        except Exception:
            pass
    existing = conn.execute("SELECT value FROM admin_settings WHERE key='admin_pass_hash'").fetchone()
    if not existing:
        h = hashlib.sha256("GaziMedia2026!".encode()).hexdigest()
        conn.execute("INSERT INTO admin_settings VALUES ('admin_pass_hash',?)", (h,))
        conn.execute("INSERT OR IGNORE INTO admin_settings VALUES ('admin_user','gazi')")
    conn.commit()
    conn.close()


init_db()

# ── İmzalama anahtarları ──────────────────────────────────────────────────────
_K_HR = [
    0x47,0x61,0x7A,0x69,0x4D,0x65,0x64,0x79,0x61,0x48,0x52,
    0x32,0x30,0x32,0x36,0x53,0x65,0x63,0x72,0x65,0x74,0x4B,
    0x65,0x79,0x5F,0x44,0x6F,0x4E,0x6F,0x74,0x53,0x68,0x61,0x72,0x65
]
_K_ASC = [
    0x41,0x75,0x74,0x6F,0x53,0x65,0x72,0x76,0x69,0x73,0x43,
    0x52,0x4D,0x2D,0x32,0x30,0x32,0x35,0x2D,0x4C,0x69,0x63,
    0x4B,0x65,0x79,0x2D,0x47,0x61,0x7A,0x69
]
_K_FT = [
    70,105,121,97,116,84,101,107,108,105,102,105,45,69,84,65,
    45,65,110,97,108,105,116,105,107,45,50,48,50,54,45,76,105,99,75,101,121
]
_K_ETA = [
    0x45,0x54,0x41,0x44,0x4B,0x47,0x61,0x7A,0x69,0x4D,0x65,0x64,
    0x79,0x61,0x32,0x30,0x32,0x36,0x53,0x65,0x63,0x72,0x65,0x74,
    0x4B,0x65,0x79,0x5F,0x45,0x54,0x41,0x6E,0x61,0x6C,0x69,0x74
]
_K_KKDIK = [
    75,75,68,73,75,83,117,105,116,101,50,48,50,54,
    71,97,122,105,77,101,100,105,97,83,101,99,114,101,116,75,101,121
]
_K_ETNTK = [
    69,116,97,110,111,109,84,101,107,108,105,102,83,105,115,
    116,101,109,105,50,48,50,54,71,97,122,105,77,101,100,105,
    97,83,101,99,114,101,116,75,101,121
]
_K_ETNFT = [
    69,116,97,110,111,109,70,97,116,117,114,97,83,105,115,116,
    101,109,105,50,48,50,54,71,97,122,105,77,101,100,105,97,83,
    101,99,114,101,116,75,101,121
]

PRODUCTS = {
    "gazi-hr":        {"prefix":"GMHR",  "key":_K_HR,    "label":"Gazi HR",          "color":"#3b82f6","emoji":"👥"},
    "autoservis-crm": {"prefix":"ASC",   "key":_K_ASC,   "label":"AutoServis CRM",   "color":"#f97316","emoji":"🔧"},
    "fiyat-teklifi":  {"prefix":"FTK",   "key":_K_FT,    "label":"Fiyat Teklifi",    "color":"#10b981","emoji":"📊"},
    "eta-analitik":   {"prefix":"ETADK", "key":_K_ETA,   "label":"ETA Analitik ERP", "color":"#8b5cf6","emoji":"🚢"},
    "kkdik":          {"prefix":"KKDIK", "key":_K_KKDIK, "label":"KKDİK Suite",      "color":"#06b6d4","emoji":"⚗️"},
    "etanom-teklif":  {"prefix":"ETNTK", "key":_K_ETNTK, "label":"Etanom Teklif",   "color":"#f59e0b","emoji":"📄"},
    "etanom-fatura":  {"prefix":"ETNFT", "key":_K_ETNFT, "label":"Etanom Fatura (İhracat)", "color":"#dc2626","emoji":"🧾"},
}


def _sign(key_bytes, data: str) -> str:
    return hmac.new(bytes(key_bytes), data.encode(), hashlib.sha256).hexdigest()


def _to_base36(num: int) -> str:
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if num <= 0:
        return "0"
    out = ""
    while num:
        out = chars[num % 36] + out
        num //= 36
    return out


def gen_key(hw_id: str, expires_at: str, product: str = "gazi-hr") -> str:
    cfg = PRODUCTS.get(product, PRODUCTS["gazi-hr"])
    hw_hash = hashlib.sha256(hw_id.encode()).hexdigest()[:6].upper()
    ts = int(datetime.fromisoformat(expires_at).timestamp())
    r = _to_base36(ts)
    prefix = cfg["prefix"]
    data = f"{prefix}-{hw_hash}-{r}"
    chk = _sign(cfg["key"], data)[:8].upper()
    return f"{data}-{chk}"


def validate_key_math(license_key: str, hw_id: str, expires_at: str, product: str):
    cfg = PRODUCTS.get(product)
    if not cfg:
        return False, "Bilinmeyen ürün"
    key = (license_key or "").strip().upper()
    parts = key.split("-")
    if len(parts) != 4:
        return False, "Lisans formatı hatalı"
    prefix, hw_hash, encoded_ts, checksum = parts
    if prefix != cfg["prefix"]:
        return False, "Prefix eşleşmiyor"
    expected_hash = hashlib.sha256(hw_id.encode()).hexdigest()[:6].upper()
    if hw_hash != expected_hash:
        return False, "HW hash eşleşmiyor"
    expected_data = f"{cfg['prefix']}-{expected_hash}-{encoded_ts}"
    expected_checksum = _sign(cfg["key"], expected_data)[:8].upper()
    if checksum != expected_checksum:
        return False, "Checksum eşleşmiyor"
    expected_full = gen_key(hw_id, expires_at, product)
    if expected_full != key:
        return False, f"Beklenen anahtar farklı: {expected_full}"
    return True, "Matematiksel doğrulama başarılı"


def get_admin():
    conn = get_db()
    u = conn.execute("SELECT value FROM admin_settings WHERE key='admin_user'").fetchone()
    p = conn.execute("SELECT value FROM admin_settings WHERE key='admin_pass_hash'").fetchone()
    conn.close()
    return (u[0] if u else "gazi"), (p[0] if p else "")


def _current_admin_user() -> str:
    if has_request_context():
        return (session.get("admin_user", "") or request.form.get("username", "") or "sistem")[:80]
    return "sistem"


def _client_ip() -> str:
    if has_request_context():
        return (request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip())[:80]
    return ""


def log(action, detail=""):
    username = ""
    ip_address = ""
    user_agent = ""
    path = ""
    method = ""
    if has_request_context():
        username = _current_admin_user()
        ip_address = _client_ip()
        user_agent = (request.headers.get("User-Agent", "") or "")[:250]
        path = (request.path or "")[:160]
        method = (request.method or "")[:16]
    conn = get_db()
    conn.execute(
        """
        INSERT INTO audit_log (action,detail,username,ip_address,user_agent,path,method)
        VALUES (?,?,?,?,?,?,?)
        """,
        (action, detail, username, ip_address, user_agent, path, method),
    )
    conn.commit()
    conn.close()


def auth(f):
    @wraps(f)
    def d(*a, **k):
        if not session.get("logged_in"):
            return redirect("/login")
        return f(*a, **k)
    return d


def _verify_core(key: str, hw: str, product: str):
    if product not in PRODUCTS:
        return None, {"valid": False, "message": "Bilinmeyen ürün"}
    conn = get_db()
    lic = conn.execute(
        "SELECT * FROM licenses WHERE license_key=? AND product=?", (key, product)
    ).fetchone()
    if not lic:
        conn.close()
        return None, {"valid": False, "message": "Lisans bulunamadı"}
    if lic["is_revoked"]:
        conn.close()
        return None, {"valid": False, "message": f"İptal edildi: {lic['revoke_reason'] or ''}"}
    if lic["hw_id"].upper() != hw.upper():
        conn.close()
        return None, {"valid": False, "message": "Donanım eşleşmiyor"}
    exp = datetime.fromisoformat(lic["expires_at"])
    if datetime.now() > exp:
        conn.close()
        return None, {"valid": False, "message": f"Süresi doldu ({exp.strftime('%d.%m.%Y')})"}
    ok, math_msg = validate_key_math(lic["license_key"], lic["hw_id"], lic["expires_at"], lic["product"] or product)
    if not ok:
        conn.close()
        return None, {"valid": False, "message": f"Algoritma uyuşmuyor: {math_msg}"}
    conn.execute(
        "UPDATE licenses SET last_seen=?, verify_count=verify_count+1 WHERE id=?",
        (datetime.now().isoformat(), lic["id"]),
    )
    conn.commit()
    conn.close()
    days_left = (exp - datetime.now()).days
    return lic, {
        "valid":     True,
        "expires":   exp.strftime("%d.%m.%Y"),
        "customer":  lic["customer_name"],
        "message":   "Geçerli",
        "package":   lic["package"] or "enterprise",
        "days_left": days_left,
    }


# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET","POST"])
def login():
    err = ""
    if request.method == "POST":
        admin_user, admin_hash = get_admin()
        given = hashlib.sha256(request.form.get("password","").encode()).hexdigest()
        if request.form.get("username","") == admin_user and given == admin_hash:
            session["logged_in"] = True
            session["admin_user"] = admin_user
            log("GİRİŞ", f"Kullanıcı: {admin_user}")
            return redirect("/")
        err = "Kullanıcı adı veya şifre hatalı"
        log("BAŞARISIZ GİRİŞ")
    return render_template_string(LOGIN_HTML, error=err)

@app.route("/logout")
def logout():
    log("ÇIKIŞ")
    session.clear()
    return redirect("/login")

@app.route("/change-password", methods=["GET","POST"])
@auth
def change_password():
    msg = ""
    err = ""
    if request.method == "POST":
        _, admin_hash = get_admin()
        cur  = request.form.get("current","")
        new  = request.form.get("new_pass","")
        conf = request.form.get("confirm","")
        if hashlib.sha256(cur.encode()).hexdigest() != admin_hash:
            err = "Mevcut şifre hatalı"
        elif len(new) < 8:
            err = "Yeni şifre en az 8 karakter olmalı"
        elif new != conf:
            err = "Şifreler eşleşmiyor"
        else:
            conn = get_db()
            conn.execute("UPDATE admin_settings SET value=? WHERE key='admin_pass_hash'",
                         (hashlib.sha256(new.encode()).hexdigest(),))
            conn.commit()
            conn.close()
            log("ŞİFRE DEĞİŞTİRİLDİ")
            msg = "Şifre başarıyla güncellendi"
    return render_template_string(CHANGE_PASS_HTML, msg=msg, err=err)



def _sidebar_stats(conn):
    now = datetime.now().isoformat()
    soon = (datetime.now() + timedelta(days=30)).isoformat()
    return {
        "total":         conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        "active":        conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=0 AND expires_at>?", (now,)).fetchone()[0],
        "expired":       conn.execute("SELECT COUNT(*) FROM licenses WHERE expires_at<? AND is_revoked=0", (now,)).fetchone()[0],
        "revoked":       conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=1").fetchone()[0],
        "expiring":      conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=0 AND expires_at>? AND expires_at<?", (now, soon)).fetchone()[0],
        "hr_count":      conn.execute("SELECT COUNT(*) FROM licenses WHERE product='gazi-hr'").fetchone()[0],
        "asc_count":     conn.execute("SELECT COUNT(*) FROM licenses WHERE product='autoservis-crm'").fetchone()[0],
        "ft_count":      conn.execute("SELECT COUNT(*) FROM licenses WHERE product='fiyat-teklifi'").fetchone()[0],
        "eta_count":     conn.execute("SELECT COUNT(*) FROM licenses WHERE product='eta-analitik'").fetchone()[0],
        "kkdik_count":   conn.execute("SELECT COUNT(*) FROM licenses WHERE product='kkdik'").fetchone()[0],
        "etanom_count":  conn.execute("SELECT COUNT(*) FROM licenses WHERE product='etanom-teklif'").fetchone()[0],
        "fatura_count":  conn.execute("SELECT COUNT(*) FROM licenses WHERE product='etanom-fatura'").fetchone()[0],
    }


def _audit_filters():
    q = request.args.get("q", "").strip()
    action = request.args.get("action", "all").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    where = []
    params = []
    if q:
        like = f"%{q}%"
        where.append("(action LIKE ? OR detail LIKE ? OR username LIKE ? OR ip_address LIKE ? OR path LIKE ? OR method LIKE ?)")
        params.extend([like, like, like, like, like, like])
    if action and action != "all":
        where.append("action=?")
        params.append(action)
    if date_from:
        where.append("created_at>=?")
        params.append(date_from + " 00:00:00")
    if date_to:
        where.append("created_at<=?")
        params.append(date_to + " 23:59:59")
    sql_where = (" WHERE " + " AND ".join(where)) if where else ""
    return sql_where, params, {"q": q, "action": action, "date_from": date_from, "date_to": date_to}


@app.route("/audit-log")
@auth
def audit_log_page():
    conn = get_db()
    stats = _sidebar_stats(conn)
    sql_where, params, filters = _audit_filters()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except Exception:
        page = 1
    try:
        per_page = int(request.args.get("per_page", 50))
    except Exception:
        per_page = 50
    per_page = min(max(per_page, 25), 200)
    total_filtered = conn.execute(f"SELECT COUNT(*) FROM audit_log{sql_where}", params).fetchone()[0]
    offset = (page - 1) * per_page
    logs = conn.execute(
        f"""
        SELECT * FROM audit_log
        {sql_where}
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        params + [per_page, offset],
    ).fetchall()
    actions = conn.execute("SELECT DISTINCT action FROM audit_log WHERE action IS NOT NULL AND action<>'' ORDER BY action").fetchall()
    today = datetime.now().strftime("%Y-%m-%d")
    audit_stats = {
        "total": conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
        "today": conn.execute("SELECT COUNT(*) FROM audit_log WHERE created_at LIKE ?", (today + "%",)).fetchone()[0],
        "license_ops": conn.execute("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'LİSANS%'").fetchone()[0],
        "failed_login": conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='BAŞARISIZ GİRİŞ'").fetchone()[0],
    }
    conn.close()
    pages = max(1, (total_filtered + per_page - 1) // per_page)
    return render_template_string(
        AUDIT_HTML,
        logs=logs,
        actions=actions,
        filters=filters,
        stats=stats,
        audit_stats=audit_stats,
        total_filtered=total_filtered,
        page=page,
        pages=pages,
        per_page=per_page,
        products=PRODUCTS,
    )


@app.route("/audit-log/export")
@auth
def audit_log_export():
    conn = get_db()
    sql_where, params, _ = _audit_filters()
    rows = conn.execute(
        f"""
        SELECT id, created_at, action, detail, username, ip_address, method, path, user_agent
        FROM audit_log
        {sql_where}
        ORDER BY created_at DESC, id DESC
        """,
        params,
    ).fetchall()
    conn.close()
    out = io.StringIO()
    writer = csv.writer(out, delimiter=";")
    writer.writerow(["ID", "Tarih", "İşlem", "Detay", "Kullanıcı", "IP", "Metot", "Yol", "Tarayıcı"])
    for r in rows:
        writer.writerow([
            r["id"], r["created_at"], r["action"], r["detail"], r["username"],
            r["ip_address"], r["method"], r["path"], r["user_agent"],
        ])
    filename = f"islem-gecmisi-{datetime.now().strftime('%Y%m%d-%H%M')}.csv"
    return Response(
        "\ufeff" + out.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _license_filters():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "all").strip()
    product = request.args.get("product", "all").strip()
    now_iso = datetime.now().isoformat()
    soon_iso = (datetime.now() + timedelta(days=30)).isoformat()
    where = []
    params = []
    if product and product != "all" and product in PRODUCTS:
        where.append("product=?")
        params.append(product)
    if q:
        like = f"%{q}%"
        where.append(
            "(customer_name LIKE ? OR customer_email LIKE ? OR customer_phone LIKE ? OR "
            "license_key LIKE ? OR hw_id LIKE ? OR notes LIKE ? OR package LIKE ? OR product LIKE ?)"
        )
        params.extend([like, like, like, like, like, like, like, like])
    if status == "active":
        where.append("is_revoked=0 AND expires_at>?")
        params.append(now_iso)
    elif status == "expired":
        where.append("is_revoked=0 AND expires_at<=?")
        params.append(now_iso)
    elif status == "revoked":
        where.append("is_revoked=1")
    elif status == "expiring":
        where.append("is_revoked=0 AND expires_at>? AND expires_at<?")
        params.extend([now_iso, soon_iso])
    sql_where = (" WHERE " + " AND ".join(where)) if where else ""
    return sql_where, params, {"q": q, "status": status, "product": product}


@app.route("/licenses/export")
@auth
def licenses_export():
    conn = get_db()
    sql_where, params, filters = _license_filters()
    rows = conn.execute(
        f"""
        SELECT *
        FROM licenses
        {sql_where}
        ORDER BY issued_at DESC, id DESC
        """,
        params,
    ).fetchall()
    conn.close()

    out = io.StringIO()
    writer = csv.writer(out, delimiter=";")
    writer.writerow([
        "ID", "Ürün", "Müşteri/Firma", "E-posta", "Telefon", "Paket",
        "HW ID", "Lisans Anahtarı", "Durum", "Oluşturulma Tarihi", "Oluşturan",
        "Aktifleştirme Tarihi", "Aktifleştiren", "Aktifleştirme IP",
        "Son Geçerlilik", "Son Görülme", "Doğrulama Sayısı",
        "Son Uzatma", "Uzatan", "Son Güncelleme", "Güncelleyen",
        "İptal Tarihi", "İptal Eden", "İptal Sebebi", "Not"
    ])
    now_iso = datetime.now().isoformat()
    for r in rows:
        product_label = PRODUCTS.get(r["product"] or "gazi-hr", PRODUCTS["gazi-hr"])["label"]
        if r["is_revoked"]:
            status_text = "İptal"
        elif (r["expires_at"] or "") <= now_iso:
            status_text = "Dolmuş"
        else:
            status_text = "Aktif"
        writer.writerow([
            r["id"], product_label, r["customer_name"] or "", r["customer_email"] or "",
            r["customer_phone"] or "", r["package"] or "", r["hw_id"] or "",
            r["license_key"] or "", status_text, r["issued_at"] or "", r["created_by"] or "",
            r["activated_at"] or "", r["activated_by"] or "", r["activated_ip"] or "",
            r["expires_at"] or "", r["last_seen"] or "", r["verify_count"] or 0,
            r["extended_at"] or "", r["extended_by"] or "", r["updated_at"] or "", r["updated_by"] or "",
            r["revoked_at"] or "", r["revoked_by"] or "", r["revoke_reason"] or "", r["notes"] or "",
        ])

    suffix = []
    if filters["product"] and filters["product"] != "all":
        suffix.append(filters["product"])
    if filters["status"] and filters["status"] != "all":
        suffix.append(filters["status"])
    suffix_txt = ("-" + "-".join(suffix)) if suffix else ""
    filename = f"lisanslar{suffix_txt}-{datetime.now().strftime('%Y%m%d-%H%M')}.csv"
    return Response(
        "\ufeff" + out.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Panel routes ──────────────────────────────────────────────────────────────
@app.route("/")
@auth
def index():
    conn = get_db()
    prod_filter = request.args.get("product","all")
    if prod_filter != "all":
        licenses = conn.execute(
            "SELECT * FROM licenses WHERE product=? ORDER BY issued_at DESC, id DESC", (prod_filter,)
        ).fetchall()
    else:
        licenses = conn.execute(
            "SELECT * FROM licenses ORDER BY issued_at DESC, id DESC"
        ).fetchall()
    now  = datetime.now().isoformat()
    soon = (datetime.now() + timedelta(days=30)).isoformat()
    stats = {
        "total":         conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        "active":        conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=0 AND expires_at>?", (now,)).fetchone()[0],
        "expired":       conn.execute("SELECT COUNT(*) FROM licenses WHERE expires_at<? AND is_revoked=0", (now,)).fetchone()[0],
        "revoked":       conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=1").fetchone()[0],
        "expiring":      conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=0 AND expires_at>? AND expires_at<?", (now,soon)).fetchone()[0],
        "hr_count":      conn.execute("SELECT COUNT(*) FROM licenses WHERE product='gazi-hr'").fetchone()[0],
        "asc_count":     conn.execute("SELECT COUNT(*) FROM licenses WHERE product='autoservis-crm'").fetchone()[0],
        "ft_count":      conn.execute("SELECT COUNT(*) FROM licenses WHERE product='fiyat-teklifi'").fetchone()[0],
        "eta_count":     conn.execute("SELECT COUNT(*) FROM licenses WHERE product='eta-analitik'").fetchone()[0],
        "kkdik_count":   conn.execute("SELECT COUNT(*) FROM licenses WHERE product='kkdik'").fetchone()[0],
        "etanom_count":  conn.execute("SELECT COUNT(*) FROM licenses WHERE product='etanom-teklif'").fetchone()[0],
        "fatura_count":  conn.execute("SELECT COUNT(*) FROM licenses WHERE product='etanom-fatura'").fetchone()[0],
    }
    logs = conn.execute("SELECT * FROM audit_log ORDER BY created_at DESC, id DESC LIMIT 25").fetchall()
    conn.close()
    # Seçili ürüne göre (görüntüleme amaçlı) sayfa-bazlı istatistikler — mevcut 'stats' hesaplamasına dokunmadan,
    # zaten çekilmiş olan 'licenses' listesinden Python tarafında türetilir.
    fstats = {
        "total":    len(licenses),
        "active":   sum(1 for l in licenses if not l["is_revoked"] and l["expires_at"] > now),
        "expired":  sum(1 for l in licenses if not l["is_revoked"] and l["expires_at"] <= now),
        "revoked":  sum(1 for l in licenses if l["is_revoked"]),
        "expiring": sum(1 for l in licenses if not l["is_revoked"] and now < l["expires_at"] < soon),
    }
    return render_template_string(PANEL_HTML, licenses=licenses, stats=stats, fstats=fstats,
                                  now=now, logs=logs, products=PRODUCTS, prod_filter=prod_filter)


@app.route("/create", methods=["POST"])
@auth
def create():
    hw_id    = request.form.get("hw_id","").strip().upper()
    days     = int(request.form.get("days",365))
    customer = request.form.get("customer_name","").strip()
    email    = request.form.get("customer_email","").strip()
    phone    = request.form.get("customer_phone","").strip()
    notes    = request.form.get("notes","").strip()
    package  = request.form.get("package","enterprise").strip()
    product  = request.form.get("product","gazi-hr").strip()
    if product not in PRODUCTS:
        product = "gazi-hr"
    if not hw_id:
        return "Donanım ID gerekli", 400
    expires = (datetime.now() + timedelta(days=days)).isoformat()
    conn = get_db()
    now_iso = datetime.now().isoformat()
    existing = conn.execute(
        "SELECT id FROM licenses WHERE hw_id=? AND product=? AND is_revoked=0 AND expires_at>?",
        (hw_id, product, now_iso)
    ).fetchone()
    if existing:
        conn.close()
        return "<script>alert('Bu HW ID ve ürün için AKTİF bir lisans zaten var.');history.back()</script>"
    key = gen_key(hw_id, expires, product)
    try:
        conn.execute(
            """
            INSERT INTO licenses (
                license_key, hw_id, product, customer_name, customer_email, customer_phone,
                expires_at, notes, package, created_by, activated_at, activated_by, activated_ip
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                key, hw_id, product, customer, email, phone, expires, notes, package,
                _current_admin_user(), now_iso, _current_admin_user(), _client_ip()
            ),
        )
        conn.commit()
        log("LİSANS OLUŞTURULDU", f"{customer or '?'} | {PRODUCTS[product]['label']} | {expires[:10]}")
    except sqlite3.IntegrityError:
        conn.close()
        return "<script>alert('Lisans oluşturulamadı.');history.back()</script>"
    conn.close()
    return redirect("/")


@app.route("/extend/<int:lid>", methods=["POST"])
@auth
def extend(lid):
    days = int(request.form.get("days",365))
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    if lic:
        cur = datetime.fromisoformat(lic["expires_at"])
        if cur < datetime.now():
            cur = datetime.now()
        new_exp = cur + timedelta(days=days)
        product = lic["product"] or "gazi-hr"
        new_key = gen_key(lic["hw_id"], new_exp.isoformat(), product)
        now_action = datetime.now().isoformat()
        user_action = _current_admin_user()
        if lic["is_revoked"] or datetime.fromisoformat(lic["expires_at"]) < datetime.now():
            conn.execute(
                """
                UPDATE licenses
                SET license_key=?, expires_at=?, is_revoked=0, revoke_reason=NULL,
                    extended_at=?, extended_by=?, activated_at=?, activated_by=?, activated_ip=?
                WHERE id=?
                """,
                (new_key, new_exp.isoformat(), now_action, user_action, now_action, user_action, _client_ip(), lid),
            )
        else:
            conn.execute(
                """
                UPDATE licenses
                SET license_key=?, expires_at=?, is_revoked=0, revoke_reason=NULL,
                    extended_at=?, extended_by=?
                WHERE id=?
                """,
                (new_key, new_exp.isoformat(), now_action, user_action, lid),
            )
        conn.commit()
        log("LİSANS UZATILDI", f"ID:{lid} | {lic['customer_name'] or '-'} | +{days} gün | {new_exp.strftime('%d.%m.%Y')} | Kullanıcı:{user_action}")
    conn.close()
    return redirect("/")


@app.route("/revoke/<int:lid>", methods=["POST"])
@auth
def revoke(lid):
    reason = request.form.get("reason","").strip()
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    now_action = datetime.now().isoformat()
    user_action = _current_admin_user()
    conn.execute(
        "UPDATE licenses SET is_revoked=1, revoke_reason=?, revoked_at=?, revoked_by=? WHERE id=?",
        (reason, now_action, user_action, lid),
    )
    conn.commit()
    conn.close()
    log("LİSANS İPTAL", f"ID:{lid} | {lic['customer_name'] if lic else ''} | {reason or 'Sebep yok'} | Kullanıcı:{user_action}")
    return redirect("/")


@app.route("/restore/<int:lid>", methods=["POST"])
@auth
def restore(lid):
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    now_action = datetime.now().isoformat()
    user_action = _current_admin_user()
    conn.execute(
        """
        UPDATE licenses
        SET is_revoked=0, revoke_reason=NULL, activated_at=?, activated_by=?, activated_ip=?
        WHERE id=?
        """,
        (now_action, user_action, _client_ip(), lid),
    )
    conn.commit()
    conn.close()
    log("LİSANS AKTİFLEŞTİRİLDİ", f"ID:{lid} | {lic['customer_name'] if lic else ''} | Kullanıcı:{user_action}")
    return redirect("/")


@app.route("/edit/<int:lid>", methods=["POST"])
@auth
def edit(lid):
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    if lic:
        pkg = request.form.get("package","enterprise").strip()
        now_action = datetime.now().isoformat()
        user_action = _current_admin_user()
        conn.execute(
            """
            UPDATE licenses
            SET customer_name=?, customer_email=?, customer_phone=?, notes=?, package=?,
                updated_at=?, updated_by=?
            WHERE id=?
            """,
            (
                request.form.get("customer_name","").strip(), request.form.get("customer_email","").strip(),
                request.form.get("customer_phone","").strip(), request.form.get("notes","").strip(), pkg,
                now_action, user_action, lid
            ),
        )
        conn.commit()
        log("LİSANS DÜZENLENDİ", f"ID:{lid} | Paket:{pkg} | Kullanıcı:{user_action}")
    conn.close()
    return redirect("/")


@app.route("/delete/<int:lid>", methods=["POST"])
@auth
def delete(lid):
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    conn.execute("DELETE FROM licenses WHERE id=?", (lid,))
    conn.commit()
    conn.close()
    log("LİSANS SİLİNDİ", f"ID:{lid} | {lic['customer_name'] if lic else ''}")
    return redirect("/")


# ── API Endpoints ─────────────────────────────────────────────────────────────
@app.route("/api/hr-license", methods=["POST"])
def verify_hr():
    d = request.get_json(silent=True) or {}
    _, result = _verify_core(d.get("license_key","").strip().upper(), d.get("hw_id","").strip(), "gazi-hr")
    return jsonify(result)

@app.route("/api/autoservis-license", methods=["POST"])
def verify_autoservis():
    d = request.get_json(silent=True) or {}
    _, result = _verify_core(d.get("license_key","").strip().upper(), d.get("hw_id","").strip(), "autoservis-crm")
    return jsonify(result)

@app.route("/api/fiyat-teklifi-license", methods=["POST"])
def verify_fiyat_teklifi():
    d = request.get_json(silent=True) or {}
    _, result = _verify_core(d.get("license_key","").strip().upper(), d.get("hw_id","").strip(), "fiyat-teklifi")
    return jsonify(result)

@app.route("/api/eta-license", methods=["POST"])
def verify_eta():
    d = request.get_json(silent=True) or {}
    _, result = _verify_core(d.get("license_key","").strip().upper(), d.get("hw_id","").strip(), "eta-analitik")
    return jsonify(result)

@app.route("/api/kkdik-license", methods=["POST"])
def verify_kkdik():
    d = request.get_json(silent=True) or {}
    _, result = _verify_core(d.get("license_key","").strip().upper(), d.get("hw_id","").strip(), "kkdik")
    return jsonify(result)

@app.route("/api/etanom-teklif-license", methods=["POST"])
def verify_etanom():
    d = request.get_json(silent=True) or {}
    _, result = _verify_core(d.get("license_key","").strip().upper(), d.get("hw_id","").strip(), "etanom-teklif")
    return jsonify(result)

@app.route("/api/etanom-fatura-license", methods=["POST"])
def verify_etanom_fatura():
    d = request.get_json(silent=True) or {}
    _, result = _verify_core(d.get("license_key","").strip().upper(), d.get("hw_id","").strip(), "etanom-fatura")
    return jsonify(result)

@app.route("/health")
def health():
    return jsonify({"ok": True, "service": "license-panel"})



LOGIN_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gazi Medya | Lisans Yönetim Paneli</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --navy:#07111f;--navy2:#0f1b2d;--panel:#0b1626;--paper:#ffffff;
  --ink:#101828;--muted:#667085;--soft:#f2f4f7;--line:#e4e7ec;
  --brand:#1d4ed8;--brand2:#0f766e;--brand-soft:#eff6ff;
  --danger:#b42318;--danger-bg:#fff1f0;--danger-line:#fecdca;
  --shadow:0 28px 70px rgba(2,6,23,.34);
}
html,body{min-height:100%;overflow-x:hidden}
body{
  min-height:100vh;
  font-family:'Inter',Arial,sans-serif;
  color:var(--ink);
  background:
    radial-gradient(circle at 8% 8%,rgba(29,78,216,.24),transparent 30%),
    radial-gradient(circle at 92% 12%,rgba(15,118,110,.22),transparent 32%),
    linear-gradient(135deg,#06101f 0%,#0b1324 48%,#111827 100%);
  display:flex;
  align-items:center;
  justify-content:center;
  padding:34px;
  -webkit-font-smoothing:antialiased;
}
body:before{
  content:"";
  position:fixed;
  inset:0;
  background-image:
    linear-gradient(rgba(255,255,255,.045) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.045) 1px,transparent 1px);
  background-size:44px 44px;
  mask-image:linear-gradient(to bottom,rgba(0,0,0,.95),transparent 82%);
  pointer-events:none;
}
.login-shell{
  position:relative;
  width:min(1040px,100%);
  min-height:640px;
  background:rgba(255,255,255,.96);
  border:1px solid rgba(255,255,255,.42);
  border-radius:30px;
  box-shadow:var(--shadow);
  overflow:hidden;
  display:grid;
  grid-template-columns:1.12fr .88fr;
}
.login-info{
  position:relative;
  padding:42px;
  color:#fff;
  background:
    linear-gradient(145deg,rgba(7,17,31,.98),rgba(15,27,45,.96)),
    radial-gradient(circle at 20% 20%,rgba(29,78,216,.60),transparent 38%);
  overflow:hidden;
}
.login-info:before{
  content:"";
  position:absolute;
  width:420px;height:420px;
  right:-170px;bottom:-150px;
  border-radius:50%;
  background:radial-gradient(circle,rgba(37,99,235,.34),transparent 68%);
}
.login-info:after{
  content:"";
  position:absolute;
  inset:0;
  background-image:linear-gradient(rgba(255,255,255,.055) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.055) 1px,transparent 1px);
  background-size:34px 34px;
  opacity:.38;
  pointer-events:none;
}
.brand-row{position:relative;z-index:1;display:flex;align-items:center;gap:14px;margin-bottom:76px}
.brand-mark{
  width:48px;height:48px;border-radius:15px;
  background:linear-gradient(135deg,#2563eb,#0f766e);
  display:flex;align-items:center;justify-content:center;
  color:#fff;font-size:15px;font-weight:900;letter-spacing:-.04em;
  box-shadow:0 18px 34px rgba(37,99,235,.30);
}
.brand-name{font-size:17px;font-weight:850;letter-spacing:-.03em}
.brand-sub{font-size:12px;color:#b9c7d8;margin-top:2px;font-weight:500}
.hero{position:relative;z-index:1;max-width:500px}
.eyebrow{
  display:inline-flex;align-items:center;gap:8px;
  color:#bfdbfe;background:rgba(37,99,235,.16);border:1px solid rgba(147,197,253,.22);
  border-radius:999px;padding:8px 12px;font-size:12px;font-weight:700;margin-bottom:20px;
}
.eyebrow:before{content:"";width:7px;height:7px;border-radius:50%;background:#22c55e;box-shadow:0 0 0 4px rgba(34,197,94,.14)}
.hero h1{font-size:42px;line-height:1.06;letter-spacing:-.055em;font-weight:900;margin-bottom:18px}
.hero p{font-size:15px;line-height:1.72;color:#c9d5e4;max-width:430px}
.feature-grid{position:relative;z-index:1;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:46px;max-width:500px}
.feature{
  background:rgba(255,255,255,.075);
  border:1px solid rgba(255,255,255,.11);
  border-radius:18px;
  padding:16px;
  backdrop-filter:blur(8px);
}
.feature strong{display:block;font-size:13px;font-weight:800;margin-bottom:5px;color:#fff}
.feature span{display:block;color:#b9c7d8;font-size:12px;line-height:1.45}
.login-area{display:flex;align-items:center;justify-content:center;padding:48px;background:linear-gradient(180deg,#ffffff 0%,#f8fafc 100%)}
.card{width:100%;max-width:390px}
.card-top{margin-bottom:30px}
.secure-badge{
  width:58px;height:58px;border-radius:18px;
  background:linear-gradient(135deg,var(--brand-soft),#ecfdf3);
  border:1px solid #dbeafe;
  display:flex;align-items:center;justify-content:center;
  margin-bottom:20px;
}
.secure-badge svg{width:28px;height:28px;color:var(--brand)}
h2{font-size:27px;line-height:1.18;letter-spacing:-.04em;font-weight:900;margin-bottom:9px;color:var(--ink)}
.sub{color:var(--muted);font-size:14px;line-height:1.58}
.err{
  display:flex;align-items:flex-start;gap:10px;
  background:var(--danger-bg);
  border:1px solid var(--danger-line);
  color:var(--danger);
  border-radius:14px;
  padding:12px 14px;
  margin:0 0 18px;
  font-size:13px;
  line-height:1.45;
  font-weight:700;
}
.err:before{content:"!";width:20px;height:20px;border-radius:50%;background:#fee4e2;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:12px;font-weight:900}
.form-group{margin-bottom:16px}
label{display:block;font-size:12px;font-weight:800;color:#344054;margin-bottom:7px;letter-spacing:.01em}
.input-wrap{position:relative}
.input-wrap svg{position:absolute;left:14px;top:50%;transform:translateY(-50%);width:18px;height:18px;color:#98a2b3;pointer-events:none}
input{
  width:100%;height:48px;background:#fff;border:1.5px solid #d0d5dd;color:var(--ink);
  border-radius:14px;padding:0 14px 0 44px;font-size:14px;outline:none;font-family:inherit;
  transition:border-color .15s,box-shadow .15s,background .15s;
}
input::placeholder{color:#98a2b3}
input:focus{border-color:#2563eb;box-shadow:0 0 0 4px rgba(37,99,235,.13)}
.form-meta{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:6px 0 18px;color:#667085;font-size:12px}
.status{display:inline-flex;align-items:center;gap:7px;font-weight:700;color:#475467}
.status:before{content:"";width:7px;height:7px;border-radius:50%;background:#16a34a}
button{
  width:100%;height:48px;border:none;border-radius:14px;
  background:linear-gradient(135deg,#1d4ed8,#2563eb 58%,#0f766e);
  color:#fff;font-size:14px;font-weight:850;cursor:pointer;
  box-shadow:0 16px 28px rgba(29,78,216,.24);
  transition:transform .15s,box-shadow .15s,filter .15s;
}
button:hover{filter:brightness(.98);box-shadow:0 20px 36px rgba(29,78,216,.30)}
button:active{transform:translateY(1px)}
.security-note{
  margin-top:20px;
  padding:14px 15px;
  background:#f8fafc;
  border:1px solid var(--line);
  border-radius:16px;
  color:#667085;
  font-size:12px;
  line-height:1.55;
}
.foot{margin-top:28px;color:#98a2b3;font-size:11px;letter-spacing:.08em;text-transform:uppercase;font-weight:800;text-align:center}
@media(max-width:900px){
  body{padding:22px}
  .login-shell{grid-template-columns:1fr;min-height:auto;border-radius:24px}
  .login-info{display:none}
  .login-area{padding:42px 24px}
}
@media(max-width:480px){
  body{padding:14px}
  .login-area{padding:30px 20px}
  h2{font-size:24px}
}
</style></head>
<body>
<div class="login-shell">
  <section class="login-info">
    <div class="brand-row">
      <div class="brand-mark">GM</div>
      <div>
        <div class="brand-name">Gazi Medya</div>
        <div class="brand-sub">Kurumsal Yazılım Lisans Altyapısı</div>
      </div>
    </div>
    <div class="hero">
      <div class="eyebrow">Yönetici erişim alanı</div>
      <h1>Lisans süreçlerinizi tek panelden yönetin.</h1>
      <p>Ürün lisansları, müşteri kayıtları, doğrulama hareketleri ve yetkili işlemler için hazırlanmış güvenli yönetim ekranı.</p>
    </div>
    <div class="feature-grid">
      <div class="feature"><strong>Merkezi Kontrol</strong><span>Tüm ürün lisanslarını tek yönetim ekranında izleyin.</span></div>
      <div class="feature"><strong>Güvenli Doğrulama</strong><span>Donanım ID ve lisans anahtarı eşleşmelerini takip edin.</span></div>
      <div class="feature"><strong>İşlem Geçmişi</strong><span>Panel üzerinde yapılan kritik işlemleri kayıt altında tutun.</span></div>
      <div class="feature"><strong>Kurumsal Kullanım</strong><span>Müşteri, paket ve süre yönetimini düzenli şekilde yürütün.</span></div>
    </div>
  </section>

  <section class="login-area">
    <div class="card">
      <div class="card-top">
        <div class="secure-badge" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.55-2.9 8.64-7 10-4.1-1.36-7-5.45-7-10V6l7-3z" stroke="currentColor" stroke-width="1.8"/><path d="M9.5 12.2l1.7 1.7 3.6-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </div>
        <h2>Panele Giriş</h2>
        <div class="sub">Lisans yönetim sistemine erişmek için yetkili kullanıcı bilgilerinizle oturum açın.</div>
      </div>

      {% if error %}<div class="err">{{ error }}</div>{% endif %}

      <form method="POST">
        <div class="form-group">
          <label>Kullanıcı Adı</label>
          <div class="input-wrap">
            <svg viewBox="0 0 24 24" fill="none"><path d="M20 21a8 8 0 0 0-16 0" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M12 13a5 5 0 1 0 0-10 5 5 0 0 0 0 10z" stroke="currentColor" stroke-width="1.8"/></svg>
            <input name="username" autocomplete="username" placeholder="Kullanıcı adınızı girin" required autofocus>
          </div>
        </div>
        <div class="form-group">
          <label>Şifre</label>
          <div class="input-wrap">
            <svg viewBox="0 0 24 24" fill="none"><path d="M7 11V8a5 5 0 0 1 10 0v3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M6.5 11h11A1.5 1.5 0 0 1 19 12.5v6A1.5 1.5 0 0 1 17.5 20h-11A1.5 1.5 0 0 1 5 18.5v-6A1.5 1.5 0 0 1 6.5 11z" stroke="currentColor" stroke-width="1.8"/></svg>
            <input name="password" type="password" autocomplete="current-password" placeholder="Şifrenizi girin" required>
          </div>
        </div>
        <div class="form-meta"><span class="status">Güvenli oturum</span><span>Yetkili erişim</span></div>
        <button type="submit">Oturum Aç</button>
      </form>

      <div class="security-note">Bu alan yalnızca yetkili kullanıcılar içindir. Giriş işlemleri sistem güvenliği kapsamında kayıt altına alınır.</div>
      <div class="foot">GAZİ MEDYA YAZILIM &copy; LİSANS YÖNETİM PLATFORMU</div>
    </div>
  </section>
</div>
</body></html>"""
CHANGE_PASS_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Şifre Değiştir</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700;900&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f5f7fb;--card:#ffffff;--line:#e6eaf0;--text:#172033;--muted:#667085;
  --brand:#1d4ed8;--brand-d:#1e40af;--ok:#067647;--ok-bg:#ecfdf3;--danger:#b42318;--danger-bg:#fff1f0;
}
html,body{overflow-x:hidden;min-height:100%}
body{
  min-height:100vh;background:
  radial-gradient(circle at 0 0,rgba(37,99,235,.10),transparent 32%),
  linear-gradient(180deg,#ffffff 0%,var(--bg) 100%);
  font-family:'Roboto',Arial,sans-serif;color:var(--text);-webkit-font-smoothing:antialiased;
}
nav{
  height:68px;display:flex;align-items:center;justify-content:space-between;
  padding:0 28px;background:rgba(255,255,255,.88);backdrop-filter:blur(14px);
  border-bottom:1px solid var(--line);position:sticky;top:0;z-index:10;
}
.brand{font-weight:900;font-size:15px;color:var(--text);display:flex;align-items:center;gap:11px;letter-spacing:-.015em}
.brand .b{
  width:34px;height:34px;border-radius:11px;
  background:linear-gradient(135deg,var(--brand),#2563eb);
  display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:900;color:#fff;
  box-shadow:0 10px 20px rgba(29,78,216,.20);
}
.nav-links{display:flex;align-items:center;gap:8px}
.nav-links a{
  color:#475467;text-decoration:none;font-size:13px;font-weight:800;
  padding:9px 12px;border-radius:10px;transition:background .15s,color .15s;
}
.nav-links a:hover{background:#eef4ff;color:var(--brand-d)}
.wrap{max-width:520px;margin:70px auto;padding:0 20px}
.card{
  background:var(--card);border:1px solid var(--line);border-radius:20px;padding:34px;
  box-shadow:0 24px 70px rgba(15,23,42,.10);
}
h1{font-size:22px;font-weight:900;letter-spacing:-.03em;margin-bottom:6px}
.sub{color:var(--muted);font-size:14px;line-height:1.55;margin-bottom:26px}
.ok,.er{
  padding:12px 14px;border-radius:12px;margin-bottom:18px;font-size:13px;font-weight:800;
}
.ok{background:var(--ok-bg);border:1px solid #abefc6;color:var(--ok)}
.er{background:var(--danger-bg);border:1px solid #fecdca;color:var(--danger)}
label{display:block;font-size:12px;font-weight:800;color:#344054;margin-bottom:7px}
.field{margin-bottom:17px}
input{
  width:100%;background:#fff;border:1px solid #d0d5dd;color:var(--text);border-radius:12px;
  padding:12px 14px;font-size:14px;outline:none;font-family:inherit;transition:border-color .15s,box-shadow .15s;
}
input:focus{border-color:#2563eb;box-shadow:0 0 0 4px rgba(37,99,235,.13)}
button{
  width:100%;border:none;border-radius:12px;padding:12px 16px;margin-top:8px;
  background:linear-gradient(135deg,var(--brand),#2563eb);color:#fff;font-size:14px;font-weight:900;cursor:pointer;
  box-shadow:0 12px 24px rgba(29,78,216,.20);transition:filter .15s,transform .15s;
}
button:hover{filter:brightness(.96)}
button:active{transform:translateY(1px)}
@media(max-width:620px){nav{padding:0 16px}.nav-links a{padding:8px 9px}.wrap{margin:38px auto}.card{padding:26px;border-radius:18px}}
</style></head>
<body>
<nav>
  <div class="brand"><div class="b">GM</div>Gazi Medya</div>
  <div class="nav-links"><a href="/">Panele Dön</a><a href="/logout">Çıkış</a></div>
</nav>
<div class="wrap"><div class="card">
  <h1>Şifre Değiştir</h1>
  <div class="sub">Panel giriş şifrenizi güvenli şekilde güncelleyin.</div>
  {% if msg %}<div class="ok">{{ msg }}</div>{% endif %}
  {% if err %}<div class="er">{{ err }}</div>{% endif %}
  <form method="POST">
    <div class="field"><label>Mevcut Şifre</label><input type="password" name="current" required></div>
    <div class="field"><label>Yeni Şifre</label><input type="password" name="new_pass" required minlength="8"></div>
    <div class="field"><label>Yeni Şifre Tekrar</label><input type="password" name="confirm" required></div>
    <button type="submit">Şifreyi Güncelle</button>
  </form>
</div></div>
</body></html>"""

PANEL_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gazi Medya Lisans Paneli</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700;900&family=Roboto+Mono:wght@500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{overflow-x:hidden;width:100%}
:root{
  --bg:#f5f7fb;--card:#ffffff;--line:#e6eaf0;--line2:#d0d5dd;
  --text:#172033;--muted:#667085;--muted2:#98a2b3;
  --brand:#1d4ed8;--brand-d:#1e40af;--brand-soft:#eff6ff;
  --nav:#0b1220;--nav-2:#111b2f;--nav-line:rgba(255,255,255,.08);--nav-text:#d0d5dd;
  --green:#067647;--green-bg:#ecfdf3;--green-bd:#abefc6;
  --amber:#b54708;--amber-bg:#fffaeb;--amber-bd:#fedf89;
  --red:#b42318;--red-bg:#fff1f0;--red-bd:#fecdca;
  --gray:#344054;--gray-bg:#f2f4f7;--gray-bd:#d0d5dd;
  --radius:16px;--sidebar-w:276px
}
html{scrollbar-color:#cbd5e1 transparent}
::-webkit-scrollbar{height:10px;width:10px}
::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:999px;border:2px solid transparent;background-clip:content-box}
body{
  background:
    radial-gradient(circle at 70% -10%,rgba(37,99,235,.10),transparent 32%),
    linear-gradient(180deg,#ffffff 0%,var(--bg) 260px);
  color:var(--text);min-height:100vh;font-family:'Roboto',Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
}
.shell{display:flex;min-height:100vh;min-width:0}

/* ── Sol Menü ────────────────────────────────────────── */
.sidebar{
  width:var(--sidebar-w);flex-shrink:0;
  background:linear-gradient(180deg,var(--nav) 0%,var(--nav-2) 100%);
  border-right:1px solid var(--nav-line);display:flex;flex-direction:column;
  position:sticky;top:0;height:100vh;overflow-y:auto;
  box-shadow:18px 0 45px rgba(15,23,42,.10);
}
.side-brand{
  display:flex;align-items:center;gap:12px;padding:22px 20px 18px;border-bottom:1px solid var(--nav-line);
}
.side-brand .b{
  width:42px;height:42px;border-radius:14px;
  background:linear-gradient(135deg,#2563eb,#1d4ed8 58%,#0f766e);
  display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:#fff;flex-shrink:0;
  box-shadow:0 16px 30px rgba(37,99,235,.24);
}
.side-brand h1{font-size:15px;font-weight:900;letter-spacing:-.02em;color:#fff}
.side-brand small{display:block;color:#98a2b3;font-size:11px;margin-top:3px;font-weight:500}
.side-section{padding:14px 12px 8px}
.side-label{
  font-size:10px;font-weight:900;letter-spacing:.12em;text-transform:uppercase;color:#7b8798;
  padding:13px 12px 8px;
}
.nav-link{
  display:flex;align-items:center;justify-content:space-between;gap:9px;color:var(--nav-text);text-decoration:none;
  font-size:13px;font-weight:700;padding:10px 11px;border-radius:12px;margin-bottom:4px;
  transition:background .15s,color .15s,transform .15s;
}
.nav-link:hover{background:rgba(255,255,255,.07);color:#fff}
.nav-link.on{background:rgba(37,99,235,.18);color:#fff;box-shadow:0 0 0 1px rgba(59,130,246,.20) inset}
.nav-link .lbl{display:flex;align-items:center;gap:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.badge{
  width:28px;height:24px;border-radius:9px;flex-shrink:0;display:flex;align-items:center;justify-content:center;
  font-size:9.5px;font-weight:900;color:#fff;letter-spacing:-.02em;box-shadow:0 7px 14px rgba(0,0,0,.18);
}
.badge-all{background:#475467}.badge-hr{background:#2563eb}.badge-asc{background:#ea580c}.badge-ft{background:#039855}
.badge-eta{background:#7c3aed}.badge-kkdik{background:#0891b2}.badge-etk{background:#d97706}.badge-etf{background:#dc2626}
.nav-link .cnt{
  background:rgba(255,255,255,.08);color:#cbd5e1;font-size:11px;font-weight:900;padding:3px 8px;border-radius:999px;flex-shrink:0;
}
.nav-link.on .cnt{background:#fff;color:var(--brand-d)}
.side-spacer{flex:1}
.side-log{padding:6px 12px 10px;border-top:1px solid var(--nav-line);margin-top:6px}
.side-log .side-label{padding:14px 12px 10px}
.side-log .list{max-height:320px;overflow-y:auto;display:flex;flex-direction:column;gap:8px;padding-right:2px}
.side-log .log-item{
  padding:10px 11px;border-radius:13px;background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.08);
  border-left:3px solid #60a5fa;
}
.side-log .log-item strong{display:block;margin-bottom:4px;font-size:11px;font-weight:900;color:#fff}
.side-log .log-item div{font-size:11px;color:#cbd5e1;margin-bottom:4px;word-break:break-word;line-height:1.4}
.side-log .log-item small{color:#7b8798;font-size:10px}
.side-foot{padding:12px;border-top:1px solid var(--nav-line)}
.side-foot a{
  display:flex;align-items:center;gap:8px;color:var(--nav-text);text-decoration:none;font-size:13px;font-weight:800;
  padding:10px 11px;border-radius:12px;transition:background .15s,color .15s;
}
.side-foot a:hover{background:rgba(255,255,255,.07);color:#fff}

/* ── İçerik ──────────────────────────────────────────── */
.main{flex:1;min-width:0;padding:30px 34px 46px;max-width:100%}
.topbar{
  display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap;margin-bottom:22px;
  padding:22px 24px;border:1px solid var(--line);border-radius:22px;background:rgba(255,255,255,.90);
  box-shadow:0 18px 45px rgba(15,23,42,.06);
}
.topbar h2{font-size:25px;font-weight:900;letter-spacing:-.04em;margin-bottom:7px;color:#101828}
.topbar p{color:var(--muted);font-size:13.5px;max-width:650px;line-height:1.55}
.btn{
  border:none;border-radius:12px;padding:10px 16px;font-size:13px;font-weight:900;cursor:pointer;color:#fff;text-decoration:none;
  display:inline-flex;align-items:center;justify-content:center;gap:7px;transition:filter .15s,transform .15s,box-shadow .15s;white-space:nowrap;
  box-shadow:0 8px 18px rgba(15,23,42,.12);
}
.btn:hover{filter:brightness(.96);box-shadow:0 10px 22px rgba(15,23,42,.16)}
.btn:active{transform:translateY(1px)}
.btn-main{background:linear-gradient(135deg,var(--brand),#2563eb)}
.btn-green{background:linear-gradient(135deg,#067647,#039855)}
.btn-orange{background:linear-gradient(135deg,#b54708,#d97706)}
.btn-red{background:linear-gradient(135deg,#b42318,#dc2626)}
.btn-muted{background:linear-gradient(135deg,#475467,#667085)}
.btn-xs{padding:7px 10px;font-size:11px;border-radius:10px;box-shadow:none}

.stats{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin-bottom:10px}
.stat{
  background:rgba(255,255,255,.92);border:1px solid var(--line);border-radius:18px;padding:16px 17px;min-width:0;
  box-shadow:0 12px 34px rgba(15,23,42,.05);position:relative;overflow:hidden;
}
.stat:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:linear-gradient(180deg,var(--brand),#0f766e)}
.stat .k{color:var(--muted);font-size:11px;margin-bottom:9px;font-weight:900;text-transform:uppercase;letter-spacing:.06em}
.stat .v{font-size:28px;font-weight:900;letter-spacing:-.04em;color:#101828}
.stats-note{font-size:12px;color:var(--muted);margin-bottom:22px;padding-left:2px}

.card{
  background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:20px;overflow:hidden;min-width:0;
  box-shadow:0 20px 55px rgba(15,23,42,.07);
}
.card-head{
  padding:17px 20px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:12px;
  background:linear-gradient(180deg,#fff,#fbfcff);
}
.card-head h3{font-size:15px;font-weight:900;letter-spacing:-.01em}
.card-body{padding:20px}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}
.full{grid-column:1/-1}
label{display:block;font-size:12px;font-weight:900;color:#344054;margin-bottom:7px}
input,select,textarea{
  width:100%;background:#fff;border:1px solid #d0d5dd;color:var(--text);border-radius:12px;padding:11px 13px;font-size:13px;
  outline:none;font-family:inherit;transition:border-color .15s,box-shadow .15s;
}
select,option{background:#fff;color:var(--text)}
textarea{min-height:86px;resize:vertical}
input:focus,select:focus,textarea:focus{border-color:#2563eb;box-shadow:0 0 0 4px rgba(37,99,235,.13)}
.actions{margin-top:17px;display:flex;justify-content:flex-end;gap:10px}

.table-wrap{overflow-x:auto;max-width:100%}
.toolbar{
  display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:14px 20px;border-bottom:1px solid var(--line);
  background:#fff;
}
.search{
  min-width:240px;flex:1;background:#f9fafb;border:1px solid #d0d5dd;border-radius:12px;color:var(--text);
  padding:10px 13px;font-size:13px;outline:none;
}
.search:focus{background:#fff;border-color:#2563eb;box-shadow:0 0 0 4px rgba(37,99,235,.13)}
.filter-tabs{display:flex;gap:6px;flex-wrap:wrap}
.ftab{
  border:1px solid var(--line2);background:#fff;color:#475467;border-radius:999px;padding:8px 12px;font-size:11px;font-weight:900;cursor:pointer;
  transition:all .15s;
}
.ftab:hover{background:#f8fafc;color:#1d2939}
.ftab.on{color:#fff;background:linear-gradient(135deg,var(--brand),#2563eb);border-color:transparent;box-shadow:0 8px 18px rgba(29,78,216,.18)}
table{width:100%;border-collapse:separate;border-spacing:0;table-layout:auto}
th,td{padding:13px 14px;border-bottom:1px solid var(--line);text-align:left;font-size:12.5px;vertical-align:middle}
th{
  color:#667085;font-size:10px;letter-spacing:.07em;text-transform:uppercase;font-weight:900;background:#f8fafc;white-space:nowrap;
  position:sticky;top:0;z-index:1;
}
tbody tr{transition:background .12s}
tbody tr:hover td{background:#f6f9ff}
td.col-id{width:52px;color:var(--muted2);font-variant-numeric:tabular-nums;font-weight:800}
td.col-cust{max-width:190px}
.custname{font-weight:800;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;color:#1d2939}
.kbox{
  display:inline-flex;align-items:center;gap:6px;max-width:230px;overflow:hidden;text-overflow:ellipsis;padding:7px 10px;border-radius:10px;
  background:#f2f4f7;border:1px solid #eaecf0;font-family:'Roboto Mono',ui-monospace,Consolas,monospace;cursor:pointer;font-size:11px;
  white-space:nowrap;transition:background .15s,border-color .15s,color .15s;
}
.kbox:hover{background:var(--brand-soft);border-color:#bfdbfe;color:var(--brand-d)}
.pill{
  display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:999px;font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;
}
.pill::before{content:"";width:7px;height:7px;border-radius:50%;flex-shrink:0}
.green{background:var(--green-bg);color:var(--green);border:1px solid var(--green-bd)}.green::before{background:var(--green)}
.amber{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-bd)}.amber::before{background:var(--amber)}
.red{background:var(--red-bg);color:var(--red);border:1px solid var(--red-bd)}.red::before{background:var(--red)}
.gray{background:var(--gray-bg);color:var(--gray);border:1px solid var(--gray-bd)}.gray::before{background:var(--gray)}
.actions-row{display:flex;gap:5px;flex-wrap:nowrap;align-items:center}

.modal{
  position:fixed;inset:0;background:rgba(15,23,42,.54);backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center;
  z-index:999;padding:18px;
}
.modal.open{display:flex}
.modal-box{
  width:100%;max-width:480px;background:#fff;border:1px solid rgba(255,255,255,.55);border-radius:22px;
  box-shadow:0 30px 90px rgba(2,6,23,.35);overflow:hidden;max-height:88vh;display:flex;flex-direction:column;
}
.modal-head{
  padding:18px 21px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;
  background:linear-gradient(180deg,#fff,#f8fafc);
}
.modal-head h4{font-size:15px;font-weight:900;letter-spacing:-.01em}
.modal-close{
  border:none;background:#f2f4f7;color:#667085;font-size:18px;cursor:pointer;width:32px;height:32px;border-radius:10px;line-height:1;
}
.modal-close:hover{background:#e4e7ec;color:#101828}
.modal-body{padding:21px;overflow-y:auto}
.info-section{margin:16px 0 6px;padding-top:14px;border-top:1px solid var(--line);font-size:11px;font-weight:900;color:#667085;text-transform:uppercase;letter-spacing:.08em}
.info-section:first-child{margin-top:0;padding-top:0;border-top:none}
.info-row{display:flex;justify-content:space-between;gap:16px;padding:12px 0;border-bottom:1px solid var(--line);font-size:13px}
.info-row:last-child{border-bottom:none}
.info-row .ik{color:var(--muted);font-weight:900;flex-shrink:0}
.info-row .iv{text-align:right;font-weight:800;word-break:break-word;color:#1d2939}
.toast{
  position:fixed;right:22px;bottom:22px;z-index:1200;background:#101828;color:#fff;padding:11px 16px;border-radius:12px;font-size:13px;font-weight:900;
  opacity:0;transform:translateY(10px);transition:.2s;pointer-events:none;box-shadow:0 18px 40px rgba(15,23,42,.24);
}
.toast.show{opacity:1;transform:translateY(0)}
.note{font-size:12px;color:var(--muted);font-weight:800}
@media(max-width:1280px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.actions-row{flex-wrap:wrap}}
@media(max-width:980px){.sidebar{display:none}.main{padding:20px}}
@media(max-width:740px){.main{padding:16px}.topbar{padding:18px}.stats{grid-template-columns:minmax(0,1fr)}.form-grid{grid-template-columns:minmax(0,1fr)}.search{min-width:100%}.toolbar{align-items:stretch}.filter-tabs{width:100%}.ftab{flex:1}.actions{flex-direction:column}.actions .btn{width:100%}}
</style></head>
<body>
<div class="shell">
  <aside class="sidebar">
    <div class="side-brand">
      <div class="b">GM</div>
      <div><h1>Gazi Medya</h1><small>Lisans Paneli</small></div>
    </div>
    <div class="side-section">
      <div class="side-label">Ürünler</div>
      <a href="/?product=all" class="nav-link {{ 'on' if prod_filter=='all' else '' }}"><span class="lbl"><span class="badge badge-all">TÜM</span>Tümü</span><span class="cnt">{{ stats.total }}</span></a>
      <a href="/?product=gazi-hr" class="nav-link {{ 'on' if prod_filter=='gazi-hr' else '' }}"><span class="lbl"><span class="badge badge-hr">HR</span>Gazi HR</span><span class="cnt">{{ stats.hr_count }}</span></a>
      <a href="/?product=autoservis-crm" class="nav-link {{ 'on' if prod_filter=='autoservis-crm' else '' }}"><span class="lbl"><span class="badge badge-asc">AS</span>AutoServis</span><span class="cnt">{{ stats.asc_count }}</span></a>
      <a href="/?product=fiyat-teklifi" class="nav-link {{ 'on' if prod_filter=='fiyat-teklifi' else '' }}"><span class="lbl"><span class="badge badge-ft">FT</span>Fiyat Teklifi</span><span class="cnt">{{ stats.ft_count }}</span></a>
      <a href="/?product=eta-analitik" class="nav-link {{ 'on' if prod_filter=='eta-analitik' else '' }}"><span class="lbl"><span class="badge badge-eta">EA</span>ETA Analitik</span><span class="cnt">{{ stats.eta_count }}</span></a>
      <a href="/?product=kkdik" class="nav-link {{ 'on' if prod_filter=='kkdik' else '' }}"><span class="lbl"><span class="badge badge-kkdik">KK</span>KKDİK Suite</span><span class="cnt">{{ stats.kkdik_count }}</span></a>
      <a href="/?product=etanom-teklif" class="nav-link {{ 'on' if prod_filter=='etanom-teklif' else '' }}"><span class="lbl"><span class="badge badge-etk">ET</span>Etanom Teklif</span><span class="cnt">{{ stats.etanom_count }}</span></a>
      <a href="/?product=etanom-fatura" class="nav-link {{ 'on' if prod_filter=='etanom-fatura' else '' }}"><span class="lbl"><span class="badge badge-etf">EF</span>Etanom Fatura</span><span class="cnt">{{ stats.fatura_count }}</span></a>
    </div>
    <div class="side-section">
      <div class="side-label">Yönetim</div>
      <a href="/audit-log" class="nav-link"><span class="lbl"><span class="badge badge-all">LOG</span>İşlem Geçmişi</span></a>
    </div>
    <div class="side-spacer"></div>
    <div class="side-log">
      <div class="side-label">Son İşlemler</div>
      <a href="/audit-log" class="nav-link" style="margin:0 0 8px 0"><span class="lbl"><span class="badge badge-all">TÜM</span>Tüm geçmişi aç</span></a>
      <div class="list">
        {% for lg in logs %}
        <div class="log-item">
          <strong>{{ lg.action }}</strong>
          <div>{{ lg.detail or '-' }}</div>
          <small>{{ lg.created_at }}</small>
        </div>
        {% else %}
        <div class="log-item">Kayıt yok.</div>
        {% endfor %}
      </div>
    </div>
    <div class="side-foot">
      <a href="/change-password">Şifre Değiştir</a>
      <a href="/logout">Çıkış Yap</a>
    </div>
  </aside>

  <main class="main">
    <div class="topbar">
      <div>
        <h2>
          {% if prod_filter in products %}{{ products[prod_filter].label }} Lisansları
          {% else %}Tüm Lisanslar{% endif %}
        </h2>
        <p>
          {% if prod_filter in products %}Bu sayfada yalnızca {{ products[prod_filter].label }} ürününe ait lisanslar listelenir.
          {% else %}Tüm ürün portföyünüzdeki lisansları buradan yönetin.{% endif %}
        </p>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <a class="btn btn-muted" href="/audit-log">İşlem Geçmişi</a>
        <button class="btn btn-green" type="button" onclick="exportLicenses()">Excel'e Aktar</button>
        <button class="btn btn-main" type="button" onclick="openM('yeniLisans')">+ Yeni Lisans Ekle</button>
      </div>
    </div>

    <div class="stats">
      <div class="stat"><div class="k">Toplam</div><div class="v">{{ fstats.total }}</div></div>
      <div class="stat"><div class="k">Aktif</div><div class="v">{{ fstats.active }}</div></div>
      <div class="stat"><div class="k">Dolmuş</div><div class="v">{{ fstats.expired }}</div></div>
      <div class="stat"><div class="k">İptal</div><div class="v">{{ fstats.revoked }}</div></div>
      <div class="stat"><div class="k">Yaklaşan (30 Gün)</div><div class="v">{{ fstats.expiring }}</div></div>
    </div>
    <div class="stats-note">
      {% if prod_filter in products %}Bu sayılar yalnızca {{ products[prod_filter].label }} lisanslarını kapsar &middot; Portföy genelinde {{ stats.total }} lisans bulunuyor.
      {% else %}Bu sayılar tüm ürün portföyünü kapsar.{% endif %}
    </div>

    <div class="card">
      <div class="card-head">
        <h3>Lisanslar</h3>
        <div class="note">{{ licenses|length }} kayıt listeleniyor</div>
      </div>
      <div class="toolbar">
        <input class="search" id="srch" placeholder="Müşteri, lisans anahtarı veya HW ID ara..." oninput="flt()">
        <div class="filter-tabs">
          <button class="ftab on" type="button" onclick="setF('all',this)">Tümü</button>
          <button class="ftab" type="button" onclick="setF('active',this)">Aktif</button>
          <button class="ftab" type="button" onclick="setF('expired',this)">Dolmuş</button>
          <button class="ftab" type="button" onclick="setF('revoked',this)">İptal</button>
          <button class="ftab" type="button" onclick="exportLicenses()">Excel</button>
        </div>
      </div>
      <div class="card-body table-wrap" style="padding:0">
        <table>
          <thead>
            <tr>
              <th>ID</th><th>Müşteri</th><th>HW ID</th><th>Lisans Anahtarı</th><th>Durum</th><th>İşlemler</th>
            </tr>
          </thead>
          <tbody>
            {% for l in licenses %}
            {% set is_exp = l.expires_at < now %}
            {% set status = 'revoked' if l.is_revoked else ('expired' if is_exp else 'active') %}
            <tr data-s="{{ status }}" data-q="{{ ((l.customer_name or '')~' '~(l.customer_email or '')~' '~(l.customer_phone or '')~' '~(l.license_key or '')~' '~(l.hw_id or '')~' '~(l.notes or '')~' '~(l.package or ''))|lower }}">
              <td class="col-id">{{ l.id }}</td>
              <td class="col-cust"><span class="custname" title="{{ l.customer_name or '-' }}">{{ l.customer_name or '-' }}</span></td>
              <td><span class="kbox" onclick="copyText('{{ l.hw_id }}')" title="Kopyala">{{ l.hw_id }}</span></td>
              <td><span class="kbox" onclick="copyText('{{ l.license_key }}')" title="Kopyala">{{ l.license_key }}</span></td>
              <td>
                {% if l.is_revoked %}<span class="pill red">İptal</span>
                {% elif is_exp %}<span class="pill amber">Dolmuş</span>
                {% else %}<span class="pill green">Aktif</span>{% endif %}
              </td>
              <td>
                <div class="actions-row">
                  <button class="btn btn-muted btn-xs" type="button" onclick="openM('detay{{ l.id }}')">Detay</button>
                  <button class="btn btn-green btn-xs" type="button" onclick="openM('uzat{{ l.id }}')">Uzat</button>
                  <button class="btn btn-main btn-xs" type="button" onclick="openM('duz{{ l.id }}')">Düzenle</button>
                  {% if not l.is_revoked %}
                    <button class="btn btn-orange btn-xs" type="button" onclick="openM('ipt{{ l.id }}')">İptal</button>
                  {% else %}
                    <form method="POST" action="/restore/{{ l.id }}" style="display:inline">
                      <button class="btn btn-green btn-xs" type="submit">Aktifleştir</button>
                    </form>
                  {% endif %}
                  <form method="POST" action="/delete/{{ l.id }}" style="display:inline" onsubmit="return confirm('Kalıcı silinecek. Devam?')">
                    <button class="btn btn-red btn-xs" type="submit">Sil</button>
                  </form>
                </div>
              </td>
            </tr>
            {% else %}
            <tr><td colspan="6" style="padding:32px;color:var(--muted)">Henüz lisans kaydı yok.</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </main>
</div>

<div id="yeniLisans" class="modal" onclick="if(event.target===this)closeM('yeniLisans')">
  <div class="modal-box">
    <div class="modal-head"><h4>Yeni Lisans Ekle</h4><button class="modal-close" type="button" onclick="closeM('yeniLisans')">&times;</button></div>
    <div class="modal-body">
      <form method="POST" action="/create">
        <div class="form-grid">
          <div>
            <label>Ürün</label>
            <select name="product">
              <option value="gazi-hr" {{ 'selected' if prod_filter=='gazi-hr' else '' }}>Gazi HR</option>
              <option value="autoservis-crm" {{ 'selected' if prod_filter=='autoservis-crm' else '' }}>AutoServis CRM</option>
              <option value="fiyat-teklifi" {{ 'selected' if prod_filter=='fiyat-teklifi' else '' }}>Fiyat Teklifi</option>
              <option value="eta-analitik" {{ 'selected' if prod_filter=='eta-analitik' else '' }}>ETA Analitik ERP</option>
              <option value="kkdik" {{ 'selected' if prod_filter=='kkdik' else '' }}>KKDİK Suite</option>
              <option value="etanom-teklif" {{ 'selected' if prod_filter=='etanom-teklif' else '' }}>Etanom Teklif</option>
              <option value="etanom-fatura" {{ 'selected' if prod_filter=='etanom-fatura' else '' }}>Etanom Fatura (İhracat)</option>
            </select>
          </div>
          <div>
            <label>Lisans Süresi</label>
            <select name="days">
              <option value="365">1 Yıl</option>
              <option value="730">2 Yıl</option>
              <option value="180">6 Ay</option>
              <option value="90">90 Gün</option>
              <option value="30">30 Gün</option>
              <option value="9999">Süresiz</option>
            </select>
          </div>
          <div class="full">
            <label>Donanım ID (HW ID)</label>
            <input name="hw_id" required placeholder="A1B2C3-D4E5F6-A1B2C3-D4E5F6">
          </div>
          <div>
            <label>Müşteri / Firma</label>
            <input name="customer_name" placeholder="ABC Ltd. Şti.">
          </div>
          <div>
            <label>Paket</label>
            <select name="package">
              <option value="starter">Başlangıç</option>
              <option value="standard">Standart</option>
              <option value="enterprise" selected>Kurumsal</option>
            </select>
          </div>
          <div>
            <label>E-posta</label>
            <input name="customer_email" placeholder="info@firma.com">
          </div>
          <div>
            <label>Telefon</label>
            <input name="customer_phone" placeholder="+90 ...">
          </div>
          <div class="full">
            <label>Not</label>
            <textarea name="notes" placeholder="Sipariş no, temsilci, ödeme notu..."></textarea>
          </div>
        </div>
        <div class="actions">
          <button class="btn btn-muted" type="button" onclick="closeM('yeniLisans')">Vazgeç</button>
          <button class="btn btn-main" type="submit">Lisans Oluştur</button>
        </div>
      </form>
    </div>
  </div>
</div>

{% for l in licenses %}
{% set prod = l.product or 'gazi-hr' %}
<div id="detay{{ l.id }}" class="modal" onclick="if(event.target===this)closeM('detay{{ l.id }}')">
  <div class="modal-box">
    <div class="modal-head"><h4>Lisans Detayı &middot; #{{ l.id }}</h4><button class="modal-close" type="button" onclick="closeM('detay{{ l.id }}')">&times;</button></div>
    <div class="modal-body">
      <div class="info-section">Lisans Bilgileri</div>
      <div class="info-row"><div class="ik">Ürün</div><div class="iv">
        {% if prod=='autoservis-crm' %}AutoServis CRM
        {% elif prod=='fiyat-teklifi' %}Fiyat Teklifi
        {% elif prod=='eta-analitik' %}ETA Analitik ERP
        {% elif prod=='kkdik' %}KKDİK Suite
        {% elif prod=='etanom-teklif' %}Etanom Teklif
        {% elif prod=='etanom-fatura' %}Etanom Fatura (İhracat)
        {% else %}Gazi HR{% endif %}
      </div></div>
      <div class="info-row"><div class="ik">Müşteri / Firma</div><div class="iv">{{ l.customer_name or '-' }}</div></div>
      <div class="info-row"><div class="ik">E-posta</div><div class="iv">{{ l.customer_email or '-' }}</div></div>
      <div class="info-row"><div class="ik">Telefon</div><div class="iv">{{ l.customer_phone or '-' }}</div></div>
      <div class="info-row"><div class="ik">Paket</div><div class="iv">
        {% if l.package=='starter' %}Başlangıç{% elif l.package=='standard' %}Standart{% else %}Kurumsal{% endif %}
      </div></div>
      <div class="info-row"><div class="ik">Son Geçerlilik</div><div class="iv">{{ l.expires_at[:10] }}</div></div>
      <div class="info-row"><div class="ik">Son Görülme</div><div class="iv">{{ l.last_seen[:16].replace('T',' ') if l.last_seen else 'Henüz yok' }}</div></div>
      <div class="info-row"><div class="ik">Doğrulama Sayısı</div><div class="iv">{{ l.verify_count or 0 }}</div></div>

      <div class="info-section">Aktifleştirme ve Yetkili Takibi</div>
      <div class="info-row"><div class="ik">Oluşturulma Tarihi</div><div class="iv">{{ l.issued_at[:16].replace('T',' ') if l.issued_at else '-' }}</div></div>
      <div class="info-row"><div class="ik">Oluşturan Kullanıcı</div><div class="iv">{{ l.created_by or 'Eski kayıt / bilinmiyor' }}</div></div>
      <div class="info-row"><div class="ik">Aktifleştirme Tarihi</div><div class="iv">{{ l.activated_at[:16].replace('T',' ') if l.activated_at else 'Eski kayıt / bilinmiyor' }}</div></div>
      <div class="info-row"><div class="ik">Aktifleştiren Kullanıcı</div><div class="iv">{{ l.activated_by or 'Eski kayıt / bilinmiyor' }}</div></div>
      <div class="info-row"><div class="ik">Aktifleştirme IP</div><div class="iv">{{ l.activated_ip or '-' }}</div></div>
      <div class="info-row"><div class="ik">Son Uzatma</div><div class="iv">{{ l.extended_at[:16].replace('T',' ') if l.extended_at else '-' }}</div></div>
      <div class="info-row"><div class="ik">Uzatan Kullanıcı</div><div class="iv">{{ l.extended_by or '-' }}</div></div>
      <div class="info-row"><div class="ik">Son Düzenleme</div><div class="iv">{{ l.updated_at[:16].replace('T',' ') if l.updated_at else '-' }}</div></div>
      <div class="info-row"><div class="ik">Düzenleyen Kullanıcı</div><div class="iv">{{ l.updated_by or '-' }}</div></div>
      {% if l.is_revoked %}
      <div class="info-row"><div class="ik">İptal Tarihi</div><div class="iv">{{ l.revoked_at[:16].replace('T',' ') if l.revoked_at else '-' }}</div></div>
      <div class="info-row"><div class="ik">İptal Eden</div><div class="iv">{{ l.revoked_by or '-' }}</div></div>
      <div class="info-row"><div class="ik">İptal Sebebi</div><div class="iv">{{ l.revoke_reason or '-' }}</div></div>
      {% endif %}

      <div class="info-section">Notlar</div>
      <div class="info-row"><div class="ik">Not</div><div class="iv">{{ l.notes or '-' }}</div></div>
    </div>
  </div>
</div>
<div id="uzat{{ l.id }}" class="modal" onclick="if(event.target===this)closeM('uzat{{ l.id }}')">
  <div class="modal-box">
    <div class="modal-head"><h4>Süre Uzat</h4><button class="modal-close" type="button" onclick="closeM('uzat{{ l.id }}')">&times;</button></div>
    <div class="modal-body">
      <form method="POST" action="/extend/{{ l.id }}">
        <label>Uzatma Süresi</label>
        <select name="days">
          <option value="365">+ 1 Yıl</option><option value="730">+ 2 Yıl</option>
          <option value="180">+ 6 Ay</option><option value="90">+ 90 Gün</option><option value="30">+ 30 Gün</option>
        </select>
        <div class="actions"><button class="btn btn-green" type="submit">Uzat</button></div>
      </form>
    </div>
  </div>
</div>
<div id="duz{{ l.id }}" class="modal" onclick="if(event.target===this)closeM('duz{{ l.id }}')">
  <div class="modal-box">
    <div class="modal-head"><h4>Lisansı Düzenle</h4><button class="modal-close" type="button" onclick="closeM('duz{{ l.id }}')">&times;</button></div>
    <div class="modal-body">
      <form method="POST" action="/edit/{{ l.id }}">
        <label>Müşteri Adı</label><input name="customer_name" value="{{ l.customer_name or '' }}">
        <label>E-posta</label><input name="customer_email" value="{{ l.customer_email or '' }}">
        <label>Telefon</label><input name="customer_phone" value="{{ l.customer_phone or '' }}">
        <label>Paket</label>
        <select name="package">
          <option value="starter" {{ 'selected' if l.package=='starter' else '' }}>Başlangıç</option>
          <option value="standard" {{ 'selected' if l.package=='standard' else '' }}>Standart</option>
          <option value="enterprise" {{ 'selected' if not l.package or l.package=='enterprise' else '' }}>Kurumsal</option>
        </select>
        <label>Not</label><textarea name="notes">{{ l.notes or '' }}</textarea>
        <div class="actions"><button class="btn btn-main" type="submit">Kaydet</button></div>
      </form>
    </div>
  </div>
</div>
{% if not l.is_revoked %}
<div id="ipt{{ l.id }}" class="modal" onclick="if(event.target===this)closeM('ipt{{ l.id }}')">
  <div class="modal-box">
    <div class="modal-head"><h4>Lisansı İptal Et</h4><button class="modal-close" type="button" onclick="closeM('ipt{{ l.id }}')">&times;</button></div>
    <div class="modal-body">
      <form method="POST" action="/revoke/{{ l.id }}">
        <label>İptal Sebebi</label>
        <textarea name="reason" placeholder="Ödeme yapılmadı, iptal talebi..."></textarea>
        <div class="actions"><button class="btn btn-orange" type="submit">İptal Et</button></div>
      </form>
    </div>
  </div>
</div>
{% endif %}
{% endfor %}

<div class="toast" id="toast">Kopyalandı</div>
<script>
let cf='all';
function setF(f,btn){cf=f;document.querySelectorAll('.ftab').forEach(b=>b.classList.remove('on'));btn.classList.add('on');flt();}
function flt(){const q=document.getElementById('srch').value.toLowerCase();document.querySelectorAll('tbody tr[data-s]').forEach(tr=>{const ms=cf==='all'||tr.dataset.s===cf;const mq=!q||tr.dataset.q.includes(q);tr.style.display=(ms&&mq)?'':'none';});}
function openM(id){const el=document.getElementById(id);if(el)el.classList.add('open');}
function closeM(id){const el=document.getElementById(id);if(el)el.classList.remove('open');}
function copyText(text){navigator.clipboard.writeText(text).then(()=>{const t=document.getElementById('toast');t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1800);});}
function exportLicenses(){
  const q=document.getElementById('srch') ? document.getElementById('srch').value.trim() : '';
  const params=new URLSearchParams();
  params.set('product', {{ prod_filter|tojson }});
  params.set('status',cf);
  if(q) params.set('q',q);
  window.location.href='/licenses/export?'+params.toString();
}
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.modal.open').forEach(m=>m.classList.remove('open'));});
</script>
</body></html>"""


AUDIT_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>İşlem Geçmişi | Gazi Medya Lisans Paneli</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700;900&family=Roboto+Mono:wght@500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{overflow-x:hidden;width:100%}
:root{--bg:#f5f7fb;--card:#ffffff;--line:#e5e7eb;--line2:#cbd5e1;--text:#111827;--muted:#64748b;--muted2:#94a3b8;--nav:#0f172a;--nav2:#111c33;--nav-line:#233150;--accent:#2563eb;--accent-d:#1d4ed8;--accent-bg:#eff6ff;--green:#15803d;--green-bg:#ecfdf5;--amber:#b45309;--amber-bg:#fffbeb;--red:#b91c1c;--red-bg:#fef2f2;--radius:14px;--sidebar-w:268px}
body{background:var(--bg);color:var(--text);min-height:100vh;font-family:'Roboto',Arial,sans-serif;-webkit-font-smoothing:antialiased}.shell{display:flex;min-height:100vh;min-width:0}.sidebar{width:var(--sidebar-w);flex-shrink:0;background:linear-gradient(180deg,var(--nav),var(--nav2));border-right:1px solid var(--nav-line);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}.side-brand{display:flex;align-items:center;gap:12px;padding:22px 18px 18px}.side-brand .b{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#60a5fa,#2563eb);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:900;color:#fff}.side-brand h1{font-size:14px;font-weight:900;color:#fff}.side-brand small{display:block;color:#93a4bd;font-size:11px;margin-top:2px}.side-section{padding:8px 12px 4px}.side-label{font-size:10px;font-weight:900;letter-spacing:.11em;text-transform:uppercase;color:#74849d;padding:12px 12px 8px}.nav-link{display:flex;align-items:center;justify-content:space-between;gap:8px;color:#dbeafe;text-decoration:none;font-size:12.5px;font-weight:700;padding:9px 10px;border-radius:10px;margin-bottom:3px;transition:background .12s,color .12s}.nav-link:hover{background:rgba(255,255,255,.07)}.nav-link.on{background:#fff;color:#1e3a8a}.nav-link .lbl{display:flex;align-items:center;gap:9px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}.badge{min-width:24px;height:22px;border-radius:7px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:900;color:#fff}.badge-all{background:#475569}.badge-hr{background:#2563eb}.badge-asc{background:#ea580c}.badge-ft{background:#16a34a}.badge-eta{background:#7c3aed}.badge-kkdik{background:#0891b2}.badge-etk{background:#d97706}.badge-etf{background:#dc2626}.nav-link .cnt{background:rgba(255,255,255,.10);color:#cbd5e1;font-size:10px;font-weight:900;padding:2px 7px;border-radius:999px}.nav-link.on .cnt{background:#dbeafe;color:#1d4ed8}.side-spacer{flex:1}.side-foot{padding:12px;border-top:1px solid var(--nav-line)}.side-foot a{display:flex;align-items:center;gap:8px;color:#dbeafe;text-decoration:none;font-size:12.5px;font-weight:700;padding:9px 10px;border-radius:10px}.side-foot a:hover{background:rgba(255,255,255,.07)}.main{flex:1;min-width:0;padding:28px 32px 42px;max-width:100%}.topbar{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:20px;background:#fff;border:1px solid var(--line);border-radius:18px;padding:22px 24px;box-shadow:0 10px 30px rgba(15,23,42,.04)}.topbar h2{font-size:24px;font-weight:900;letter-spacing:-.03em;margin-bottom:7px}.topbar p{color:var(--muted);font-size:13.5px;max-width:720px;line-height:1.55}.btn{border:none;border-radius:10px;padding:10px 15px;font-size:13px;font-weight:900;cursor:pointer;color:#fff;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:7px;transition:filter .12s,transform .12s;white-space:nowrap}.btn:hover{filter:brightness(.95)}.btn:active{transform:translateY(1px)}.btn-main{background:var(--accent)}.btn-muted{background:#475569}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:18px}.stat{background:#fff;border:1px solid var(--line);border-radius:16px;padding:17px 18px;min-width:0;box-shadow:0 10px 30px rgba(15,23,42,.035)}.stat .k{color:var(--muted);font-size:11px;margin-bottom:9px;font-weight:900;text-transform:uppercase;letter-spacing:.05em}.stat .v{font-size:28px;font-weight:900;letter-spacing:-.03em}.card{background:var(--card);border:1px solid var(--line);border-radius:18px;overflow:hidden;min-width:0;box-shadow:0 10px 30px rgba(15,23,42,.04)}.card-head{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:12px}.card-head h3{font-size:15px;font-weight:900}.note{font-size:12px;color:var(--muted)}.filters{display:grid;grid-template-columns:2fr 1fr 1fr 1fr auto;gap:10px;padding:16px 20px;border-bottom:1px solid var(--line);align-items:end}label{display:block;font-size:11.5px;font-weight:900;color:#334155;margin-bottom:6px}input,select{width:100%;background:#fff;border:1.5px solid #cbd5e1;color:var(--text);border-radius:10px;padding:10px 12px;font-size:13px;outline:none;font-family:inherit}input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 4px rgba(37,99,235,.12)}.table-wrap{overflow-x:auto;max-width:100%}table{width:100%;border-collapse:collapse;table-layout:auto}th,td{padding:12px 14px;border-bottom:1px solid var(--line);text-align:left;font-size:12px;vertical-align:top}th{color:var(--muted);font-size:10px;letter-spacing:.06em;text-transform:uppercase;font-weight:900;background:#f8fafc;white-space:nowrap}tbody tr:hover td{background:#f8fafc}.mono{font-family:'Roboto Mono',ui-monospace,Consolas,monospace;font-size:11px}.detail{max-width:420px;line-height:1.45;color:#334155}.path{max-width:220px;word-break:break-word;color:#475569}.ua{max-width:280px;word-break:break-word;color:#64748b;font-size:11px}.pill{display:inline-flex;align-items:center;gap:6px;padding:5px 9px;border-radius:999px;font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}.pill::before{content:"";width:6px;height:6px;border-radius:50%;flex-shrink:0}.p-green{background:var(--green-bg);color:var(--green)}.p-green::before{background:var(--green)}.p-amber{background:var(--amber-bg);color:var(--amber)}.p-amber::before{background:var(--amber)}.p-red{background:var(--red-bg);color:var(--red)}.p-red::before{background:var(--red)}.p-blue{background:var(--accent-bg);color:var(--accent-d)}.p-blue::before{background:var(--accent)}.pagination{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:16px 20px}.pagination .page-text{font-size:12.5px;color:var(--muted);font-weight:700}.pagination .pager{display:flex;gap:8px}.empty{padding:36px;color:var(--muted);text-align:center}@media(max-width:1180px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.filters{grid-template-columns:1fr 1fr}}@media(max-width:980px){.sidebar{display:none}.main{padding:20px}}@media(max-width:700px){.main{padding:14px}.stats{grid-template-columns:1fr}.filters{grid-template-columns:1fr}.topbar{padding:18px}.btn{width:100%}.topbar>div:last-child{width:100%}}
</style></head>
<body>
<div class="shell">
  <aside class="sidebar">
    <div class="side-brand"><div class="b">GM</div><div><h1>Gazi Medya</h1><small>Lisans Paneli</small></div></div>
    <div class="side-section">
      <div class="side-label">Ürünler</div>
      <a href="/?product=all" class="nav-link"><span class="lbl"><span class="badge badge-all">TÜM</span>Tümü</span><span class="cnt">{{ stats.total }}</span></a>
      <a href="/?product=gazi-hr" class="nav-link"><span class="lbl"><span class="badge badge-hr">HR</span>Gazi HR</span><span class="cnt">{{ stats.hr_count }}</span></a>
      <a href="/?product=autoservis-crm" class="nav-link"><span class="lbl"><span class="badge badge-asc">AS</span>AutoServis</span><span class="cnt">{{ stats.asc_count }}</span></a>
      <a href="/?product=fiyat-teklifi" class="nav-link"><span class="lbl"><span class="badge badge-ft">FT</span>Fiyat Teklifi</span><span class="cnt">{{ stats.ft_count }}</span></a>
      <a href="/?product=eta-analitik" class="nav-link"><span class="lbl"><span class="badge badge-eta">EA</span>ETA Analitik</span><span class="cnt">{{ stats.eta_count }}</span></a>
      <a href="/?product=kkdik" class="nav-link"><span class="lbl"><span class="badge badge-kkdik">KK</span>KKDİK Suite</span><span class="cnt">{{ stats.kkdik_count }}</span></a>
      <a href="/?product=etanom-teklif" class="nav-link"><span class="lbl"><span class="badge badge-etk">ET</span>Etanom Teklif</span><span class="cnt">{{ stats.etanom_count }}</span></a>
      <a href="/?product=etanom-fatura" class="nav-link"><span class="lbl"><span class="badge badge-etf">EF</span>Etanom Fatura</span><span class="cnt">{{ stats.fatura_count }}</span></a>
    </div>
    <div class="side-section">
      <div class="side-label">Yönetim</div>
      <a href="/audit-log" class="nav-link on"><span class="lbl"><span class="badge badge-all">LOG</span>İşlem Geçmişi</span></a>
    </div>
    <div class="side-spacer"></div>
    <div class="side-foot"><a href="/change-password">Şifre Değiştir</a><a href="/logout">Çıkış Yap</a></div>
  </aside>

  <main class="main">
    <div class="topbar">
      <div>
        <h2>İşlem Geçmişi</h2>
        <p>Panel üzerinde yapılan giriş, lisans oluşturma, düzenleme, süre uzatma, iptal, silme ve şifre işlemlerini detaylı şekilde takip edin.</p>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <a class="btn btn-muted" href="/">Panele Dön</a>
        <a class="btn btn-main" href="/audit-log/export?q={{ filters.q }}&action={{ filters.action }}&date_from={{ filters.date_from }}&date_to={{ filters.date_to }}">CSV Dışa Aktar</a>
      </div>
    </div>

    <div class="stats">
      <div class="stat"><div class="k">Toplam Kayıt</div><div class="v">{{ audit_stats.total }}</div></div>
      <div class="stat"><div class="k">Bugünkü İşlem</div><div class="v">{{ audit_stats.today }}</div></div>
      <div class="stat"><div class="k">Lisans İşlemi</div><div class="v">{{ audit_stats.license_ops }}</div></div>
      <div class="stat"><div class="k">Başarısız Giriş</div><div class="v">{{ audit_stats.failed_login }}</div></div>
    </div>

    <div class="card">
      <div class="card-head"><h3>Detaylı Kayıtlar</h3><div class="note">{{ total_filtered }} kayıt eşleşti</div></div>
      <form class="filters" method="GET" action="/audit-log">
        <div><label>Arama</label><input name="q" value="{{ filters.q }}" placeholder="İşlem, detay, kullanıcı, IP veya yol ara..."></div>
        <div><label>İşlem Tipi</label><select name="action"><option value="all">Tüm İşlemler</option>{% for a in actions %}<option value="{{ a.action }}" {{ 'selected' if filters.action==a.action else '' }}>{{ a.action }}</option>{% endfor %}</select></div>
        <div><label>Başlangıç</label><input type="date" name="date_from" value="{{ filters.date_from }}"></div>
        <div><label>Bitiş</label><input type="date" name="date_to" value="{{ filters.date_to }}"></div>
        <div><button class="btn btn-main" type="submit">Filtrele</button></div>
      </form>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>Tarih</th><th>İşlem</th><th>Detay</th><th>Kullanıcı</th><th>IP</th><th>Metot</th><th>Yol</th><th>Tarayıcı</th></tr></thead>
          <tbody>
            {% for lg in logs %}
            <tr>
              <td class="mono">#{{ lg.id }}</td>
              <td class="mono">{{ lg.created_at }}</td>
              <td>
                {% if 'BAŞARISIZ' in (lg.action or '') %}<span class="pill p-red">{{ lg.action }}</span>
                {% elif 'GİRİŞ' in (lg.action or '') or 'ÇIKIŞ' in (lg.action or '') %}<span class="pill p-blue">{{ lg.action }}</span>
                {% elif 'LİSANS' in (lg.action or '') %}<span class="pill p-green">{{ lg.action }}</span>
                {% else %}<span class="pill p-amber">{{ lg.action or '-' }}</span>{% endif %}
              </td>
              <td class="detail">{{ lg.detail or '-' }}</td>
              <td>{{ lg.username or '-' }}</td>
              <td class="mono">{{ lg.ip_address or '-' }}</td>
              <td class="mono">{{ lg.method or '-' }}</td>
              <td class="path">{{ lg.path or '-' }}</td>
              <td class="ua">{{ lg.user_agent or '-' }}</td>
            </tr>
            {% else %}
            <tr><td colspan="9" class="empty">Seçili filtrelerle eşleşen işlem kaydı bulunamadı.</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      <div class="pagination">
        <div class="page-text">Sayfa {{ page }} / {{ pages }} · Sayfa başına {{ per_page }} kayıt</div>
        <div class="pager">
          {% if page > 1 %}<a class="btn btn-muted" href="/audit-log?q={{ filters.q }}&action={{ filters.action }}&date_from={{ filters.date_from }}&date_to={{ filters.date_to }}&page={{ page-1 }}&per_page={{ per_page }}">Önceki</a>{% endif %}
          {% if page < pages %}<a class="btn btn-main" href="/audit-log?q={{ filters.q }}&action={{ filters.action }}&date_from={{ filters.date_from }}&date_to={{ filters.date_to }}&page={{ page+1 }}&per_page={{ per_page }}">Sonraki</a>{% endif %}
        </div>
      </div>
    </div>
  </main>
</div>
</body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"Gazi Medya Lisans Paneli basliyor - port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
