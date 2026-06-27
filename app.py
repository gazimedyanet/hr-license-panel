from flask import Flask, request, jsonify, render_template_string, redirect, session
import sqlite3
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


def log(action, detail=""):
    conn = get_db()
    conn.execute("INSERT INTO audit_log (action,detail) VALUES (?,?)", (action, detail))
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
    return render_template_string(PANEL_HTML, licenses=licenses, stats=stats,
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
    existing = conn.execute("SELECT id FROM licenses WHERE hw_id=? AND product=?", (hw_id, product)).fetchone()
    if existing:
        conn.close()
        return "<script>alert('Bu HW ID ve ürün için zaten lisans var.');history.back()</script>"
    key = gen_key(hw_id, expires, product)
    try:
        conn.execute(
            "INSERT INTO licenses (license_key,hw_id,product,customer_name,customer_email,customer_phone,expires_at,notes,package) VALUES(?,?,?,?,?,?,?,?,?)",
            (key, hw_id, product, customer, email, phone, expires, notes, package),
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
        conn.execute("UPDATE licenses SET license_key=?, expires_at=?, is_revoked=0, revoke_reason=NULL WHERE id=?",
                     (new_key, new_exp.isoformat(), lid))
        conn.commit()
        log("LİSANS UZATILDI", f"ID:{lid} | {lic['customer_name'] or '-'} | +{days} gün | {new_exp.strftime('%d.%m.%Y')}")
    conn.close()
    return redirect("/")


@app.route("/revoke/<int:lid>", methods=["POST"])
@auth
def revoke(lid):
    reason = request.form.get("reason","").strip()
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    conn.execute("UPDATE licenses SET is_revoked=1, revoke_reason=? WHERE id=?", (reason, lid))
    conn.commit()
    conn.close()
    log("LİSANS İPTAL", f"ID:{lid} | {lic['customer_name'] if lic else ''} | {reason or 'Sebep yok'}")
    return redirect("/")


@app.route("/restore/<int:lid>", methods=["POST"])
@auth
def restore(lid):
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    conn.execute("UPDATE licenses SET is_revoked=0, revoke_reason=NULL WHERE id=?", (lid,))
    conn.commit()
    conn.close()
    log("LİSANS AKTİFLEŞTİRİLDİ", f"ID:{lid} | {lic['customer_name'] if lic else ''}")
    return redirect("/")


@app.route("/edit/<int:lid>", methods=["POST"])
@auth
def edit(lid):
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    if lic:
        pkg = request.form.get("package","enterprise").strip()
        conn.execute(
            "UPDATE licenses SET customer_name=?, customer_email=?, customer_phone=?, notes=?, package=? WHERE id=?",
            (request.form.get("customer_name","").strip(), request.form.get("customer_email","").strip(),
             request.form.get("customer_phone","").strip(), request.form.get("notes","").strip(), pkg, lid),
        )
        conn.commit()
        log("LİSANS DÜZENLENDİ", f"ID:{lid} | Paket:{pkg}")
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
<title>Gazi Medya - Giriş</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#07111f;--panel:#0f1b2d;--line:#223552;--text:#e8eef8;--muted:#8ea2bf;--blue:#3b82f6;--cyan:#06b6d4;--danger:#ef4444}
body{min-height:100vh;background:radial-gradient(circle at top left,rgba(59,130,246,.20),transparent 30%),radial-gradient(circle at bottom right,rgba(6,182,212,.14),transparent 28%),linear-gradient(160deg,#07111f 0%,#0b1526 100%);font-family:Segoe UI,system-ui,sans-serif;color:var(--text);display:flex;align-items:center;justify-content:center;padding:24px}
.shell{width:100%;max-width:420px;background:rgba(15,27,45,.9);backdrop-filter:blur(18px);border:1px solid rgba(255,255,255,.08);border-radius:24px;padding:34px 30px 28px;box-shadow:0 24px 80px rgba(0,0,0,.45)}
.logo{width:64px;height:64px;border-radius:18px;background:linear-gradient(135deg,var(--blue),var(--cyan));display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 18px;box-shadow:0 16px 40px rgba(59,130,246,.35)}
h1{text-align:center;font-size:24px;font-weight:800;margin-bottom:6px}
.sub{text-align:center;color:var(--muted);font-size:13px;margin-bottom:28px}
.err{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.28);color:#fecaca;border-radius:12px;padding:12px 14px;margin-bottom:16px;font-size:13px}
label{display:block;font-size:11px;font-weight:700;letter-spacing:.12em;color:var(--muted);margin-bottom:8px;text-transform:uppercase}
input{width:100%;background:rgba(255,255,255,.04);border:1px solid var(--line);color:var(--text);border-radius:14px;padding:14px 16px;font-size:14px;outline:none;margin-bottom:16px}
input:focus{border-color:var(--blue);box-shadow:0 0 0 4px rgba(59,130,246,.14)}
button{width:100%;border:none;border-radius:14px;padding:14px 16px;background:linear-gradient(135deg,var(--blue),#2563eb);color:#fff;font-size:14px;font-weight:700;cursor:pointer}
</style></head>
<body>
<div class="shell">
  <div class="logo">🔐</div>
  <h1>Gazi Medya</h1>
  <div class="sub">Lisans Yönetim Paneli</div>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="POST">
    <label>Kullanıcı Adı</label><input name="username" autocomplete="username" required autofocus>
    <label>Şifre</label><input name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Giriş Yap</button>
  </form>
</div>
</body></html>"""

CHANGE_PASS_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Şifre Değiştir</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#07111f;--nav:#0c1627;--panel:#0f1b2d;--line:#223552;--text:#e8eef8;--muted:#8ea2bf;--blue:#3b82f6;--ok:#10b981;--danger:#ef4444}
body{min-height:100vh;background:radial-gradient(circle at top left,rgba(59,130,246,.16),transparent 28%),linear-gradient(160deg,#07111f 0%,#0b1526 100%);color:var(--text);font-family:Segoe UI,system-ui,sans-serif}
nav{height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 28px;background:rgba(12,22,39,.86);border-bottom:1px solid rgba(255,255,255,.06);backdrop-filter:blur(14px)}
.brand{font-weight:800}
.nav-links a{color:var(--muted);text-decoration:none;margin-left:14px;font-size:13px}
.wrap{max-width:560px;margin:40px auto;padding:0 20px}
.card{background:rgba(15,27,45,.9);border:1px solid rgba(255,255,255,.08);border-radius:24px;padding:28px;box-shadow:0 24px 80px rgba(0,0,0,.35)}
h1{font-size:26px;margin-bottom:8px}
.sub{color:var(--muted);font-size:13px;margin-bottom:24px}
.ok{padding:12px 14px;border-radius:12px;margin-bottom:16px;font-size:13px;background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.28);color:#bbf7d0}
.er{padding:12px 14px;border-radius:12px;margin-bottom:16px;font-size:13px;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.28);color:#fecaca}
label{display:block;font-size:11px;font-weight:700;letter-spacing:.12em;color:var(--muted);margin-bottom:8px;text-transform:uppercase}
input{width:100%;background:rgba(255,255,255,.04);border:1px solid var(--line);color:var(--text);border-radius:14px;padding:14px 16px;font-size:14px;outline:none;margin-bottom:16px}
button{width:100%;border:none;border-radius:14px;padding:14px 16px;background:linear-gradient(135deg,var(--blue),#2563eb);color:#fff;font-size:14px;font-weight:700;cursor:pointer}
</style></head>
<body>
<nav>
  <div class="brand">Gazi Medya</div>
  <div class="nav-links"><a href="/">Panele Dön</a><a href="/logout">Çıkış</a></div>
</nav>
<div class="wrap"><div class="card">
  <h1>Şifre Değiştir</h1>
  <div class="sub">Panel giriş şifrenizi güvenli şekilde güncelleyin.</div>
  {% if msg %}<div class="ok">{{ msg }}</div>{% endif %}
  {% if err %}<div class="er">{{ err }}</div>{% endif %}
  <form method="POST">
    <label>Mevcut Şifre</label><input type="password" name="current" required>
    <label>Yeni Şifre</label><input type="password" name="new_pass" required minlength="8">
    <label>Yeni Şifre Tekrar</label><input type="password" name="confirm" required>
    <button type="submit">Şifreyi Güncelle</button>
  </form>
</div></div>
</body></html>"""

PANEL_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gazi Medya Lisans Paneli</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#07111f;--bg2:#0b1526;--panel:#0f1b2d;--panel2:#13233a;--line:#223552;--line2:#314764;--text:#e8eef8;--muted:#8ea2bf;--blue:#3b82f6;--cyan:#06b6d4;--green:#10b981;--amber:#f59e0b;--red:#ef4444;--orange:#f97316;--purple:#8b5cf6}
body{background:radial-gradient(circle at top left,rgba(59,130,246,.16),transparent 22%),radial-gradient(circle at bottom right,rgba(6,182,212,.10),transparent 22%),linear-gradient(160deg,var(--bg) 0%,var(--bg2) 100%);color:var(--text);min-height:100vh;font-family:Segoe UI,system-ui,sans-serif}
nav{height:70px;display:flex;align-items:center;justify-content:space-between;padding:0 28px;background:rgba(12,22,39,.86);border-bottom:1px solid rgba(255,255,255,.06);backdrop-filter:blur(14px);position:sticky;top:0;z-index:50}
.brand{display:flex;align-items:center;gap:12px}
.brand-badge{width:36px;height:36px;border-radius:12px;background:linear-gradient(135deg,var(--blue),var(--cyan));display:flex;align-items:center;justify-content:center;box-shadow:0 10px 28px rgba(59,130,246,.28)}
.brand h1{font-size:16px;font-weight:800}
.brand small{display:block;color:var(--muted);font-size:11px;margin-top:2px}
.nav-links a{color:var(--muted);text-decoration:none;margin-left:14px;font-size:13px}
.wrap{max-width:1480px;margin:0 auto;padding:28px}
.hero{background:linear-gradient(135deg,#132742 0%,#18345a 55%,#0f2d49 100%);border:1px solid rgba(255,255,255,.08);border-radius:26px;padding:24px;margin-bottom:20px;box-shadow:0 24px 80px rgba(0,0,0,.28)}
.hero-top{display:flex;justify-content:space-between;gap:18px;flex-wrap:wrap;align-items:flex-start}
.hero h2{font-size:28px;font-weight:800;margin-bottom:8px}
.hero p{color:#c8d7ec;max-width:760px;line-height:1.6;font-size:14px}
.hero-meta{display:grid;grid-template-columns:repeat(2,minmax(140px,1fr));gap:12px;min-width:320px}
.meta-box{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:14px}
.meta-box .k{font-size:10px;color:#b7c7df;letter-spacing:.12em;font-weight:700;margin-bottom:6px;text-transform:uppercase}
.meta-box .v{font-size:18px;font-weight:800}
.tabs{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0 18px}
.tab{padding:10px 16px;border-radius:999px;text-decoration:none;border:1px solid var(--line);color:var(--muted);background:rgba(255,255,255,.03);font-size:13px;font-weight:700}
.tab.on{color:#fff;border-color:rgba(255,255,255,.18);background:rgba(59,130,246,.18)}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:20px}
.stat{background:rgba(15,27,45,.88);border:1px solid rgba(255,255,255,.06);border-radius:20px;padding:18px 20px}
.stat .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.12em;margin-bottom:8px;font-weight:700}
.stat .v{font-size:32px;font-weight:800;line-height:1}
.grid{display:grid;grid-template-columns:1.08fr .92fr;gap:18px;align-items:start}
.card{background:rgba(15,27,45,.9);border:1px solid rgba(255,255,255,.07);border-radius:22px;overflow:hidden;box-shadow:0 18px 50px rgba(0,0,0,.22)}
.card-head{padding:18px 20px;border-bottom:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.02);display:flex;justify-content:space-between;align-items:center;gap:12px}
.card-head h3{font-size:14px;font-weight:800;letter-spacing:.04em}
.card-body{padding:20px}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.full{grid-column:1/-1}
label{display:block;font-size:11px;font-weight:700;letter-spacing:.12em;color:var(--muted);margin-bottom:8px;text-transform:uppercase}
input,select,textarea{width:100%;background:#0f1b2d;border:1px solid var(--line);color:var(--text);border-radius:14px;padding:13px 14px;font-size:14px;outline:none;font-family:inherit}
select,option{background:#0f1b2d;color:var(--text)}
textarea{min-height:90px;resize:vertical}
input:focus,select:focus,textarea:focus{border-color:var(--blue);box-shadow:0 0 0 4px rgba(59,130,246,.14)}
.actions{margin-top:16px;display:flex;justify-content:flex-end}
.btn{border:none;border-radius:14px;padding:11px 16px;font-size:12px;font-weight:800;cursor:pointer;color:#fff;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px}
.btn-main{background:linear-gradient(135deg,var(--blue),#2563eb)}
.btn-green{background:linear-gradient(135deg,#10b981,#059669)}
.btn-orange{background:linear-gradient(135deg,#f59e0b,#d97706)}
.btn-red{background:linear-gradient(135deg,#ef4444,#dc2626)}
.btn-muted{background:linear-gradient(135deg,#475569,#334155)}
.btn-xs{padding:8px 10px;font-size:11px;border-radius:10px}
.table-wrap{overflow:auto}
.toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:16px 20px;border-bottom:1px solid rgba(255,255,255,.06)}
.search{min-width:280px;flex:1;background:#0f1b2d;border:1px solid var(--line);border-radius:14px;color:var(--text);padding:12px 14px;font-size:13px}
.filter-tabs{display:flex;gap:8px;flex-wrap:wrap}
.ftab{border:1px solid var(--line);background:rgba(255,255,255,.03);color:var(--muted);border-radius:999px;padding:9px 12px;font-size:12px;font-weight:700;cursor:pointer}
.ftab.on{color:#fff;background:rgba(59,130,246,.18)}
table{width:100%;border-collapse:collapse}
th,td{padding:12px 14px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left;font-size:13px;white-space:nowrap;vertical-align:top}
th{color:var(--muted);font-size:11px;letter-spacing:.1em;text-transform:uppercase;font-weight:800}
tr:hover td{background:rgba(255,255,255,.02)}
.kbox{display:inline-flex;align-items:center;gap:6px;max-width:220px;overflow:hidden;text-overflow:ellipsis;padding:7px 10px;border-radius:10px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);font-family:ui-monospace,Consolas,monospace;cursor:pointer;font-size:12px}
.pill{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:999px;font-size:11px;font-weight:800}
.green{background:rgba(16,185,129,.16);color:#86efac}
.amber{background:rgba(245,158,11,.16);color:#fcd34d}
.red{background:rgba(239,68,68,.16);color:#fca5a5}
.blue{background:rgba(59,130,246,.16);color:#93c5fd}
.orange{background:rgba(249,115,22,.16);color:#fdba74}
.purple{background:rgba(139,92,246,.16);color:#c4b5fd}
.cyan{background:rgba(6,182,212,.16);color:#67e8f9}
.yellow{background:rgba(245,158,11,.16);color:#fde68a}
.actions-row{display:flex;gap:6px;flex-wrap:wrap}
.log{display:flex;flex-direction:column;gap:10px}
.log-item{padding:12px 14px;border-radius:14px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.05)}
.log-item strong{display:block;margin-bottom:4px}
.log-item small{color:var(--muted)}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;align-items:center;justify-content:center;z-index:999;padding:16px}
.modal.open{display:flex}
.modal-box{width:100%;max-width:460px;background:#101c2f;border:1px solid rgba(255,255,255,.08);border-radius:22px;box-shadow:0 24px 80px rgba(0,0,0,.5);overflow:hidden}
.modal-head{padding:18px 20px;border-bottom:1px solid rgba(255,255,255,.06);display:flex;align-items:center;justify-content:space-between}
.modal-head h4{font-size:15px;font-weight:800}
.modal-close{border:none;background:none;color:var(--muted);font-size:22px;cursor:pointer}
.modal-body{padding:20px}
.toast{position:fixed;right:18px;bottom:18px;z-index:1200;background:rgba(16,185,129,.95);color:#fff;padding:10px 14px;border-radius:12px;opacity:0;transform:translateY(10px);transition:.25s;pointer-events:none}
.toast.show{opacity:1;transform:translateY(0)}
.note{font-size:12px;color:var(--muted);line-height:1.6}
@media(max-width:1120px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}}
@media(max-width:740px){.wrap{padding:18px}.stats{grid-template-columns:1fr}.form-grid{grid-template-columns:1fr}}
</style></head>
<body>
<nav>
  <div class="brand">
    <div class="brand-badge">🔐</div>
    <div><h1>Gazi Medya</h1><small>Lisans Yönetim Paneli</small></div>
  </div>
  <div class="nav-links">
    <a href="/change-password">Şifre Değiştir</a>
    <a href="/logout">Çıkış</a>
  </div>
</nav>
<div class="wrap">
  <div class="hero">
    <div class="hero-top">
      <div>
        <h2>Lisansları tek panelden yönet</h2>
        <p>Gazi HR, AutoServis CRM, Fiyat Teklifi, ETA Analitik, KKDİK Suite, Etanom Teklif ve Etanom Fatura (İhracat) lisanslarını oluşturun, uzatın, iptal edin ve müşteri bazlı takip edin.</p>
      </div>
      <div class="hero-meta">
        <div class="meta-box"><div class="k">Toplam Lisans</div><div class="v">{{ stats.total }}</div></div>
        <div class="meta-box"><div class="k">Aktif</div><div class="v">{{ stats.active }}</div></div>
        <div class="meta-box"><div class="k">30 Gün İçinde</div><div class="v">{{ stats.expiring }}</div></div>
        <div class="meta-box"><div class="k">İptal</div><div class="v">{{ stats.revoked }}</div></div>
      </div>
    </div>
  </div>

  <div class="tabs">
    <a href="/?product=all"            class="tab {{ 'on' if prod_filter=='all' else '' }}">Tümü ({{ stats.total }})</a>
    <a href="/?product=gazi-hr"        class="tab {{ 'on' if prod_filter=='gazi-hr' else '' }}">👥 Gazi HR ({{ stats.hr_count }})</a>
    <a href="/?product=autoservis-crm" class="tab {{ 'on' if prod_filter=='autoservis-crm' else '' }}">🔧 AutoServis ({{ stats.asc_count }})</a>
    <a href="/?product=fiyat-teklifi"  class="tab {{ 'on' if prod_filter=='fiyat-teklifi' else '' }}">📊 Fiyat Teklifi ({{ stats.ft_count }})</a>
    <a href="/?product=eta-analitik"   class="tab {{ 'on' if prod_filter=='eta-analitik' else '' }}">🚢 ETA Analitik ({{ stats.eta_count }})</a>
    <a href="/?product=kkdik"          class="tab {{ 'on' if prod_filter=='kkdik' else '' }}">⚗️ KKDİK Suite ({{ stats.kkdik_count }})</a>
    <a href="/?product=etanom-teklif"  class="tab {{ 'on' if prod_filter=='etanom-teklif' else '' }}">📄 Etanom Teklif ({{ stats.etanom_count }})</a>
    <a href="/?product=etanom-fatura"  class="tab {{ 'on' if prod_filter=='etanom-fatura' else '' }}">🧾 Etanom Fatura ({{ stats.fatura_count }})</a>
  </div>

  <div class="stats">
    <div class="stat"><div class="k">Toplam</div><div class="v">{{ stats.total }}</div></div>
    <div class="stat"><div class="k">Aktif</div><div class="v">{{ stats.active }}</div></div>
    <div class="stat"><div class="k">Dolmuş</div><div class="v">{{ stats.expired }}</div></div>
    <div class="stat"><div class="k">İptal</div><div class="v">{{ stats.revoked }}</div></div>
    <div class="stat"><div class="k">Yaklaşan</div><div class="v">{{ stats.expiring }}</div></div>
  </div>

  <div class="grid">
    <div>
      <div class="card">
        <div class="card-head"><h3>Yeni Lisans Oluştur</h3></div>
        <div class="card-body">
          <form method="POST" action="/create">
            <div class="form-grid">
              <div>
                <label>Ürün</label>
                <select name="product">
                  <option value="gazi-hr">👥 Gazi HR</option>
                  <option value="autoservis-crm">🔧 AutoServis CRM</option>
                  <option value="fiyat-teklifi">📊 Fiyat Teklifi</option>
                  <option value="eta-analitik">🚢 ETA Analitik ERP</option>
                  <option value="kkdik">⚗️ KKDİK Suite</option>
                  <option value="etanom-teklif">📄 Etanom Teklif</option>
                  <option value="etanom-fatura">🧾 Etanom Fatura (İhracat)</option>
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
              <button class="btn btn-main" type="submit">Lisans Oluştur</button>
            </div>
          </form>
        </div>
      </div>

      <div class="card" style="margin-top:18px">
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
          </div>
        </div>
        <div class="card-body table-wrap" style="padding:0">
          <table>
            <thead>
              <tr>
                <th>ID</th><th>Ürün</th><th>Müşteri</th><th>Paket</th>
                <th>Lisans Anahtarı</th><th>HW ID</th>
                <th>Son Geçerlilik</th><th>Son Görülme</th><th>Kullanım</th>
                <th>Durum</th><th>İşlemler</th>
              </tr>
            </thead>
            <tbody>
              {% for l in licenses %}
              {% set is_exp = l.expires_at < now %}
              {% set status = 'revoked' if l.is_revoked else ('expired' if is_exp else 'active') %}
              {% set prod = l.product or 'gazi-hr' %}
              <tr data-s="{{ status }}" data-q="{{ ((l.customer_name or '')~' '~(l.customer_email or '')~' '~l.license_key~' '~l.hw_id)|lower }}">
                <td>{{ l.id }}</td>
                <td>
                  {% if prod=='autoservis-crm' %}<span class="pill orange">🔧 AutoServis</span>
                  {% elif prod=='fiyat-teklifi' %}<span class="pill green">📊 Fiyat Teklifi</span>
                  {% elif prod=='eta-analitik' %}<span class="pill purple">🚢 ETA Analitik</span>
                  {% elif prod=='kkdik' %}<span class="pill cyan">⚗️ KKDİK Suite</span>
                  {% elif prod=='etanom-teklif' %}<span class="pill yellow">📄 Etanom Teklif</span>
                  {% elif prod=='etanom-fatura' %}<span class="pill red">🧾 Etanom Fatura</span>
                  {% else %}<span class="pill blue">👥 Gazi HR</span>{% endif %}
                </td>
                <td>
                  <div style="font-weight:700">{{ l.customer_name or '-' }}</div>
                  {% if l.customer_email %}<div style="font-size:11px;color:var(--muted)">{{ l.customer_email }}</div>{% endif %}
                </td>
                <td>
                  {% if l.package=='starter' %}<span class="pill blue">Başlangıç</span>
                  {% elif l.package=='standard' %}<span class="pill purple">Standart</span>
                  {% else %}<span class="pill amber">Kurumsal</span>{% endif %}
                </td>
                <td><span class="kbox" onclick="copyText('{{ l.license_key }}')">{{ l.license_key }}</span></td>
                <td><span class="kbox" onclick="copyText('{{ l.hw_id }}')">{{ l.hw_id }}</span></td>
                <td>{{ l.expires_at[:10] }}</td>
                <td>
                  {% if l.last_seen %}{{ l.last_seen[:10] }}<br><span style="color:var(--muted);font-size:11px">{{ l.last_seen[11:16] }}</span>
                  {% else %}<span style="color:var(--muted)">Henüz yok</span>{% endif %}
                </td>
                <td>{{ l.verify_count or 0 }}</td>
                <td>
                  {% if l.is_revoked %}<span class="pill red">İptal</span>
                  {% elif is_exp %}<span class="pill amber">Dolmuş</span>
                  {% else %}<span class="pill green">Aktif</span>{% endif %}
                </td>
                <td>
                  <div class="actions-row">
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
              <tr><td colspan="11" style="padding:32px;color:var(--muted)">Henüz lisans kaydı yok.</td></tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div>
      <div class="card">
        <div class="card-head"><h3>Son İşlemler</h3></div>
        <div class="card-body">
          <div class="log">
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
      </div>
    </div>
  </div>
</div>

{% for l in licenses %}
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
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.modal.open').forEach(m=>m.classList.remove('open'));});
</script>
</body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"Gazi Medya Lisans Paneli basliyor - port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
