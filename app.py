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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f5f6f8;--card:#ffffff;--line:#e4e7ec;--text:#101828;--muted:#667085;--accent:#4338ca;--accent2:#4f46e5;--danger:#b42318;--danger-bg:#fef3f2}
body{min-height:100vh;background:var(--bg);font-family:'Inter',Segoe UI,system-ui,sans-serif;color:var(--text);display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:380px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:36px 32px;box-shadow:0 1px 3px rgba(16,24,40,.04),0 8px 24px rgba(16,24,40,.06)}
.logo{width:44px;height:44px;border-radius:11px;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:20px}
h1{font-size:20px;font-weight:700;letter-spacing:-.01em;margin-bottom:4px}
.sub{color:var(--muted);font-size:13.5px;margin-bottom:26px}
.err{background:var(--danger-bg);border:1px solid #fda29b;color:var(--danger);border-radius:10px;padding:11px 13px;margin-bottom:18px;font-size:13px;font-weight:500}
label{display:block;font-size:13px;font-weight:600;color:#344054;margin-bottom:6px}
.field{margin-bottom:16px}
input{width:100%;background:#fff;border:1px solid #d0d5dd;color:var(--text);border-radius:9px;padding:10px 13px;font-size:14px;outline:none;font-family:inherit;transition:border-color .12s,box-shadow .12s}
input:focus{border-color:var(--accent2);box-shadow:0 0 0 4px rgba(79,70,229,.12)}
button{width:100%;border:none;border-radius:9px;padding:11px 16px;margin-top:8px;background:var(--accent);color:#fff;font-size:14px;font-weight:600;cursor:pointer;transition:background .12s}
button:hover{background:var(--accent2)}
.foot{text-align:center;color:#98a2b3;font-size:11.5px;margin-top:22px}
</style></head>
<body>
<div class="card">
  <div class="logo">🔐</div>
  <h1>Gazi Medya</h1>
  <div class="sub">Lisans yönetim paneline giriş yapın</div>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="POST">
    <div class="field"><label>Kullanıcı Adı</label><input name="username" autocomplete="username" required autofocus></div>
    <div class="field"><label>Şifre</label><input name="password" type="password" autocomplete="current-password" required></div>
    <button type="submit">Giriş Yap</button>
  </form>
  <div class="foot">Gazi Medya Yazılım · Lisans Yönetim Sistemi</div>
</div>
</body></html>"""

CHANGE_PASS_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Şifre Değiştir</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f5f6f8;--card:#ffffff;--line:#e4e7ec;--text:#101828;--muted:#667085;--accent:#4338ca;--accent2:#4f46e5;--ok:#067647;--ok-bg:#ecfdf3;--danger:#b42318;--danger-bg:#fef3f2}
body{min-height:100vh;background:var(--bg);font-family:'Inter',Segoe UI,system-ui,sans-serif;color:var(--text)}
nav{height:60px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;background:#fff;border-bottom:1px solid var(--line)}
.brand{font-weight:700;font-size:14.5px;display:flex;align-items:center;gap:9px}
.brand::before{content:"🔐"}
.nav-links a{color:var(--muted);text-decoration:none;margin-left:18px;font-size:13.5px;font-weight:600}
.nav-links a:hover{color:var(--text)}
.wrap{max-width:480px;margin:56px auto;padding:0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:30px;box-shadow:0 1px 3px rgba(16,24,40,.04),0 8px 24px rgba(16,24,40,.06)}
h1{font-size:19px;font-weight:700;letter-spacing:-.01em;margin-bottom:5px}
.sub{color:var(--muted);font-size:13.5px;margin-bottom:24px}
.ok{padding:11px 13px;border-radius:10px;margin-bottom:18px;font-size:13px;font-weight:500;background:var(--ok-bg);border:1px solid #abefc6;color:var(--ok)}
.er{padding:11px 13px;border-radius:10px;margin-bottom:18px;font-size:13px;font-weight:500;background:var(--danger-bg);border:1px solid #fda29b;color:var(--danger)}
label{display:block;font-size:13px;font-weight:600;color:#344054;margin-bottom:6px}
.field{margin-bottom:16px}
input{width:100%;background:#fff;border:1px solid #d0d5dd;color:var(--text);border-radius:9px;padding:10px 13px;font-size:14px;outline:none;font-family:inherit;transition:border-color .12s,box-shadow .12s}
input:focus{border-color:var(--accent2);box-shadow:0 0 0 4px rgba(79,70,229,.12)}
button{width:100%;border:none;border-radius:9px;padding:11px 16px;margin-top:6px;background:var(--accent);color:#fff;font-size:14px;font-weight:600;cursor:pointer;transition:background .12s}
button:hover{background:var(--accent2)}
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
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f5f6f8;--card:#ffffff;--line:#e4e7ec;--line2:#d0d5dd;
  --text:#101828;--muted:#667085;--muted2:#98a2b3;
  --accent:#4338ca;--accent2:#4f46e5;--accent-bg:#eef2ff;
  --green:#067647;--green-bg:#ecfdf3;--green-bd:#abefc6;
  --amber:#b54708;--amber-bg:#fffaeb;--amber-bd:#fedf89;
  --red:#b42318;--red-bg:#fef3f2;--red-bd:#fda29b;
  --blue:#175cd3;--blue-bg:#eff8ff;--blue-bd:#b2ddff;
  --orange:#c4320a;--orange-bg:#fff4ed;--orange-bd:#f9dbaf;
  --purple:#6941c6;--purple-bg:#f9f5ff;--purple-bd:#d6bbfb;
  --cyan:#0e7090;--cyan-bg:#ecfdff;--cyan-bd:#a5f0fc;
  --yellow:#854a0e;--yellow-bg:#fefbe8;--yellow-bd:#fde272;
}
body{background:var(--bg);color:var(--text);min-height:100vh;font-family:'Inter',Segoe UI,system-ui,sans-serif;-webkit-font-smoothing:antialiased}
nav{height:62px;display:flex;align-items:center;justify-content:space-between;padding:0 26px;background:#fff;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:50}
.brand{display:flex;align-items:center;gap:11px}
.brand-badge{width:34px;height:34px;border-radius:9px;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:15px}
.brand h1{font-size:14.5px;font-weight:700;letter-spacing:-.01em}
.brand small{display:block;color:var(--muted);font-size:11px;margin-top:1px;font-weight:500}
.nav-links a{color:var(--muted);text-decoration:none;margin-left:18px;font-size:13.5px;font-weight:600}
.nav-links a:hover{color:var(--text)}
.wrap{max-width:1440px;margin:0 auto;padding:26px}
.pagehead{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:20px}
.pagehead h2{font-size:22px;font-weight:700;letter-spacing:-.01em;margin-bottom:4px}
.pagehead p{color:var(--muted);font-size:13.5px}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:20px;border-bottom:1px solid var(--line);padding-bottom:14px}
.tab{padding:8px 14px;border-radius:8px;text-decoration:none;color:var(--muted);background:transparent;font-size:13px;font-weight:600;border:1px solid transparent}
.tab:hover{background:#f2f4f7;color:var(--text)}
.tab.on{color:var(--accent);background:var(--accent-bg);border-color:#c7d2fe}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:20px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.stat .k{color:var(--muted);font-size:12px;margin-bottom:8px;font-weight:600}
.stat .v{font-size:26px;font-weight:700;letter-spacing:-.01em}
.grid{display:grid;grid-template-columns:1.1fr .9fr;gap:18px;align-items:start}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.card-head{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:12px}
.card-head h3{font-size:14px;font-weight:700}
.card-body{padding:20px}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.full{grid-column:1/-1}
label{display:block;font-size:12.5px;font-weight:600;color:#344054;margin-bottom:6px}
input,select,textarea{width:100%;background:#fff;border:1px solid #d0d5dd;color:var(--text);border-radius:9px;padding:10px 12px;font-size:13.5px;outline:none;font-family:inherit;transition:border-color .12s,box-shadow .12s}
select,option{background:#fff;color:var(--text)}
textarea{min-height:80px;resize:vertical}
input:focus,select:focus,textarea:focus{border-color:var(--accent2);box-shadow:0 0 0 4px rgba(79,70,229,.12)}
.actions{margin-top:16px;display:flex;justify-content:flex-end}
.btn{border:none;border-radius:9px;padding:10px 16px;font-size:13px;font-weight:600;cursor:pointer;color:#fff;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;transition:filter .12s}
.btn:hover{filter:brightness(.94)}
.btn-main{background:var(--accent)}
.btn-green{background:#079455}
.btn-orange{background:#dc6803}
.btn-red{background:#d92d20}
.btn-muted{background:#667085}
.btn-xs{padding:7px 11px;font-size:11.5px;border-radius:7px}
.table-wrap{overflow:auto}
.toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:14px 20px;border-bottom:1px solid var(--line)}
.search{min-width:240px;flex:1;background:#fff;border:1px solid #d0d5dd;border-radius:9px;color:var(--text);padding:9px 13px;font-size:13px;outline:none}
.search:focus{border-color:var(--accent2);box-shadow:0 0 0 4px rgba(79,70,229,.12)}
.filter-tabs{display:flex;gap:6px;flex-wrap:wrap}
.ftab{border:1px solid var(--line2);background:#fff;color:var(--muted);border-radius:8px;padding:7px 12px;font-size:11.5px;font-weight:600;cursor:pointer}
.ftab:hover{background:#f2f4f7}
.ftab.on{color:var(--accent);background:var(--accent-bg);border-color:#c7d2fe}
table{width:100%;border-collapse:collapse}
th,td{padding:11px 14px;border-bottom:1px solid var(--line);text-align:left;font-size:12.5px;white-space:nowrap;vertical-align:top}
th{color:var(--muted);font-size:11px;letter-spacing:.03em;text-transform:uppercase;font-weight:700;background:#fafafa}
tbody tr:hover td{background:#fafbff}
.kbox{display:inline-flex;align-items:center;gap:6px;max-width:200px;overflow:hidden;text-overflow:ellipsis;padding:6px 9px;border-radius:7px;background:#f2f4f7;border:1px solid var(--line);font-family:'JetBrains Mono',ui-monospace,Consolas,monospace;cursor:pointer;font-size:11px}
.kbox:hover{background:var(--accent-bg);border-color:#c7d2fe}
.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:600}
.green{background:var(--green-bg);color:var(--green);border:1px solid var(--green-bd)}
.amber{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-bd)}
.red{background:var(--red-bg);color:var(--red);border:1px solid var(--red-bd)}
.blue{background:var(--blue-bg);color:var(--blue);border:1px solid var(--blue-bd)}
.orange{background:var(--orange-bg);color:var(--orange);border:1px solid var(--orange-bd)}
.purple{background:var(--purple-bg);color:var(--purple);border:1px solid var(--purple-bd)}
.cyan{background:var(--cyan-bg);color:var(--cyan);border:1px solid var(--cyan-bd)}
.yellow{background:var(--yellow-bg);color:var(--yellow);border:1px solid var(--yellow-bd)}
.actions-row{display:flex;gap:5px;flex-wrap:wrap}
.log{display:flex;flex-direction:column;gap:8px}
.log-item{padding:11px 13px;border-radius:10px;background:#fafafa;border:1px solid var(--line)}
.log-item strong{display:block;margin-bottom:3px;font-size:12.5px;font-weight:700}
.log-item div{font-size:12px;color:#475467;margin-bottom:3px}
.log-item small{color:var(--muted2);font-size:11px}
.modal{position:fixed;inset:0;background:rgba(16,24,40,.45);display:none;align-items:center;justify-content:center;z-index:999;padding:16px}
.modal.open{display:flex}
.modal-box{width:100%;max-width:420px;background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:0 20px 60px rgba(16,24,40,.25);overflow:hidden}
.modal-head{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between}
.modal-head h4{font-size:14.5px;font-weight:700}
.modal-close{border:none;background:#f2f4f7;color:var(--muted);font-size:17px;cursor:pointer;width:26px;height:26px;border-radius:7px;line-height:1}
.modal-close:hover{background:#e4e7ec;color:var(--text)}
.modal-body{padding:20px}
.toast{position:fixed;right:20px;bottom:20px;z-index:1200;background:#101828;color:#fff;padding:10px 15px;border-radius:9px;font-size:13px;font-weight:600;opacity:0;transform:translateY(10px);transition:.2s;pointer-events:none}
.toast.show{opacity:1;transform:translateY(0)}
.note{font-size:12px;color:var(--muted)}
@media(max-width:1120px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}}
@media(max-width:740px){.wrap{padding:16px}.stats{grid-template-columns:1fr}.form-grid{grid-template-columns:1fr}}
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
  <div class="pagehead">
    <div>
      <h2>Lisans Yönetimi</h2>
      <p>Gazi HR, AutoServis CRM, Fiyat Teklifi, ETA Analitik, KKDİK Suite, Etanom Teklif ve Etanom Fatura lisanslarını yönetin.</p>
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
    <div class="stat"><div class="k">Yaklaşan (30 gün)</div><div class="v">{{ stats.expiring }}</div></div>
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
                  <div style="font-weight:600">{{ l.customer_name or '-' }}</div>
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
