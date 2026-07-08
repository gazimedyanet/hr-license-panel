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
:root{--bg:#060b16;--panel:#0e1728;--line:#1e2c46;--text:#eef2fb;--muted:#8695b3;--blue:#4f7cff;--blue2:#2f5ce0;--cyan:#22d3ee;--danger:#f87171;--radius:20px}
body{min-height:100vh;background:
  radial-gradient(900px 500px at 12% -8%,rgba(79,124,255,.24),transparent 60%),
  radial-gradient(800px 480px at 100% 108%,rgba(34,211,238,.16),transparent 55%),
  linear-gradient(175deg,#060b16 0%,#0a1120 55%,#070d19 100%);
  font-family:'Inter',Segoe UI,system-ui,sans-serif;color:var(--text);display:flex;align-items:center;justify-content:center;padding:24px;position:relative;overflow:hidden}
body::before{content:"";position:absolute;inset:0;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:42px 42px;mask-image:radial-gradient(circle at 50% 40%,#000 0%,transparent 72%);pointer-events:none}
.shell{position:relative;width:100%;max-width:400px;background:linear-gradient(180deg,rgba(20,32,54,.92),rgba(13,21,36,.92));backdrop-filter:blur(22px);border:1px solid rgba(255,255,255,.08);border-radius:var(--radius);padding:38px 32px 32px;box-shadow:0 30px 90px rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.05)}
.logo{width:58px;height:58px;border-radius:16px;background:linear-gradient(135deg,var(--blue),var(--cyan));display:flex;align-items:center;justify-content:center;font-size:26px;margin:0 auto 20px;box-shadow:0 14px 34px rgba(79,124,255,.4)}
h1{text-align:center;font-size:22px;font-weight:800;letter-spacing:-.01em;margin-bottom:5px}
.sub{text-align:center;color:var(--muted);font-size:13px;margin-bottom:30px;font-weight:500}
.err{display:flex;align-items:center;gap:8px;background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.25);color:#fecaca;border-radius:12px;padding:12px 14px;margin-bottom:18px;font-size:13px;font-weight:500}
.err::before{content:"⚠";flex-shrink:0}
label{display:block;font-size:10.5px;font-weight:700;letter-spacing:.1em;color:var(--muted);margin-bottom:7px;text-transform:uppercase}
.field{margin-bottom:16px}
input{width:100%;background:rgba(255,255,255,.03);border:1.5px solid var(--line);color:var(--text);border-radius:12px;padding:13px 15px;font-size:14px;outline:none;font-family:inherit;transition:border-color .15s,box-shadow .15s}
input:hover{border-color:#2c3d5c}
input:focus{border-color:var(--blue);box-shadow:0 0 0 4px rgba(79,124,255,.15)}
button{width:100%;border:none;border-radius:12px;padding:14px 16px;margin-top:6px;background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;font-size:14px;font-weight:700;letter-spacing:.01em;cursor:pointer;box-shadow:0 12px 28px rgba(47,92,224,.35);transition:filter .15s,transform .15s}
button:hover{filter:brightness(1.08)}
button:active{transform:translateY(1px)}
</style></head>
<body>
<div class="shell">
  <div class="logo">🔐</div>
  <h1>Gazi Medya</h1>
  <div class="sub">Lisans Yönetim Paneli</div>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="POST">
    <div class="field"><label>Kullanıcı Adı</label><input name="username" autocomplete="username" required autofocus></div>
    <div class="field"><label>Şifre</label><input name="password" type="password" autocomplete="current-password" required></div>
    <button type="submit">Giriş Yap</button>
  </form>
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
:root{--bg:#060b16;--nav:#0b1424;--panel:#0e1728;--line:#1e2c46;--text:#eef2fb;--muted:#8695b3;--blue:#4f7cff;--blue2:#2f5ce0;--ok:#22c58e;--danger:#f87171}
body{min-height:100vh;background:radial-gradient(900px 460px at 10% -8%,rgba(79,124,255,.18),transparent 60%),linear-gradient(175deg,#060b16 0%,#0a1120 100%);color:var(--text);font-family:'Inter',Segoe UI,system-ui,sans-serif}
nav{height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 28px;background:rgba(11,20,36,.88);border-bottom:1px solid rgba(255,255,255,.06);backdrop-filter:blur(16px);position:sticky;top:0;z-index:10}
.brand{font-weight:800;letter-spacing:-.01em;display:flex;align-items:center;gap:10px}
.brand::before{content:"🔐";font-size:16px}
.nav-links a{color:var(--muted);text-decoration:none;margin-left:18px;font-size:13px;font-weight:600;transition:color .15s}
.nav-links a:hover{color:var(--text)}
.wrap{max-width:520px;margin:52px auto;padding:0 20px}
.card{background:linear-gradient(180deg,rgba(20,32,54,.9),rgba(13,21,36,.9));border:1px solid rgba(255,255,255,.08);border-radius:22px;padding:32px;box-shadow:0 26px 80px rgba(0,0,0,.4),inset 0 1px 0 rgba(255,255,255,.04)}
h1{font-size:23px;font-weight:800;letter-spacing:-.01em;margin-bottom:6px}
.sub{color:var(--muted);font-size:13px;margin-bottom:26px;line-height:1.5}
.ok{display:flex;gap:8px;align-items:center;padding:12px 14px;border-radius:12px;margin-bottom:18px;font-size:13px;font-weight:500;background:rgba(34,197,142,.1);border:1px solid rgba(34,197,142,.28);color:#a7f3d0}
.ok::before{content:"✓"}
.er{display:flex;gap:8px;align-items:center;padding:12px 14px;border-radius:12px;margin-bottom:18px;font-size:13px;font-weight:500;background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.28);color:#fecaca}
.er::before{content:"⚠"}
label{display:block;font-size:10.5px;font-weight:700;letter-spacing:.1em;color:var(--muted);margin-bottom:7px;text-transform:uppercase}
.field{margin-bottom:16px}
input{width:100%;background:rgba(255,255,255,.03);border:1.5px solid var(--line);color:var(--text);border-radius:12px;padding:13px 15px;font-size:14px;outline:none;font-family:inherit;transition:border-color .15s,box-shadow .15s}
input:hover{border-color:#2c3d5c}
input:focus{border-color:var(--blue);box-shadow:0 0 0 4px rgba(79,124,255,.15)}
button{width:100%;border:none;border-radius:12px;padding:14px 16px;margin-top:6px;background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;font-size:14px;font-weight:700;cursor:pointer;box-shadow:0 12px 28px rgba(47,92,224,.35);transition:filter .15s}
button:hover{filter:brightness(1.08)}
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
  --bg:#060b16;--bg2:#0a1120;--panel:#0e1728;--panel2:#111d33;--line:#1e2c46;--line2:#2c3d5c;
  --text:#eef2fb;--muted:#8695b3;--muted2:#5f7196;
  --blue:#4f7cff;--blue2:#2f5ce0;--cyan:#22d3ee;--green:#22c58e;--amber:#f6ad3c;--red:#f87171;--orange:#fb923c;--purple:#a78bfa;
  --radius-lg:22px;--radius-md:16px;--radius-sm:12px
}
html{scrollbar-color:#2c3d5c transparent}
::-webkit-scrollbar{height:10px;width:10px}
::-webkit-scrollbar-thumb{background:#22314e;border-radius:8px}
::-webkit-scrollbar-thumb:hover{background:#2c3d5c}
body{
  background:
    radial-gradient(1000px 560px at 8% -10%,rgba(79,124,255,.14),transparent 55%),
    radial-gradient(900px 520px at 100% 0%,rgba(34,211,238,.09),transparent 50%),
    linear-gradient(175deg,var(--bg) 0%,var(--bg2) 60%,#070d19 100%);
  color:var(--text);min-height:100vh;font-family:'Inter',Segoe UI,system-ui,sans-serif;-webkit-font-smoothing:antialiased;letter-spacing:-.005em
}
nav{height:66px;display:flex;align-items:center;justify-content:space-between;padding:0 30px;background:rgba(9,15,28,.82);border-bottom:1px solid rgba(255,255,255,.06);backdrop-filter:blur(18px);position:sticky;top:0;z-index:50}
.brand{display:flex;align-items:center;gap:12px}
.brand-badge{width:38px;height:38px;border-radius:12px;background:linear-gradient(135deg,var(--blue),var(--cyan));display:flex;align-items:center;justify-content:center;font-size:17px;box-shadow:0 10px 26px rgba(79,124,255,.35)}
.brand h1{font-size:15.5px;font-weight:800;letter-spacing:-.01em}
.brand small{display:block;color:var(--muted);font-size:11px;margin-top:2px;font-weight:500}
.nav-links a{color:var(--muted);text-decoration:none;margin-left:20px;font-size:13px;font-weight:600;transition:color .15s}
.nav-links a:hover{color:var(--text)}
.wrap{max-width:1500px;margin:0 auto;padding:30px}
.hero{position:relative;background:linear-gradient(120deg,#0f2038 0%,#16305a 55%,#0f2a4a 100%);border:1px solid rgba(255,255,255,.08);border-radius:28px;padding:28px 30px;margin-bottom:22px;box-shadow:0 26px 80px rgba(0,0,0,.32),inset 0 1px 0 rgba(255,255,255,.05);overflow:hidden}
.hero::after{content:"";position:absolute;top:-60%;right:-8%;width:420px;height:420px;background:radial-gradient(circle,rgba(79,124,255,.22),transparent 70%);pointer-events:none}
.hero-top{position:relative;display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;align-items:flex-start}
.hero h2{font-size:26px;font-weight:800;letter-spacing:-.02em;margin-bottom:9px}
.hero p{color:#b9c8e3;max-width:720px;line-height:1.65;font-size:13.5px}
.hero-meta{display:grid;grid-template-columns:repeat(2,minmax(136px,1fr));gap:12px;min-width:300px}
.meta-box{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);border-radius:15px;padding:14px 15px;transition:background .15s}
.meta-box:hover{background:rgba(255,255,255,.08)}
.meta-box .k{font-size:9.5px;color:#a9bcdc;letter-spacing:.1em;font-weight:700;margin-bottom:6px;text-transform:uppercase}
.meta-box .v{font-size:19px;font-weight:800;letter-spacing:-.01em}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 20px}
.tab{padding:9px 15px;border-radius:11px;text-decoration:none;border:1px solid var(--line);color:var(--muted);background:rgba(255,255,255,.02);font-size:12.5px;font-weight:600;transition:all .15s}
.tab:hover{border-color:var(--line2);color:var(--text)}
.tab.on{color:#fff;border-color:rgba(79,124,255,.5);background:linear-gradient(135deg,rgba(79,124,255,.28),rgba(34,211,238,.14));box-shadow:0 6px 18px rgba(79,124,255,.18)}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:22px}
.stat{position:relative;background:linear-gradient(180deg,rgba(20,32,54,.75),rgba(14,23,40,.75));border:1px solid rgba(255,255,255,.06);border-radius:18px;padding:18px 20px;overflow:hidden;transition:transform .15s,border-color .15s}
.stat:hover{transform:translateY(-2px);border-color:var(--line2)}
.stat .k{color:var(--muted);font-size:10.5px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:9px;font-weight:700}
.stat .v{font-size:30px;font-weight:800;line-height:1;letter-spacing:-.02em}
.grid{display:grid;grid-template-columns:1.1fr .9fr;gap:20px;align-items:start}
.card{background:linear-gradient(180deg,rgba(19,30,52,.82),rgba(13,21,37,.9));border:1px solid rgba(255,255,255,.07);border-radius:var(--radius-lg);overflow:hidden;box-shadow:0 20px 56px rgba(0,0,0,.24)}
.card-head{padding:19px 22px;border-bottom:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.015);display:flex;justify-content:space-between;align-items:center;gap:12px}
.card-head h3{font-size:14px;font-weight:800;letter-spacing:.01em}
.card-body{padding:22px}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.full{grid-column:1/-1}
label{display:block;font-size:10.5px;font-weight:700;letter-spacing:.1em;color:var(--muted);margin-bottom:8px;text-transform:uppercase}
input,select,textarea{width:100%;background:rgba(255,255,255,.03);border:1.5px solid var(--line);color:var(--text);border-radius:13px;padding:12px 14px;font-size:13.5px;outline:none;font-family:inherit;transition:border-color .15s,box-shadow .15s}
select,option{background:#0e1728;color:var(--text)}
textarea{min-height:88px;resize:vertical}
input:hover,select:hover,textarea:hover{border-color:var(--line2)}
input:focus,select:focus,textarea:focus{border-color:var(--blue);box-shadow:0 0 0 4px rgba(79,124,255,.14)}
.actions{margin-top:18px;display:flex;justify-content:flex-end}
.btn{border:none;border-radius:12px;padding:11px 18px;font-size:12.5px;font-weight:700;cursor:pointer;color:#fff;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;transition:filter .15s,transform .15s;letter-spacing:-.005em}
.btn:hover{filter:brightness(1.1)}
.btn:active{transform:translateY(1px)}
.btn-main{background:linear-gradient(135deg,var(--blue),var(--blue2));box-shadow:0 8px 20px rgba(47,92,224,.32)}
.btn-green{background:linear-gradient(135deg,#22c58e,#0e9e6d);box-shadow:0 8px 20px rgba(14,158,109,.28)}
.btn-orange{background:linear-gradient(135deg,#f6ad3c,#e08a12);box-shadow:0 8px 20px rgba(224,138,18,.26)}
.btn-red{background:linear-gradient(135deg,#f87171,#dc2626);box-shadow:0 8px 20px rgba(220,38,38,.28)}
.btn-muted{background:linear-gradient(135deg,#4b5b78,#334155)}
.btn-xs{padding:8px 11px;font-size:11px;border-radius:9px;box-shadow:none}
.table-wrap{overflow:auto}
.toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:16px 22px;border-bottom:1px solid rgba(255,255,255,.06)}
.search{min-width:260px;flex:1;background:rgba(255,255,255,.03);border:1.5px solid var(--line);border-radius:12px;color:var(--text);padding:11px 14px;font-size:13px;outline:none;transition:border-color .15s}
.search:focus{border-color:var(--blue);box-shadow:0 0 0 4px rgba(79,124,255,.14)}
.filter-tabs{display:flex;gap:7px;flex-wrap:wrap}
.ftab{border:1px solid var(--line);background:rgba(255,255,255,.02);color:var(--muted);border-radius:10px;padding:8px 13px;font-size:11.5px;font-weight:700;cursor:pointer;transition:all .15s}
.ftab:hover{border-color:var(--line2);color:var(--text)}
.ftab.on{color:#fff;background:rgba(79,124,255,.22);border-color:rgba(79,124,255,.45)}
table{width:100%;border-collapse:collapse}
th,td{padding:13px 15px;border-bottom:1px solid rgba(255,255,255,.05);text-align:left;font-size:12.5px;white-space:nowrap;vertical-align:top}
th{color:var(--muted2);font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;font-weight:800;background:rgba(255,255,255,.015)}
tbody tr{transition:background .12s}
tbody tr:hover td{background:rgba(79,124,255,.045)}
.kbox{display:inline-flex;align-items:center;gap:6px;max-width:210px;overflow:hidden;text-overflow:ellipsis;padding:7px 10px;border-radius:9px;background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.07);font-family:'JetBrains Mono',ui-monospace,Consolas,monospace;cursor:pointer;font-size:11.5px;transition:background .15s,border-color .15s}
.kbox:hover{background:rgba(79,124,255,.12);border-color:rgba(79,124,255,.35)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:999px;font-size:10.5px;font-weight:800;letter-spacing:.01em}
.green{background:rgba(34,197,142,.14);color:#7ee7c2;border:1px solid rgba(34,197,142,.22)}
.amber{background:rgba(246,173,60,.14);color:#fbcd80;border:1px solid rgba(246,173,60,.22)}
.red{background:rgba(248,113,113,.14);color:#fca5a5;border:1px solid rgba(248,113,113,.22)}
.blue{background:rgba(79,124,255,.14);color:#a9c0ff;border:1px solid rgba(79,124,255,.24)}
.orange{background:rgba(251,146,60,.14);color:#fdbb85;border:1px solid rgba(251,146,60,.22)}
.purple{background:rgba(167,139,250,.14);color:#cbb9fb;border:1px solid rgba(167,139,250,.22)}
.cyan{background:rgba(34,211,238,.14);color:#8be9f7;border:1px solid rgba(34,211,238,.22)}
.yellow{background:rgba(246,173,60,.14);color:#fbcd80;border:1px solid rgba(246,173,60,.22)}
.actions-row{display:flex;gap:6px;flex-wrap:wrap}
.log{display:flex;flex-direction:column;gap:9px}
.log-item{padding:13px 15px;border-radius:14px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.05);border-left:2.5px solid rgba(79,124,255,.5);transition:background .15s}
.log-item:hover{background:rgba(255,255,255,.045)}
.log-item strong{display:block;margin-bottom:4px;font-size:12.5px;font-weight:700;letter-spacing:.01em}
.log-item div{font-size:12px;color:#c3cee2;margin-bottom:4px}
.log-item small{color:var(--muted2);font-size:11px}
.modal{position:fixed;inset:0;background:rgba(3,6,14,.72);backdrop-filter:blur(3px);display:none;align-items:center;justify-content:center;z-index:999;padding:16px}
.modal.open{display:flex}
.modal-box{width:100%;max-width:440px;background:linear-gradient(180deg,#152137,#0e1626);border:1px solid rgba(255,255,255,.09);border-radius:20px;box-shadow:0 30px 90px rgba(0,0,0,.55);overflow:hidden}
.modal-head{padding:18px 22px;border-bottom:1px solid rgba(255,255,255,.06);display:flex;align-items:center;justify-content:space-between}
.modal-head h4{font-size:14.5px;font-weight:800;letter-spacing:-.005em}
.modal-close{border:none;background:rgba(255,255,255,.05);color:var(--muted);font-size:18px;cursor:pointer;width:28px;height:28px;border-radius:9px;line-height:1;transition:background .15s,color .15s}
.modal-close:hover{background:rgba(255,255,255,.1);color:var(--text)}
.modal-body{padding:22px}
.toast{position:fixed;right:20px;bottom:20px;z-index:1200;background:linear-gradient(135deg,#22c58e,#0e9e6d);color:#fff;padding:11px 16px;border-radius:12px;font-size:13px;font-weight:700;box-shadow:0 16px 40px rgba(14,158,109,.4);opacity:0;transform:translateY(10px);transition:.25s;pointer-events:none}
.toast.show{opacity:1;transform:translateY(0)}
.note{font-size:11.5px;color:var(--muted);line-height:1.6;font-weight:500}
@media(max-width:1120px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}}
@media(max-width:740px){.wrap{padding:18px}.stats{grid-template-columns:1fr}.form-grid{grid-template-columns:1fr}.hero{padding:22px}}
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
