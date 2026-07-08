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
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700;900&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{overflow-x:hidden}
:root{--bg:#f3f4f6;--card:#ffffff;--line:#dfe3e8;--text:#1a1f2b;--muted:#5f6b7a;--accent:#0b57d0;--accent-d:#0842a0;--danger:#c5221f;--danger-bg:#fce8e6}
body{min-height:100vh;background:var(--bg);font-family:'Roboto',Arial,sans-serif;color:var(--text);display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:400px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:40px 36px;box-shadow:0 1px 2px rgba(26,31,43,.04),0 6px 20px rgba(26,31,43,.06)}
.logo{width:44px;height:44px;border-radius:8px;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;color:#fff;margin-bottom:22px;letter-spacing:-.02em}
h1{font-size:21px;font-weight:700;letter-spacing:-.01em;margin-bottom:4px}
.sub{color:var(--muted);font-size:13.5px;margin-bottom:8px}
.divider{height:1px;background:var(--line);margin:22px 0}
.err{background:var(--danger-bg);border:1px solid #f6bab7;color:var(--danger);border-radius:8px;padding:11px 14px;margin-bottom:18px;font-size:13px;font-weight:500}
label{display:block;font-size:12.5px;font-weight:500;color:#3c4451;margin-bottom:6px}
.field{margin-bottom:17px}
input{width:100%;background:#fff;border:1.5px solid #c9cfd8;color:var(--text);border-radius:6px;padding:10px 13px;font-size:14px;outline:none;font-family:inherit;transition:border-color .12s,box-shadow .12s}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(11,87,208,.15)}
button{width:100%;border:none;border-radius:6px;padding:11px 16px;margin-top:8px;background:var(--accent);color:#fff;font-size:14px;font-weight:500;cursor:pointer;transition:background .12s}
button:hover{background:var(--accent-d)}
.foot{text-align:center;color:#8a94a3;font-size:11.5px;margin-top:24px;letter-spacing:.02em}
</style></head>
<body>
<div class="card">
  <div class="logo">GM</div>
  <h1>Gazi Medya</h1>
  <div class="sub">Lisans Yönetim Sistemi</div>
  <div class="divider"></div>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="POST">
    <div class="field"><label>Kullanıcı Adı</label><input name="username" autocomplete="username" required autofocus></div>
    <div class="field"><label>Şifre</label><input name="password" type="password" autocomplete="current-password" required></div>
    <button type="submit">Oturum Aç</button>
  </form>
  <div class="foot">GAZİ MEDYA YAZILIM &copy; Kurumsal Lisans Platformu</div>
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
html,body{overflow-x:hidden}
:root{--bg:#f3f4f6;--card:#ffffff;--line:#dfe3e8;--text:#1a1f2b;--muted:#5f6b7a;--accent:#0b57d0;--accent-d:#0842a0;--ok:#137333;--ok-bg:#e6f4ea;--danger:#c5221f;--danger-bg:#fce8e6}
body{min-height:100vh;background:var(--bg);font-family:'Roboto',Arial,sans-serif;color:var(--text)}
nav{height:56px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;background:#fff;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:10}
.brand{font-weight:700;font-size:14px;color:var(--text);display:flex;align-items:center;gap:10px;letter-spacing:-.005em}
.brand .b{width:26px;height:26px;border-radius:6px;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff}
.nav-links a{color:var(--muted);text-decoration:none;margin-left:20px;font-size:13px;font-weight:500}
.nav-links a:hover{color:var(--text)}
.wrap{max-width:480px;margin:60px auto;padding:0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:32px;box-shadow:0 1px 2px rgba(26,31,43,.04),0 6px 20px rgba(26,31,43,.06)}
h1{font-size:19px;font-weight:700;letter-spacing:-.01em;margin-bottom:5px}
.sub{color:var(--muted);font-size:13.5px;margin-bottom:24px}
.ok{padding:11px 14px;border-radius:8px;margin-bottom:18px;font-size:13px;font-weight:500;background:var(--ok-bg);border:1px solid #ceead6;color:var(--ok)}
.er{padding:11px 14px;border-radius:8px;margin-bottom:18px;font-size:13px;font-weight:500;background:var(--danger-bg);border:1px solid #f6bab7;color:var(--danger)}
label{display:block;font-size:12.5px;font-weight:500;color:#3c4451;margin-bottom:6px}
.field{margin-bottom:17px}
input{width:100%;background:#fff;border:1.5px solid #c9cfd8;color:var(--text);border-radius:6px;padding:10px 13px;font-size:14px;outline:none;font-family:inherit;transition:border-color .12s,box-shadow .12s}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(11,87,208,.15)}
button{width:100%;border:none;border-radius:6px;padding:11px 16px;margin-top:6px;background:var(--accent);color:#fff;font-size:14px;font-weight:500;cursor:pointer;transition:background .12s}
button:hover{background:var(--accent-d)}
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
  --bg:#f3f4f6;--card:#ffffff;--line:#dfe3e8;--line2:#c9cfd8;
  --text:#1a1f2b;--muted:#5f6b7a;--muted2:#8a94a3;
  --accent:#0b57d0;--accent-d:#0842a0;--accent-bg:#e8f0fe;
  --side-bg:#fbfbfc;--side-line:#e3e6ec;
  --green:#137333;--green-bg:#e6f4ea;--green-bd:#ceead6;
  --amber:#a35700;--amber-bg:#fef7e0;--amber-bd:#fdd775;
  --red:#c5221f;--red-bg:#fce8e6;--red-bd:#f6bab7;
  --gray:#3c4451;--gray-bg:#eef0f3;--gray-bd:#d7dbe1;
  --radius:8px;--sidebar-w:240px
}
html{scrollbar-color:#c9cfd8 transparent}
::-webkit-scrollbar{height:9px;width:9px}
::-webkit-scrollbar-thumb{background:#c9cfd8;border-radius:8px}
body{background:var(--bg);color:var(--text);min-height:100vh;font-family:'Roboto',Arial,sans-serif;-webkit-font-smoothing:antialiased}
.shell{display:flex;min-height:100vh;min-width:0}

/* ── Sol Menü ────────────────────────────────────────── */
.sidebar{width:var(--sidebar-w);flex-shrink:0;background:var(--side-bg);border-right:1px solid var(--side-line);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}
.side-brand{display:flex;align-items:center;gap:10px;padding:18px}
.side-brand .b{width:30px;height:30px;border-radius:7px;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:12.5px;font-weight:700;color:#fff;flex-shrink:0}
.side-brand h1{font-size:13.5px;font-weight:700;letter-spacing:-.005em}
.side-brand small{display:block;color:var(--muted2);font-size:10.5px;margin-top:1px;font-weight:400}
.side-section{padding:8px 10px 4px}
.side-label{font-size:10px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--muted2);padding:10px 10px 6px}
.nav-link{display:flex;align-items:center;justify-content:space-between;gap:8px;color:#333c48;text-decoration:none;font-size:12.5px;font-weight:500;padding:8px 10px;border-radius:6px;margin-bottom:1px;transition:background .12s,color .12s}
.nav-link:hover{background:#eef0f3}
.nav-link.on{background:var(--accent-bg);color:var(--accent-d);font-weight:700}
.nav-link .lbl{display:flex;align-items:center;gap:9px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.badge{width:18px;height:18px;border-radius:4px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:8.5px;font-weight:700;color:#fff;letter-spacing:-.02em}
.badge-all{background:#3c4451}
.badge-hr{background:#0b57d0}
.badge-asc{background:#b06000}
.badge-ft{background:#137333}
.badge-eta{background:#7c3aed}
.badge-kkdik{background:#0e7c86}
.badge-etk{background:#9d6b0a}
.badge-etf{background:#c5221f}
.nav-link .cnt{background:#e3e6ec;color:var(--muted);font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;flex-shrink:0}
.nav-link.on .cnt{background:#c9dbfc;color:var(--accent-d)}
.side-spacer{flex:1}
.side-log{padding:4px 10px 8px;border-top:1px solid var(--side-line);margin-top:6px}
.side-log .side-label{padding:12px 10px 8px}
.side-log .list{max-height:300px;overflow-y:auto;display:flex;flex-direction:column;gap:6px;padding-right:2px}
.side-log .log-item{padding:8px 10px;border-radius:6px;background:#fff;border:1px solid var(--line);border-left:3px solid var(--accent)}
.side-log .log-item strong{display:block;margin-bottom:2px;font-size:11px;font-weight:700}
.side-log .log-item div{font-size:10.5px;color:#4b5563;margin-bottom:2px;word-break:break-word;line-height:1.35}
.side-log .log-item small{color:var(--muted2);font-size:10px}
.side-foot{padding:10px;border-top:1px solid var(--side-line)}
.side-foot a{display:flex;align-items:center;gap:8px;color:#333c48;text-decoration:none;font-size:12.5px;font-weight:500;padding:8px 10px;border-radius:6px;transition:background .12s}
.side-foot a:hover{background:#eef0f3}

/* ── İçerik ──────────────────────────────────────────── */
.main{flex:1;min-width:0;padding:24px 30px 42px;max-width:100%}
.topbar{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:22px;padding-bottom:18px;border-bottom:1px solid var(--line)}
.topbar h2{font-size:20px;font-weight:700;letter-spacing:-.01em;margin-bottom:5px}
.topbar p{color:var(--muted);font-size:13px;max-width:600px;line-height:1.5}
.btn{border:none;border-radius:6px;padding:9px 16px;font-size:13px;font-weight:500;cursor:pointer;color:#fff;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;transition:filter .12s,transform .12s;white-space:nowrap}
.btn:hover{filter:brightness(.93)}
.btn:active{transform:translateY(1px)}
.btn-main{background:var(--accent)}
.btn-green{background:#188038}
.btn-orange{background:#b06000}
.btn-red{background:#c5221f}
.btn-muted{background:#5f6b7a}
.btn-xs{padding:6px 10px;font-size:11px;border-radius:5px}

.stats{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:8px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px;min-width:0}
.stat .k{color:var(--muted);font-size:11px;margin-bottom:8px;font-weight:500;text-transform:uppercase;letter-spacing:.03em}
.stat .v{font-size:24px;font-weight:700;letter-spacing:-.01em}
.stats-note{font-size:11.5px;color:var(--muted2);margin-bottom:20px}

.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;min-width:0}
.card-head{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:12px}
.card-head h3{font-size:13.5px;font-weight:700}
.card-body{padding:18px}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}
.full{grid-column:1/-1}
label{display:block;font-size:12px;font-weight:500;color:#3c4451;margin-bottom:6px}
input,select,textarea{width:100%;background:#fff;border:1.5px solid #c9cfd8;color:var(--text);border-radius:6px;padding:9px 12px;font-size:13px;outline:none;font-family:inherit;transition:border-color .12s,box-shadow .12s}
select,option{background:#fff;color:var(--text)}
textarea{min-height:76px;resize:vertical}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(11,87,208,.15)}
.actions{margin-top:15px;display:flex;justify-content:flex-end;gap:9px}

.table-wrap{overflow-x:auto;max-width:100%}
.toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:12px 18px;border-bottom:1px solid var(--line)}
.search{min-width:180px;flex:1;background:#fff;border:1.5px solid #c9cfd8;border-radius:6px;color:var(--text);padding:8px 12px;font-size:12.5px;outline:none}
.search:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(11,87,208,.15)}
.filter-tabs{display:flex;gap:5px;flex-wrap:wrap}
.ftab{border:1px solid var(--line2);background:#fff;color:var(--muted);border-radius:5px;padding:6px 10px;font-size:11px;font-weight:500;cursor:pointer;transition:all .12s}
.ftab:hover{background:#f8f9fa}
.ftab.on{color:#fff;background:var(--accent);border-color:var(--accent)}
table{width:100%;border-collapse:collapse;table-layout:auto}
th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;font-size:12px;vertical-align:middle}
th{color:var(--muted);font-size:10px;letter-spacing:.05em;text-transform:uppercase;font-weight:700;background:#f8f9fa;white-space:nowrap}
tbody tr:hover td{background:#f6f8fc}
td.col-id{width:44px;color:var(--muted2);font-variant-numeric:tabular-nums}
td.col-cust{max-width:150px}
.custname{font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}
.kbox{display:inline-flex;align-items:center;gap:5px;max-width:190px;overflow:hidden;text-overflow:ellipsis;padding:6px 9px;border-radius:5px;background:#f1f2f5;border:1px solid var(--line);font-family:'Roboto Mono',ui-monospace,Consolas,monospace;cursor:pointer;font-size:10.5px;white-space:nowrap;transition:background .12s,border-color .12s}
.kbox:hover{background:var(--accent-bg);border-color:#aecbfa}
.pill{display:inline-flex;align-items:center;gap:5px;padding:4px 9px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;white-space:nowrap}
.pill::before{content:"";width:6px;height:6px;border-radius:50%;flex-shrink:0}
.green{background:var(--green-bg);color:var(--green);border:1px solid var(--green-bd)}
.green::before{background:var(--green)}
.amber{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-bd)}
.amber::before{background:var(--amber)}
.red{background:var(--red-bg);color:var(--red);border:1px solid var(--red-bd)}
.red::before{background:var(--red)}
.gray{background:var(--gray-bg);color:var(--gray);border:1px solid var(--gray-bd)}
.gray::before{background:var(--gray)}
.actions-row{display:flex;gap:4px;flex-wrap:nowrap}

.modal{position:fixed;inset:0;background:rgba(26,31,43,.4);display:none;align-items:center;justify-content:center;z-index:999;padding:16px}
.modal.open{display:flex}
.modal-box{width:100%;max-width:440px;background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 48px rgba(26,31,43,.28);overflow:hidden;max-height:88vh;display:flex;flex-direction:column}
.modal-head{padding:16px 19px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.modal-head h4{font-size:14px;font-weight:700}
.modal-close{border:none;background:#eef0f3;color:var(--muted);font-size:16px;cursor:pointer;width:26px;height:26px;border-radius:5px;line-height:1}
.modal-close:hover{background:#dfe3e8;color:var(--text)}
.modal-body{padding:19px;overflow-y:auto}
.info-row{display:flex;justify-content:space-between;gap:14px;padding:10px 0;border-bottom:1px solid var(--line);font-size:12.5px}
.info-row:last-child{border-bottom:none}
.info-row .ik{color:var(--muted);font-weight:500;flex-shrink:0}
.info-row .iv{text-align:right;font-weight:500;word-break:break-word}

.toast{position:fixed;right:18px;bottom:18px;z-index:1200;background:#1a1f2b;color:#fff;padding:10px 15px;border-radius:6px;font-size:12.5px;font-weight:500;opacity:0;transform:translateY(10px);transition:.2s;pointer-events:none}
.toast.show{opacity:1;transform:translateY(0)}
.note{font-size:11.5px;color:var(--muted)}
@media(max-width:1180px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:900px){.sidebar{display:none}}
@media(max-width:740px){.main{padding:16px}.stats{grid-template-columns:minmax(0,1fr)}.form-grid{grid-template-columns:minmax(0,1fr)}}
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
    <div class="side-spacer"></div>
    <div class="side-log">
      <div class="side-label">Son İşlemler</div>
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
      <button class="btn btn-main" type="button" onclick="openM('yeniLisans')">+ Yeni Lisans Ekle</button>
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
            <tr data-s="{{ status }}" data-q="{{ ((l.customer_name or '')~' '~(l.customer_email or '')~' '~l.license_key~' '~l.hw_id)|lower }}">
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
      <div class="info-row"><div class="ik">Not</div><div class="iv">{{ l.notes or '-' }}</div></div>
      {% if l.is_revoked %}<div class="info-row"><div class="ik">İptal Sebebi</div><div class="iv">{{ l.revoke_reason or '-' }}</div></div>{% endif %}
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
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.modal.open').forEach(m=>m.classList.remove('open'));});
</script>
</body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"Gazi Medya Lisans Paneli basliyor - port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
