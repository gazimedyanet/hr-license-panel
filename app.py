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
    conn.execute(
        """
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
        """
    )
    for col, dflt in [("package", "'enterprise'"), ("product", "'gazi-hr'")]:
        try:
            conn.execute(f"ALTER TABLE licenses ADD COLUMN {col} TEXT DEFAULT {dflt}")
            conn.commit()
        except Exception:
            pass

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            detail TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    existing = conn.execute(
        "SELECT value FROM admin_settings WHERE key='admin_pass_hash'"
    ).fetchone()
    if not existing:
        h = hashlib.sha256("GaziMedia2026!".encode()).hexdigest()
        conn.execute("INSERT INTO admin_settings VALUES ('admin_pass_hash',?)", (h,))
        conn.execute("INSERT OR IGNORE INTO admin_settings VALUES ('admin_user','gazi')")

    conn.commit()
    conn.close()


init_db()

_K_HR = [
    0x47, 0x61, 0x7A, 0x69, 0x4D, 0x65, 0x64, 0x79, 0x61, 0x48, 0x52,
    0x32, 0x30, 0x32, 0x36, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4B,
    0x65, 0x79, 0x5F, 0x44, 0x6F, 0x4E, 0x6F, 0x74, 0x53, 0x68, 0x61, 0x72, 0x65
]
_K_ASC = [
    0x41, 0x75, 0x74, 0x6F, 0x53, 0x65, 0x72, 0x76, 0x69, 0x73, 0x43,
    0x52, 0x4D, 0x2D, 0x32, 0x30, 0x32, 0x35, 0x2D, 0x4C, 0x69, 0x63,
    0x4B, 0x65, 0x79, 0x2D, 0x47, 0x61, 0x7A, 0x69
]
_K_FT = [
    70, 105, 121, 97, 116, 84, 101, 107, 108, 105, 102, 105, 45, 69, 84, 65,
    45, 65, 110, 97, 108, 105, 116, 105, 107, 45, 50, 48, 50, 54, 45, 76, 105, 99, 75, 101, 121
]

PRODUCTS = {
    "gazi-hr": {"prefix": "GMHR", "key": _K_HR, "label": "Gazi HR", "color": "#3b82f6"},
    "autoservis-crm": {"prefix": "ASC", "key": _K_ASC, "label": "AutoServis CRM", "color": "#f97316"},
    "fiyat-teklifi": {"prefix": "FTK", "key": _K_FT, "label": "Fiyat Teklifi", "color": "#10b981"},
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


@app.route("/login", methods=["GET", "POST"])
def login():
    err = ""
    if request.method == "POST":
        admin_user, admin_hash = get_admin()
        given = hashlib.sha256(request.form.get("password", "").encode()).hexdigest()
        if request.form.get("username", "") == admin_user and given == admin_hash:
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


@app.route("/change-password", methods=["GET", "POST"])
@auth
def change_password():
    msg = ""
    err = ""
    if request.method == "POST":
        _, admin_hash = get_admin()
        cur = request.form.get("current", "")
        new = request.form.get("new_pass", "")
        conf = request.form.get("confirm", "")
        if hashlib.sha256(cur.encode()).hexdigest() != admin_hash:
            err = "Mevcut şifre hatalı"
        elif len(new) < 8:
            err = "Yeni şifre en az 8 karakter olmalı"
        elif new != conf:
            err = "Şifreler eşleşmiyor"
        else:
            conn = get_db()
            conn.execute(
                "UPDATE admin_settings SET value=? WHERE key='admin_pass_hash'",
                (hashlib.sha256(new.encode()).hexdigest(),),
            )
            conn.commit()
            conn.close()
            log("ŞİFRE DEĞİŞTİRİLDİ")
            msg = "Şifre başarıyla güncellendi"
    return render_template_string(CHANGE_PASS_HTML, msg=msg, err=err)


@app.route("/")
@auth
def index():
    conn = get_db()
    prod_filter = request.args.get("product", "all")
    if prod_filter != "all":
        licenses = conn.execute(
            "SELECT * FROM licenses WHERE product=? ORDER BY issued_at DESC",
            (prod_filter,),
        ).fetchall()
    else:
        licenses = conn.execute("SELECT * FROM licenses ORDER BY issued_at DESC").fetchall()

    now = datetime.now().isoformat()
    soon = (datetime.now() + timedelta(days=30)).isoformat()
    stats = {
        "total": conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        "active": conn.execute(
            "SELECT COUNT(*) FROM licenses WHERE is_revoked=0 AND expires_at>?",
            (now,),
        ).fetchone()[0],
        "expired": conn.execute(
            "SELECT COUNT(*) FROM licenses WHERE expires_at<? AND is_revoked=0",
            (now,),
        ).fetchone()[0],
        "revoked": conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=1").fetchone()[0],
        "expiring": conn.execute(
            "SELECT COUNT(*) FROM licenses WHERE is_revoked=0 AND expires_at>? AND expires_at<?",
            (now, soon),
        ).fetchone()[0],
        "hr_count": conn.execute("SELECT COUNT(*) FROM licenses WHERE product='gazi-hr'").fetchone()[0],
        "asc_count": conn.execute("SELECT COUNT(*) FROM licenses WHERE product='autoservis-crm'").fetchone()[0],
        "ft_count": conn.execute("SELECT COUNT(*) FROM licenses WHERE product='fiyat-teklifi'").fetchone()[0],
    }
    logs = conn.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 25").fetchall()
    conn.close()
    return render_template_string(
        PANEL_HTML,
        licenses=licenses,
        stats=stats,
        now=now,
        logs=logs,
        products=PRODUCTS,
        prod_filter=prod_filter,
    )


@app.route("/create", methods=["POST"])
@auth
def create():
    hw_id = request.form.get("hw_id", "").strip().upper()
    days = int(request.form.get("days", 365))
    customer = request.form.get("customer_name", "").strip()
    email = request.form.get("customer_email", "").strip()
    phone = request.form.get("customer_phone", "").strip()
    notes = request.form.get("notes", "").strip()
    package = request.form.get("package", "enterprise").strip()
    product = request.form.get("product", "gazi-hr").strip()

    if product not in PRODUCTS:
        product = "gazi-hr"
    if not hw_id:
        return "Donanım ID gerekli", 400

    expires = (datetime.now() + timedelta(days=days)).isoformat()
    key = gen_key(hw_id, expires, product)

    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO licenses
            (license_key,hw_id,product,customer_name,customer_email,customer_phone,expires_at,notes,package)
            VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (key, hw_id, product, customer, email, phone, expires, notes, package),
        )
        conn.commit()
        log("LİSANS OLUŞTURULDU", f"{customer} | {PRODUCTS[product]['label']} | {expires[:10]}")
    except sqlite3.IntegrityError:
        conn.close()
        return "<script>alert('Bu HW ID + ürün kombinasyonu için zaten lisans var!');history.back()</script>"
    conn.close()
    return redirect("/")


@app.route("/extend/<int:lid>", methods=["POST"])
@auth
def extend(lid):
    days = int(request.form.get("days", 365))
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    if lic:
        cur = datetime.fromisoformat(lic["expires_at"])
        if cur < datetime.now():
            cur = datetime.now()
        new_exp = cur + timedelta(days=days)
        product = lic["product"] or "gazi-hr"
        new_key = gen_key(lic["hw_id"], new_exp.isoformat(), product)
        conn.execute(
            "UPDATE licenses SET license_key=?,expires_at=?,is_revoked=0 WHERE id=?",
            (new_key, new_exp.isoformat(), lid),
        )
        conn.commit()
        log("LİSANS UZATILDI", f"ID:{lid} | {lic['customer_name']} | +{days}g → {new_exp.strftime('%d.%m.%Y')}")
    conn.close()
    return redirect("/")


@app.route("/revoke/<int:lid>", methods=["POST"])
@auth
def revoke(lid):
    reason = request.form.get("reason", "")
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    conn.execute("UPDATE licenses SET is_revoked=1,revoke_reason=? WHERE id=?", (reason, lid))
    conn.commit()
    conn.close()
    log("LİSANS İPTAL", f"ID:{lid} | {lic['customer_name'] if lic else ''} | {reason}")
    return redirect("/")


@app.route("/restore/<int:lid>", methods=["POST"])
@auth
def restore(lid):
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    conn.execute("UPDATE licenses SET is_revoked=0,revoke_reason=NULL WHERE id=?", (lid,))
    conn.commit()
    conn.close()
    log("LİSANS AKTİFLEŞTİRİLDİ", f"ID:{lid} | {lic['customer_name'] if lic else ''}")
    return redirect("/")


@app.route("/edit/<int:lid>", methods=["POST"])
@auth
def edit(lid):
    conn = get_db()
    pkg = request.form.get("package", "enterprise")
    conn.execute(
        "UPDATE licenses SET customer_name=?,customer_email=?,customer_phone=?,notes=?,package=? WHERE id=?",
        (
            request.form.get("customer_name", ""),
            request.form.get("customer_email", ""),
            request.form.get("customer_phone", ""),
            request.form.get("notes", ""),
            pkg,
            lid,
        ),
    )
    conn.commit()
    conn.close()
    log("LİSANS DÜZENLENDİ", f"ID:{lid} | Paket: {pkg}")
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


def _verify_core(key: str, hw: str, product: str):
    if product not in PRODUCTS:
        return None, {"valid": False, "message": "Bilinmeyen ürün"}

    conn = get_db()
    lic = conn.execute(
        "SELECT * FROM licenses WHERE license_key=? AND product=?",
        (key, product),
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

    ok, math_message = validate_key_math(
        lic["license_key"],
        lic["hw_id"],
        lic["expires_at"],
        lic["product"] or product,
    )
    if not ok:
        conn.close()
        return None, {"valid": False, "message": f"Lisans algoritması uyuşmuyor: {math_message}"}

    conn.execute(
        "UPDATE licenses SET last_seen=?,verify_count=verify_count+1 WHERE id=?",
        (datetime.now().isoformat(), lic["id"]),
    )
    conn.commit()
    conn.close()

    days_left = (exp - datetime.now()).days
    return lic, {
        "valid": True,
        "expires": exp.strftime("%d.%m.%Y"),
        "customer": lic["customer_name"],
        "message": "Geçerli",
        "package": lic["package"] or "enterprise",
        "days_left": days_left,
    }


@app.route("/api/hr-license", methods=["POST"])
def verify_hr():
    d = request.get_json(silent=True) or {}
    key = d.get("license_key", "").strip().upper()
    hw = d.get("hw_id", "").strip()
    if d.get("product", "") != "gazi-hr":
        return jsonify({"valid": False, "message": "Bilinmeyen ürün"})
    _, result = _verify_core(key, hw, "gazi-hr")
    return jsonify(result)


@app.route("/api/autoservis-license", methods=["POST"])
def verify_autoservis():
    d = request.get_json(silent=True) or {}
    key = d.get("license_key", "").strip().upper()
    hw = d.get("hw_id", "").strip()
    if d.get("product", "") != "autoservis-crm":
        return jsonify({"valid": False, "message": "Bilinmeyen ürün"})
    _, result = _verify_core(key, hw, "autoservis-crm")
    return jsonify(result)


@app.route("/api/fiyat-teklifi-license", methods=["POST"])
def verify_fiyat_teklifi():
    d = request.get_json(silent=True) or {}
    key = d.get("license_key", "").strip().upper()
    hw = d.get("hw_id", "").strip()
    if d.get("product", "") != "fiyat-teklifi":
        return jsonify({"valid": False, "message": "Bilinmeyen ürün"})
    _, result = _verify_core(key, hw, "fiyat-teklifi")
    return jsonify(result)


@app.route("/api/debug-license-math", methods=["POST"])
def debug_license_math():
    d = request.get_json(silent=True) or {}
    key = d.get("license_key", "").strip().upper()
    hw = d.get("hw_id", "").strip().upper()
    product = d.get("product", "").strip()
    expires_at = d.get("expires_at", "").strip()

    if not all([key, hw, product, expires_at]):
        return jsonify({
            "ok": False,
            "message": "license_key, hw_id, product, expires_at gerekli"
        }), 400

    ok, msg = validate_key_math(key, hw, expires_at, product)
    return jsonify({
        "ok": ok,
        "message": msg,
        "expected": gen_key(hw, expires_at, product) if product in PRODUCTS else None
    })


@app.route("/health")
def health():
    return jsonify({"ok": True, "service": "license-panel"})


LOGIN_HTML = """
LOGIN_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Gazi Medya - Giriş</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#07111f;
      --panel:#0f1b2d;
      --panel-2:#14243b;
      --line:#223552;
      --text:#e8eef8;
      --muted:#8ea2bf;
      --blue:#3b82f6;
      --cyan:#06b6d4;
      --danger:#ef4444;
    }
    body{
      min-height:100vh;
      background:
        radial-gradient(circle at top left, rgba(59,130,246,.20), transparent 30%),
        radial-gradient(circle at bottom right, rgba(6,182,212,.14), transparent 28%),
        linear-gradient(160deg,#07111f 0%,#0b1526 100%);
      font-family:Segoe UI,system-ui,sans-serif;
      color:var(--text);
      display:flex;
      align-items:center;
      justify-content:center;
      padding:24px;
    }
    .shell{
      width:100%;
      max-width:420px;
      background:rgba(15,27,45,.88);
      backdrop-filter:blur(18px);
      border:1px solid rgba(255,255,255,.08);
      border-radius:24px;
      padding:34px 30px 28px;
      box-shadow:0 24px 80px rgba(0,0,0,.45);
    }
    .logo{
      width:64px;height:64px;border-radius:18px;
      background:linear-gradient(135deg,var(--blue),var(--cyan));
      display:flex;align-items:center;justify-content:center;
      font-size:28px;margin:0 auto 18px;
      box-shadow:0 16px 40px rgba(59,130,246,.35);
    }
    h1{
      text-align:center;
      font-size:24px;
      font-weight:800;
      margin-bottom:6px;
    }
    .sub{
      text-align:center;
      color:var(--muted);
      font-size:13px;
      margin-bottom:28px;
    }
    .err{
      background:rgba(239,68,68,.12);
      border:1px solid rgba(239,68,68,.28);
      color:#fecaca;
      border-radius:12px;
      padding:12px 14px;
      margin-bottom:16px;
      font-size:13px;
    }
    label{
      display:block;
      font-size:11px;
      font-weight:700;
      letter-spacing:.12em;
      color:var(--muted);
      margin-bottom:8px;
      text-transform:uppercase;
    }
    input{
      width:100%;
      background:rgba(255,255,255,.04);
      border:1px solid var(--line);
      color:var(--text);
      border-radius:14px;
      padding:14px 16px;
      font-size:14px;
      outline:none;
      margin-bottom:16px;
      transition:.2s;
    }
    input:focus{
      border-color:var(--blue);
      box-shadow:0 0 0 4px rgba(59,130,246,.14);
    }
    button{
      width:100%;
      border:none;
      border-radius:14px;
      padding:14px 16px;
      background:linear-gradient(135deg,var(--blue),#2563eb);
      color:#fff;
      font-size:14px;
      font-weight:700;
      cursor:pointer;
      box-shadow:0 16px 34px rgba(37,99,235,.28);
      transition:.2s;
    }
    button:hover{transform:translateY(-1px)}
  </style>
</head>
<body>
  <div class="shell">
    <div class="logo">🔐</div>
    <h1>Gazi Medya</h1>
    <div class="sub">Lisans Yönetim Paneli</div>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <form method="POST">
      <label>Kullanıcı Adı</label>
      <input name="username" autocomplete="username" required autofocus>
      <label>Şifre</label>
      <input name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Giriş Yap</button>
    </form>
  </div>
</body>
</html>"""

"""

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"Gazi Medya Lisans Paneli basliyor - port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
