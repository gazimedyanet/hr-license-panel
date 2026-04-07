from flask import Flask, request, jsonify, render_template_string, redirect, session
import sqlite3, hashlib, hmac, os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = "GaziMediaPanelSecret2026"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "licenses.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT UNIQUE NOT NULL, hw_id TEXT NOT NULL,
        product TEXT DEFAULT 'gazi-hr',
        customer_name TEXT, customer_email TEXT, customer_phone TEXT,
        issued_at TEXT DEFAULT CURRENT_TIMESTAMP, expires_at TEXT NOT NULL,
        is_revoked INTEGER DEFAULT 0, revoke_reason TEXT,
        last_seen TEXT, verify_count INTEGER DEFAULT 0, notes TEXT,
        package TEXT DEFAULT 'enterprise')""")
    for col, dflt in [("package","'enterprise'"), ("product","'gazi-hr'")]:
        try:
            conn.execute(f"ALTER TABLE licenses ADD COLUMN {col} TEXT DEFAULT {dflt}")
            conn.commit()
        except:
            pass
    conn.execute("""CREATE TABLE IF NOT EXISTS admin_settings (
        key TEXT PRIMARY KEY, value TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT, detail TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    existing = conn.execute("SELECT value FROM admin_settings WHERE key='admin_pass_hash'").fetchone()
    if not existing:
        h = hashlib.sha256("GaziMedia2026!".encode()).hexdigest()
        conn.execute("INSERT INTO admin_settings VALUES ('admin_pass_hash',?)", (h,))
        conn.execute("INSERT OR IGNORE INTO admin_settings VALUES ('admin_user','gazi')")
    conn.commit()
    conn.close()

init_db()

_K_HR  = [0x47,0x61,0x7a,0x69,0x4d,0x65,0x64,0x79,0x61,0x48,0x52,
          0x32,0x30,0x32,0x36,0x53,0x65,0x63,0x72,0x65,0x74,0x4b,
          0x65,0x79,0x5f,0x44,0x6f,0x4e,0x6f,0x74,0x53,0x68,0x61,0x72,0x65]

_K_ASC = [0x41,0x75,0x74,0x6f,0x53,0x65,0x72,0x76,0x69,0x73,0x43,
          0x52,0x4d,0x2d,0x32,0x30,0x32,0x35,0x2d,0x4c,0x69,0x63,
          0x4b,0x65,0x79,0x2d,0x47,0x61,0x7a,0x69]

_K_FT  = [70,105,121,97,116,84,101,107,108,105,102,105,45,69,84,65,
          45,65,110,97,108,105,116,105,107,45,50,48,50,54,45,76,105,99,75,101,121]

PRODUCTS = {
    'gazi-hr':        { 'prefix':'GMHR', 'key':_K_HR,  'label':'Gazi HR',        'color':'#3b82f6' },
    'autoservis-crm': { 'prefix':'ASC',  'key':_K_ASC, 'label':'AutoServis CRM', 'color':'#f97316' },
    'fiyat-teklifi':  { 'prefix':'FTK',  'key':_K_FT,  'label':'Fiyat Teklifi',  'color':'#10b981' },
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

def gen_key(hw_id: str, expires_at: str, product: str = 'gazi-hr') -> str:
    cfg = PRODUCTS.get(product, PRODUCTS['gazi-hr'])
    hw_hash = hashlib.sha256(hw_id.encode()).hexdigest()[:6].upper()
    ts = int(datetime.fromisoformat(expires_at).timestamp())
    r = _to_base36(ts)
    prefix = cfg['prefix']
    data   = f"{prefix}-{hw_hash}-{r}"
    chk    = _sign(cfg['key'], data)[:8].upper()
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

    if prefix != cfg['prefix']:
        return False, "Prefix eşleşmiyor"

    expected_hash = hashlib.sha256(hw_id.encode()).hexdigest()[:6].upper()
    if hw_hash != expected_hash:
        return False, "HW hash eşleşmiyor"

    expected_data = f"{cfg['prefix']}-{expected_hash}-{encoded_ts}"
    expected_checksum = _sign(cfg['key'], expected_data)[:8].upper()
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
        if not session.get('logged_in'):
            return redirect('/login')
        return f(*a, **k)
    return d

def _verify_core(key: str, hw: str, product: str):
    if product not in PRODUCTS:
        return None, {"valid": False, "message": "Bilinmeyen ürün"}

    conn = get_db()
    lic = conn.execute(
        "SELECT * FROM licenses WHERE license_key=? AND product=?",
        (key, product)
    ).fetchone()

    if not lic:
        conn.close()
        return None, {"valid": False, "message": "Lisans bulunamadı"}

    if lic['is_revoked']:
        conn.close()
        return None, {"valid": False, "message": f"İptal edildi: {lic['revoke_reason'] or ''}"}

    if lic['hw_id'].upper() != hw.upper():
        conn.close()
        return None, {"valid": False, "message": "Donanım eşleşmiyor"}

    exp = datetime.fromisoformat(lic['expires_at'])
    if datetime.now() > exp:
        conn.close()
        return None, {"valid": False, "message": f"Süresi doldu ({exp.strftime('%d.%m.%Y')})"}

    ok, math_message = validate_key_math(
        lic['license_key'],
        lic['hw_id'],
        lic['expires_at'],
        lic['product'] or product
    )
    if not ok:
        conn.close()
        return None, {"valid": False, "message": f"Lisans algoritması uyuşmuyor: {math_message}"}

    conn.execute(
        "UPDATE licenses SET last_seen=?,verify_count=verify_count+1 WHERE id=?",
        (datetime.now().isoformat(), lic['id'])
    )
    conn.commit()
    conn.close()

    days_left = (exp - datetime.now()).days
    return lic, {
        "valid": True,
        "expires": exp.strftime('%d.%m.%Y'),
        "customer": lic['customer_name'],
        "message": "Geçerli",
        "package": lic['package'] or 'enterprise',
        "days_left": days_left,
    }

@app.route('/api/hr-license', methods=['POST'])
def verify_hr():
    d = request.get_json(silent=True) or {}
    key = d.get('license_key','').strip().upper()
    hw  = d.get('hw_id','').strip()
    if d.get('product','') != 'gazi-hr':
        return jsonify({"valid": False, "message": "Bilinmeyen ürün"})
    _, result = _verify_core(key, hw, 'gazi-hr')
    return jsonify(result)

@app.route('/api/autoservis-license', methods=['POST'])
def verify_autoservis():
    d = request.get_json(silent=True) or {}
    key = d.get('license_key','').strip().upper()
    hw  = d.get('hw_id','').strip()
    if d.get('product','') != 'autoservis-crm':
        return jsonify({"valid": False, "message": "Bilinmeyen ürün"})
    _, result = _verify_core(key, hw, 'autoservis-crm')
    return jsonify(result)

@app.route('/api/fiyat-teklifi-license', methods=['POST'])
def verify_fiyat_teklifi():
    d = request.get_json(silent=True) or {}
    key = d.get('license_key','').strip().upper()
    hw  = d.get('hw_id','').strip()
    if d.get('product','') != 'fiyat-teklifi':
        return jsonify({"valid": False, "message": "Bilinmeyen ürün"})
    _, result = _verify_core(key, hw, 'fiyat-teklifi')
    return jsonify(result)

@app.route('/api/debug-license-math', methods=['POST'])
def debug_license_math():
    d = request.get_json(silent=True) or {}
    key = d.get('license_key', '').strip().upper()
    hw = d.get('hw_id', '').strip().upper()
    product = d.get('product', '').strip()
    expires_at = d.get('expires_at', '').strip()

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
