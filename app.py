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
        except: pass
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
    conn.commit(); conn.close()

init_db()

# ── İmzalama anahtarları ──────────────────────────────────
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

def gen_key(hw_id: str, expires_at: str, product: str = 'gazi-hr') -> str:
    cfg = PRODUCTS.get(product, PRODUCTS['gazi-hr'])
    hw_hash = hashlib.sha256(hw_id.encode()).hexdigest()[:6].upper()
    ts = int(datetime.fromisoformat(expires_at).timestamp())
    chars, n, r = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", ts, ""
    while n: r = chars[n % 36] + r; n //= 36
    prefix = cfg['prefix']
    data   = f"{prefix}-{hw_hash}-{r}"
    chk    = _sign(cfg['key'], data)[:8].upper()
    return f"{data}-{chk}"

def get_admin():
    conn = get_db()
    u = conn.execute("SELECT value FROM admin_settings WHERE key='admin_user'").fetchone()
    p = conn.execute("SELECT value FROM admin_settings WHERE key='admin_pass_hash'").fetchone()
    conn.close()
    return (u[0] if u else "gazi"), (p[0] if p else "")

def log(action, detail=""):
    conn = get_db()
    conn.execute("INSERT INTO audit_log (action,detail) VALUES (?,?)", (action, detail))
    conn.commit(); conn.close()

def auth(f):
    @wraps(f)
    def d(*a, **k):
        if not session.get('logged_in'): return redirect('/login')
        return f(*a, **k)
    return d

# ── Auth rotaları ─────────────────────────────────────────
@app.route('/login', methods=['GET','POST'])
def login():
    err = ''
    if request.method == 'POST':
        admin_user, admin_hash = get_admin()
        given = hashlib.sha256(request.form.get('password','').encode()).hexdigest()
        if request.form.get('username','') == admin_user and given == admin_hash:
            session['logged_in'] = True
            log('GİRİŞ', f"Kullanıcı: {admin_user}")
            return redirect('/')
        err = 'Kullanıcı adı veya şifre hatalı'
        log('BAŞARISIZ GİRİŞ')
    return render_template_string(LOGIN_HTML, error=err)

@app.route('/logout')
def logout():
    log('ÇIKIŞ'); session.clear(); return redirect('/login')

@app.route('/change-password', methods=['GET','POST'])
@auth
def change_password():
    msg = err = ''
    if request.method == 'POST':
        _, admin_hash = get_admin()
        cur  = request.form.get('current','')
        new  = request.form.get('new_pass','')
        conf = request.form.get('confirm','')
        if hashlib.sha256(cur.encode()).hexdigest() != admin_hash:
            err = 'Mevcut şifre hatalı'
        elif len(new) < 8:
            err = 'Yeni şifre en az 8 karakter olmalı'
        elif new != conf:
            err = 'Şifreler eşleşmiyor'
        else:
            conn = get_db()
            conn.execute("UPDATE admin_settings SET value=? WHERE key='admin_pass_hash'",
                         (hashlib.sha256(new.encode()).hexdigest(),))
            conn.commit(); conn.close()
            log('ŞİFRE DEĞİŞTİRİLDİ')
            msg = 'Şifre başarıyla güncellendi'
    return render_template_string(CHANGE_PASS_HTML, msg=msg, err=err)

# ── Panel ─────────────────────────────────────────────────
@app.route('/')
@auth
def index():
    conn = get_db()
    prod_filter = request.args.get('product', 'all')
    if prod_filter != 'all':
        licenses = conn.execute("SELECT * FROM licenses WHERE product=? ORDER BY issued_at DESC", (prod_filter,)).fetchall()
    else:
        licenses = conn.execute("SELECT * FROM licenses ORDER BY issued_at DESC").fetchall()
    now  = datetime.now().isoformat()
    soon = (datetime.now() + timedelta(days=30)).isoformat()
    stats = {
        'total':    conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        'active':   conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=0 AND expires_at>?", (now,)).fetchone()[0],
        'expired':  conn.execute("SELECT COUNT(*) FROM licenses WHERE expires_at<? AND is_revoked=0", (now,)).fetchone()[0],
        'revoked':  conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=1").fetchone()[0],
        'expiring': conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=0 AND expires_at>? AND expires_at<?", (now,soon)).fetchone()[0],
        'hr_count':  conn.execute("SELECT COUNT(*) FROM licenses WHERE product='gazi-hr'").fetchone()[0],
        'asc_count': conn.execute("SELECT COUNT(*) FROM licenses WHERE product='autoservis-crm'").fetchone()[0],
        'ft_count':  conn.execute("SELECT COUNT(*) FROM licenses WHERE product='fiyat-teklifi'").fetchone()[0],
    }
    logs = conn.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 25").fetchall()
    conn.close()
    return render_template_string(PANEL_HTML, licenses=licenses, stats=stats,
                                  now=now, logs=logs, products=PRODUCTS,
                                  prod_filter=prod_filter)

@app.route('/create', methods=['POST'])
@auth
def create():
    hw_id    = request.form.get('hw_id','').strip().upper()
    days     = int(request.form.get('days', 365))
    customer = request.form.get('customer_name','').strip()
    email    = request.form.get('customer_email','').strip()
    phone    = request.form.get('customer_phone','').strip()
    notes    = request.form.get('notes','').strip()
    package  = request.form.get('package', 'enterprise').strip()
    product  = request.form.get('product', 'gazi-hr').strip()
    if product not in PRODUCTS: product = 'gazi-hr'
    if not hw_id: return "Donanım ID gerekli", 400
    expires = (datetime.now() + timedelta(days=days)).isoformat()
    key = gen_key(hw_id, expires, product)
    conn = get_db()
    try:
        conn.execute("""INSERT INTO licenses
            (license_key,hw_id,product,customer_name,customer_email,customer_phone,expires_at,notes,package)
            VALUES(?,?,?,?,?,?,?,?,?)""", (key,hw_id,product,customer,email,phone,expires,notes,package))
        conn.commit()
        log('LİSANS OLUŞTURULDU', f'{customer} | {PRODUCTS[product]["label"]} | {expires[:10]}')
    except sqlite3.IntegrityError:
        conn.close()
        return "<script>alert('Bu HW ID + ürün kombinasyonu için zaten lisans var!');history.back()</script>"
    conn.close(); return redirect('/')

@app.route('/extend/<int:lid>', methods=['POST'])
@auth
def extend(lid):
    days = int(request.form.get('days', 365))
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    if lic:
        cur = datetime.fromisoformat(lic['expires_at'])
        if cur < datetime.now(): cur = datetime.now()
        new_exp = cur + timedelta(days=days)
        product = lic['product'] or 'gazi-hr'
        new_key = gen_key(lic['hw_id'], new_exp.isoformat(), product)
        conn.execute("UPDATE licenses SET license_key=?,expires_at=?,is_revoked=0 WHERE id=?",
                     (new_key, new_exp.isoformat(), lid))
        conn.commit()
        log('LİSANS UZATILDI', f'ID:{lid} | {lic["customer_name"]} | +{days}g → {new_exp.strftime("%d.%m.%Y")}')
    conn.close(); return redirect('/')

@app.route('/revoke/<int:lid>', methods=['POST'])
@auth
def revoke(lid):
    reason = request.form.get('reason','')
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    conn.execute("UPDATE licenses SET is_revoked=1,revoke_reason=? WHERE id=?", (reason,lid))
    conn.commit(); conn.close()
    log('LİSANS İPTAL', f'ID:{lid} | {lic["customer_name"] if lic else ""} | {reason}')
    return redirect('/')

@app.route('/restore/<int:lid>', methods=['POST'])
@auth
def restore(lid):
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    conn.execute("UPDATE licenses SET is_revoked=0,revoke_reason=NULL WHERE id=?", (lid,))
    conn.commit(); conn.close()
    log('LİSANS AKTİFLEŞTİRİLDİ', f'ID:{lid} | {lic["customer_name"] if lic else ""}')
    return redirect('/')

@app.route('/edit/<int:lid>', methods=['POST'])
@auth
def edit(lid):
    conn = get_db()
    pkg = request.form.get('package', 'enterprise')
    conn.execute("UPDATE licenses SET customer_name=?,customer_email=?,customer_phone=?,notes=?,package=? WHERE id=?",
                 (request.form.get('customer_name',''), request.form.get('customer_email',''),
                  request.form.get('customer_phone',''), request.form.get('notes',''), pkg, lid))
    conn.commit(); conn.close()
    log('LİSANS DÜZENLENDİ', f'ID:{lid} | Paket: {pkg}')
    return redirect('/')

@app.route('/delete/<int:lid>', methods=['POST'])
@auth
def delete(lid):
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    conn.execute("DELETE FROM licenses WHERE id=?", (lid,))
    conn.commit(); conn.close()
    log('LİSANS SİLİNDİ', f'ID:{lid} | {lic["customer_name"] if lic else ""}')
    return redirect('/')

# ══════════════════════════════════════════════════════════
# API ENDPOINTLERİ
# ══════════════════════════════════════════════════════════

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
    conn.execute("UPDATE licenses SET last_seen=?,verify_count=verify_count+1 WHERE id=?",
                 (datetime.now().isoformat(), lic['id']))
    conn.commit(); conn.close()
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
    d   = request.get_json(silent=True) or {}
    key = d.get('license_key','').strip().upper()
    hw  = d.get('hw_id','').strip()
    if d.get('product','') != 'gazi-hr':
        return jsonify({"valid": False, "message": "Bilinmeyen ürün"})
    _, result = _verify_core(key, hw, 'gazi-hr')
    return jsonify(result)

@app.route('/api/autoservis-license', methods=['POST'])
def verify_autoservis():
    d   = request.get_json(silent=True) or {}
    key = d.get('license_key','').strip().upper()
    hw  = d.get('hw_id','').strip()
    if d.get('product','') != 'autoservis-crm':
        return jsonify({"valid": False, "message": "Bilinmeyen ürün"})
    _, result = _verify_core(key, hw, 'autoservis-crm')
    return jsonify(result)

@app.route('/api/fiyat-teklifi-license', methods=['POST'])
def verify_fiyat_teklifi():
    d   = request.get_json(silent=True) or {}
    key = d.get('license_key','').strip().upper()
    hw  = d.get('hw_id','').strip()
    if d.get('product','') != 'fiyat-teklifi':
        return jsonify({"valid": False, "message": "Bilinmeyen ürün"})
    _, result = _verify_core(key, hw, 'fiyat-teklifi')
    return jsonify(result)


# ══════════════════════════════════════════════════════════
# HTML ŞABLONLAR
# ══════════════════════════════════════════════════════════

LOGIN_HTML = """<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gazi Medya — Giriş</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#080c18;--sur:#111827;--bor:#1e2a3a;--acc:#3b82f6;--a2:#06b6d4;
      --tx:#e2e8f0;--t2:#94a3b8;--t3:#64748b;--red:#ef4444}
body{background:var(--bg);min-height:100vh;display:flex;align-items:center;
  justify-content:center;font-family:'Segoe UI',system-ui,sans-serif;color:var(--tx)}
body::before{content:'';position:fixed;inset:0;pointer-events:none;
  background:radial-gradient(ellipse 80% 60% at 50% -10%,rgba(59,130,246,.12),transparent),
             radial-gradient(ellipse 50% 40% at 80% 100%,rgba(6,182,212,.08),transparent)}
.box{background:var(--sur);border:1px solid var(--bor);border-radius:16px;
  padding:44px;width:400px;box-shadow:0 24px 60px rgba(0,0,0,.5);position:relative;z-index:1}
.icon{width:52px;height:52px;background:linear-gradient(135deg,var(--acc),var(--a2));
  border-radius:14px;display:flex;align-items:center;justify-content:center;
  font-size:24px;margin:0 auto 16px}
h1{text-align:center;font-size:20px;font-weight:700;margin-bottom:4px}
.sub{text-align:center;color:var(--t2);font-size:13px;margin-bottom:32px}
label{display:block;font-size:11px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px}
input{width:100%;background:rgba(255,255,255,.04);border:1px solid var(--bor);border-radius:8px;
  padding:11px 14px;font-size:14px;color:var(--tx);outline:none;transition:.2s;font-family:inherit;margin-bottom:16px}
input:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(59,130,246,.1)}
.btn{width:100%;padding:12px;background:linear-gradient(135deg,var(--acc),#2563eb);border:none;
  border-radius:8px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;transition:.2s}
.btn:hover{transform:translateY(-1px);box-shadow:0 8px 20px rgba(59,130,246,.3)}
.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;
  font-size:13px;padding:10px 14px;border-radius:8px;margin-bottom:16px;text-align:center}
</style></head><body>
<div class="box">
  <div class="icon">🔐</div>
  <h1>Gazi Medya</h1>
  <div class="sub">Lisans Yönetim Paneli</div>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="POST">
    <label>Kullanıcı Adı</label>
    <input name="username" autocomplete="username" required autofocus>
    <label>Şifre</label>
    <input name="password" type="password" autocomplete="current-password" required>
    <button type="submit" class="btn">Giriş Yap →</button>
  </form>
</div></body></html>"""

CHANGE_PASS_HTML = """<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Şifre Değiştir</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#080c18;--nav:#0c1220;--sur:#111827;--bor:#1e2a3a;--b2:#253347;
      --acc:#3b82f6;--a2:#06b6d4;--tx:#e2e8f0;--t2:#94a3b8;--t3:#64748b}
body{background:var(--bg);min-height:100vh;font-family:'Segoe UI',system-ui,sans-serif;color:var(--tx)}
nav{background:var(--nav);border-bottom:1px solid var(--bor);padding:0 28px;display:flex;align-items:center;height:58px;gap:12px}
.nav-icon{width:30px;height:30px;background:linear-gradient(135deg,var(--acc),var(--a2));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:14px}
.nav-title{font-size:15px;font-weight:700}.nav-sep{color:var(--bor);margin:0 2px}.nav-sub{color:var(--t3);font-size:13px}
.nav-right{margin-left:auto;display:flex;gap:8px}
.nav-btn{padding:6px 14px;border-radius:7px;border:1px solid var(--bor);color:var(--t2);background:transparent;
  text-decoration:none;font-size:12px;font-weight:500;font-family:inherit;cursor:pointer;transition:.15s}
.nav-btn:hover{color:var(--tx);border-color:var(--b2);background:var(--sur)}
.wrap{max-width:480px;margin:40px auto;padding:0 20px}
.ph{margin-bottom:24px}.ph h1{font-size:22px;font-weight:800}.ph p{color:var(--t2);font-size:13px;margin-top:4px}
.card{background:var(--sur);border:1px solid var(--bor);border-radius:12px;padding:28px}
label{display:block;font-size:11px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px}
input{width:100%;background:rgba(255,255,255,.03);border:1px solid var(--bor);border-radius:8px;padding:10px 13px;
  font-size:13px;color:var(--tx);outline:none;transition:.2s;font-family:inherit;margin-bottom:14px}
input:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(59,130,246,.1)}
.btn{padding:10px 20px;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;
  background:linear-gradient(135deg,var(--acc),#2563eb);color:#fff}
.ok{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.2);color:#34d399;padding:12px;border-radius:8px;margin-bottom:16px;font-size:13px}
.er{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);color:#f87171;padding:12px;border-radius:8px;margin-bottom:16px;font-size:13px}
</style></head><body>
<nav>
  <div class="nav-icon">🔐</div><span class="nav-title">Gazi Medya</span>
  <span class="nav-sep">/</span><span class="nav-sub">Lisans Paneli</span>
  <div class="nav-right"><a href="/" class="nav-btn">← Panele Dön</a><a href="/logout" class="nav-btn">Çıkış</a></div>
</nav>
<div class="wrap">
  <div class="ph"><h1>Şifre Değiştir</h1><p>Panel giriş şifrenizi güncelleyin</p></div>
  <div class="card">
    {% if msg %}<div class="ok">✓ {{ msg }}</div>{% endif %}
    {% if err %}<div class="er">✗ {{ err }}</div>{% endif %}
    <form method="POST">
      <label>Mevcut Şifre</label><input type="password" name="current" required placeholder="••••••••">
      <label>Yeni Şifre (min. 8 karakter)</label><input type="password" name="new_pass" required minlength="8" placeholder="Yeni şifre">
      <label>Yeni Şifre Tekrar</label><input type="password" name="confirm" required placeholder="Tekrar girin">
      <button type="submit" class="btn">Şifreyi Güncelle →</button>
    </form>
  </div>
</div></body></html>"""


PANEL_HTML = """<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gazi Medya — Lisans Paneli</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#080c18;--nav:#0c1220;--sur:#111827;--s2:#161f30;--s3:#1c2a40;
      --bor:#1e2a3a;--b2:#253347;--b3:#2d4060;
      --acc:#3b82f6;--a2:#06b6d4;--asc:#f97316;--ft:#10b981;
      --tx:#e2e8f0;--t2:#94a3b8;--t3:#64748b;
      --green:#10b981;--red:#ef4444;--amber:#f59e0b;--purple:#8b5cf6}
body{background:var(--bg);min-height:100vh;font-family:'Segoe UI',system-ui,sans-serif;color:var(--tx);font-size:13px}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(ellipse 70% 50% at 50% -5%,rgba(59,130,246,.1),transparent),
             radial-gradient(ellipse 40% 30% at 90% 90%,rgba(249,115,22,.06),transparent)}
nav{background:var(--nav);border-bottom:1px solid var(--bor);padding:0 28px;display:flex;align-items:center;
  height:58px;position:sticky;top:0;z-index:200;gap:10px}
.nav-icon{width:30px;height:30px;background:linear-gradient(135deg,var(--acc),var(--a2));border-radius:8px;
  display:flex;align-items:center;justify-content:center;font-size:14px}
.nav-title{font-size:15px;font-weight:700}.nav-sep{color:var(--bor)}.nav-sub{color:var(--t3);font-size:13px}
.nav-right{margin-left:auto;display:flex;gap:8px;align-items:center}
.nav-btn{padding:6px 14px;border-radius:7px;border:1px solid var(--bor);color:var(--t2);background:transparent;
  text-decoration:none;font-size:12px;font-weight:500;font-family:inherit;cursor:pointer;transition:.15s}
.nav-btn:hover{color:var(--tx);border-color:var(--b2);background:var(--s2)}
.wrap{max-width:1500px;margin:0 auto;padding:24px 28px;position:relative;z-index:1}
.alert{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);border-radius:10px;
  padding:12px 16px;margin-bottom:18px;display:flex;align-items:center;gap:10px;color:#fbbf24;font-size:13px}
.alert b{background:rgba(245,158,11,.15);padding:2px 8px;border-radius:20px;margin-left:auto}
.prod-tabs{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.prod-tab{display:flex;align-items:center;gap:8px;padding:10px 18px;border-radius:10px;border:1px solid var(--bor);
  color:var(--t2);background:var(--sur);text-decoration:none;font-size:13px;font-weight:600;transition:.15s}
.prod-tab:hover{border-color:var(--b2);color:var(--tx)}
.prod-tab.hr.on{border-color:var(--acc);color:var(--acc);background:rgba(59,130,246,.08)}
.prod-tab.asc.on{border-color:var(--asc);color:var(--asc);background:rgba(249,115,22,.08)}
.prod-tab.ft.on{border-color:var(--ft);color:var(--ft);background:rgba(16,185,129,.08)}
.prod-tab.all.on{border-color:var(--green);color:var(--green);background:rgba(16,185,129,.08)}
.prod-cnt{font-size:11px;padding:1px 7px;border-radius:20px;font-family:monospace}
.prod-tab.hr .prod-cnt{background:rgba(59,130,246,.15);color:#93c5fd}
.prod-tab.asc .prod-cnt{background:rgba(249,115,22,.15);color:#fdba74}
.prod-tab.ft .prod-cnt{background:rgba(16,185,129,.15);color:#6ee7b7}
.prod-tab.all .prod-cnt{background:rgba(16,185,129,.15);color:#6ee7b7}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}
.stat{background:var(--sur);border:1px solid var(--bor);border-radius:12px;padding:18px 20px;transition:.2s}
.stat:hover{border-color:var(--b2);transform:translateY(-2px)}
.stat-num{font-size:32px;font-weight:800;letter-spacing:-1px;line-height:1;margin-bottom:6px}
.stat-lbl{font-size:10.5px;color:var(--t2);text-transform:uppercase;letter-spacing:.8px;font-weight:600;
  display:flex;align-items:center;gap:6px}
.sdot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.card{background:var(--sur);border:1px solid var(--bor);border-radius:12px;margin-bottom:18px;overflow:hidden}
.card-head{padding:14px 20px;border-bottom:1px solid var(--bor);display:flex;align-items:center;gap:10px;background:var(--s2)}
.card-head h2{font-size:13px;font-weight:700}
.cnt{background:var(--s3);border:1px solid var(--b2);color:var(--t2);font-size:11px;padding:2px 9px;border-radius:20px;font-family:monospace}
.card-body{padding:18px 20px}
.fg3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px}
.field label{display:block;font-size:10.5px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.field input,.field select{width:100%;background:rgba(255,255,255,.03);border:1px solid var(--bor);border-radius:7px;
  padding:8px 11px;font-size:13px;color:var(--tx);outline:none;transition:.2s;font-family:inherit}
.field input:focus,.field select:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(59,130,246,.1)}
.field select option{background:var(--sur)}
.mono{font-family:monospace;letter-spacing:.5px}
.btn{display:inline-flex;align-items:center;gap:5px;padding:7px 14px;border:none;border-radius:7px;font-size:12px;
  font-weight:600;cursor:pointer;font-family:inherit;transition:.15s;white-space:nowrap}
.bp{background:linear-gradient(135deg,var(--acc),#2563eb);color:#fff}
.bp:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(59,130,246,.3)}
.bp-asc{background:linear-gradient(135deg,var(--asc),#ea580c);color:#fff}
.bp-asc:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(249,115,22,.3)}
.bp-ft{background:linear-gradient(135deg,#10b981,#059669);color:#fff}
.bp-ft:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(16,185,129,.3)}
.bg{background:rgba(16,185,129,.12);color:#34d399;border:1px solid rgba(16,185,129,.2)}
.bg:hover{background:rgba(16,185,129,.22)}
.bd{background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.2)}
.bd:hover{background:rgba(239,68,68,.22)}
.bw{background:rgba(245,158,11,.12);color:#fbbf24;border:1px solid rgba(245,158,11,.2)}
.bw:hover{background:rgba(245,158,11,.22)}
.bv{background:rgba(139,92,246,.12);color:#a78bfa;border:1px solid rgba(139,92,246,.2)}
.bv:hover{background:rgba(139,92,246,.22)}
.btn-sm{padding:5px 10px;font-size:11px}.btn-xs{padding:3px 8px;font-size:11px}
.tbl{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
thead th{padding:9px 12px;text-align:left;font-size:10px;font-weight:700;color:var(--t3);
  text-transform:uppercase;letter-spacing:.8px;background:var(--s2);border-bottom:1px solid var(--bor);white-space:nowrap}
tbody tr{border-bottom:1px solid rgba(30,42,58,.4);transition:.1s}
tbody tr:hover{background:rgba(255,255,255,.015)}
tbody tr:last-child{border-bottom:none}
td{padding:10px 12px;vertical-align:middle}
.kbox{display:inline-flex;align-items:center;gap:5px;background:rgba(255,255,255,.04);border:1px solid var(--bor);
  border-radius:5px;padding:4px 9px;cursor:pointer;transition:.15s;max-width:240px;font-family:monospace;font-size:11px;color:var(--t2)}
.kbox:hover{border-color:var(--acc);color:var(--tx);background:rgba(59,130,246,.06)}
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:20px;font-size:10px;font-weight:700}
.ba{background:rgba(16,185,129,.1);color:#34d399;border:1px solid rgba(16,185,129,.2)}
.br{background:rgba(239,68,68,.1);color:#f87171;border:1px solid rgba(239,68,68,.2)}
.bo{background:rgba(245,158,11,.1);color:#fbbf24;border:1px solid rgba(245,158,11,.2)}
.bdot{width:4px;height:4px;border-radius:50%;background:currentColor}
.prod-badge-hr{background:rgba(59,130,246,.12);color:#93c5fd;border:1px solid rgba(59,130,246,.2);
  padding:3px 8px;border-radius:20px;font-size:10px;font-weight:700}
.prod-badge-asc{background:rgba(249,115,22,.12);color:#fdba74;border:1px solid rgba(249,115,22,.2);
  padding:3px 8px;border-radius:20px;font-size:10px;font-weight:700}
.prod-badge-ft{background:rgba(16,185,129,.12);color:#6ee7b7;border:1px solid rgba(16,185,129,.2);
  padding:3px 8px;border-radius:20px;font-size:10px;font-weight:700}
.acts{display:flex;gap:4px;flex-wrap:wrap;align-items:center}
.sbar{display:flex;align-items:center;gap:8px;padding:12px 20px;border-bottom:1px solid var(--bor);background:var(--s2)}
.sbar input{flex:1;background:rgba(255,255,255,.03);border:1px solid var(--bor);border-radius:7px;
  padding:7px 13px;font-size:13px;color:var(--tx);outline:none;font-family:inherit}
.sbar input:focus{border-color:var(--acc)}
.ftabs{display:flex;gap:3px}
.ftab{padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;
  border:1px solid transparent;color:var(--t3);background:transparent;font-family:inherit;transition:.15s}
.ftab:hover,.ftab.on{background:var(--s3);border-color:var(--b2);color:var(--tx)}
.loglist{display:flex;flex-direction:column}
.logrow{display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid rgba(30,42,58,.3);font-size:11.5px}
.logrow:last-child{border-bottom:none}
.logt{font-family:monospace;font-size:10.5px;color:var(--t3);white-space:nowrap;min-width:125px}
.loga{font-weight:700;font-size:10px;padding:2px 7px;border-radius:4px;background:rgba(59,130,246,.1);color:#93c5fd;white-space:nowrap}
.logd{color:var(--t2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:1000;align-items:center;justify-content:center}
.modal.open{display:flex}
.mbox{background:var(--s2);border:1px solid var(--b2);border-radius:13px;padding:24px;width:320px;box-shadow:0 20px 48px rgba(0,0,0,.6)}
.mhead{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.mhead h3{font-size:14px;font-weight:700}
.mhead button{background:none;border:none;color:var(--t2);font-size:18px;cursor:pointer;line-height:1;padding:0 3px}
.mhead button:hover{color:var(--tx)}
.mbox label{display:block;font-size:10.5px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.mbox input,.mbox select{width:100%;background:rgba(255,255,255,.04);border:1px solid var(--bor);border-radius:7px;
  padding:8px 11px;font-size:13px;color:var(--tx);outline:none;margin-bottom:12px;font-family:inherit}
.mbox input:focus,.mbox select:focus{border-color:var(--acc)}
.mbox .btn{width:100%;justify-content:center;padding:10px}
#toast{position:fixed;bottom:20px;right:20px;display:flex;align-items:center;gap:7px;
  background:rgba(16,185,129,.9);backdrop-filter:blur(8px);color:#fff;padding:10px 16px;
  border-radius:9px;font-size:13px;font-weight:600;opacity:0;transform:translateY(6px);
  transition:.3s;pointer-events:none;z-index:9999}
#toast.show{opacity:1;transform:translateY(0)}
.prod-select{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.ps-opt{flex:1;min-width:140px;display:flex;align-items:center;gap:8px;padding:10px 14px;
  border:2px solid var(--bor);border-radius:9px;cursor:pointer;background:var(--s2);transition:.15s;user-select:none}
.ps-opt input[type=radio]{width:14px;height:14px}
.ps-opt:has(input:checked).hr{border-color:var(--acc);background:rgba(59,130,246,.07)}
.ps-opt:has(input:checked).asc{border-color:var(--asc);background:rgba(249,115,22,.07)}
.ps-opt:has(input:checked).ft{border-color:var(--ft);background:rgba(16,185,129,.07)}
.ps-name{font-size:13px;font-weight:700}.ps-sub{font-size:11px;color:var(--t3);margin-top:1px}
@media(max-width:900px){.stats{grid-template-columns:repeat(2,1fr)}.fg3{grid-template-columns:1fr}}
</style></head><body>

<nav>
  <div class="nav-icon">🔐</div>
  <span class="nav-title">Gazi Medya</span>
  <span class="nav-sep">/</span>
  <span class="nav-sub">Lisans Paneli</span>
  <div class="nav-right">
    <a href="/change-password" class="nav-btn">🔑 Şifre Değiştir</a>
    <a href="/logout" class="nav-btn">Çıkış →</a>
  </div>
</nav>

<div class="wrap">
  {% if stats.expiring > 0 %}
  <div class="alert">
    <span>⚠️</span>
    <span>30 gün içinde sona erecek lisanslar var — müşterilere bildirin.</span>
    <b>{{ stats.expiring }} lisans</b>
  </div>
  {% endif %}

  <div class="prod-tabs">
    <a href="/?product=all" class="prod-tab all {{ 'on' if prod_filter=='all' else '' }}">
      📦 Tümü <span class="prod-cnt">{{stats.total}}</span>
    </a>
    <a href="/?product=gazi-hr" class="prod-tab hr {{ 'on' if prod_filter=='gazi-hr' else '' }}">
      👥 Gazi HR <span class="prod-cnt">{{stats.hr_count}}</span>
    </a>
    <a href="/?product=autoservis-crm" class="prod-tab asc {{ 'on' if prod_filter=='autoservis-crm' else '' }}">
      🔧 AutoServis CRM <span class="prod-cnt">{{stats.asc_count}}</span>
    </a>
    <a href="/?product=fiyat-teklifi" class="prod-tab ft {{ 'on' if prod_filter=='fiyat-teklifi' else '' }}">
      📊 Fiyat Teklifi <span class="prod-cnt">{{stats.ft_count}}</span>
    </a>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-num" style="color:var(--acc)">{{stats.total}}</div>
      <div class="stat-lbl"><span class="sdot" style="background:var(--acc)"></span>Toplam</div></div>
    <div class="stat"><div class="stat-num" style="color:var(--green)">{{stats.active}}</div>
      <div class="stat-lbl"><span class="sdot" style="background:var(--green)"></span>Aktif</div></div>
    <div class="stat"><div class="stat-num" style="color:var(--amber)">{{stats.expiring}}</div>
      <div class="stat-lbl"><span class="sdot" style="background:var(--amber)"></span>30g İçinde Dolacak</div></div>
    <div class="stat"><div class="stat-num" style="color:var(--red)">{{stats.expired}}</div>
      <div class="stat-lbl"><span class="sdot" style="background:var(--red)"></span>Süresi Dolmuş</div></div>
    <div class="stat"><div class="stat-num" style="color:var(--t3)">{{stats.revoked}}</div>
      <div class="stat-lbl"><span class="sdot" style="background:var(--t3)"></span>İptal</div></div>
  </div>

  <div class="card">
    <div class="card-head"><h2>＋ Yeni Lisans Oluştur</h2></div>
    <div class="card-body">
      <form method="POST" action="/create" id="createForm">
        <div style="margin-bottom:14px">
          <div style="font-size:10.5px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">Ürün *</div>
          <div class="prod-select">
            <label class="ps-opt hr">
              <input type="radio" name="product" value="gazi-hr" checked onchange="onProdChange(this)">
              <div><div class="ps-name">👥 Gazi HR</div><div class="ps-sub">Personel Yönetimi</div></div>
            </label>
            <label class="ps-opt asc">
              <input type="radio" name="product" value="autoservis-crm" onchange="onProdChange(this)">
              <div><div class="ps-name">🔧 AutoServis CRM</div><div class="ps-sub">Oto Servis Yönetimi</div></div>
            </label>
            <label class="ps-opt ft">
              <input type="radio" name="product" value="fiyat-teklifi" onchange="onProdChange(this)">
              <div><div class="ps-name">📊 Fiyat Teklifi</div><div class="ps-sub">ETA Analitik - Teklif Modülü</div></div>
            </label>
          </div>
        </div>
        <div class="fg3">
          <div class="field"><label>Donanım ID *</label>
            <input name="hw_id" class="mono" placeholder="AA:BB:CC:DD:EE:FF" required></div>
          <div class="field"><label>Müşteri / Firma Adı</label>
            <input name="customer_name" placeholder="ABC Kimya Ltd."></div>
          <div class="field"><label>Lisans Süresi</label>
            <select name="days">
              <option value="365">1 Yıl (365 gün)</option>
              <option value="730">2 Yıl (730 gün)</option>
              <option value="9999">Süresiz</option>
              <option value="30">30 Gün — Deneme</option>
              <option value="90">90 Gün</option>
              <option value="180">6 Ay</option>
            </select></div>
          <div class="field" id="pkg-field"><label>Paket</label>
            <select name="package">
              <option value="starter">🥉 Başlangıç</option>
              <option value="standard">🥈 Standart</option>
              <option value="enterprise" selected>🥇 Kurumsal / Tam</option>
            </select></div>
          <div class="field"><label>E-posta</label>
            <input name="customer_email" type="email" placeholder="info@firma.com"></div>
          <div class="field"><label>Telefon</label>
            <input name="customer_phone" placeholder="0212 000 00 00"></div>
          <div class="field"><label>Not / Sipariş No</label>
            <input name="notes" placeholder="Fatura no, ödeme tarihi..."></div>
        </div>
        <button type="submit" class="btn bp" id="createBtn">Lisans Oluştur →</button>
      </form>
    </div>
  </div>

  <div class="card">
    <div class="card-head"><h2>◈ Lisanslar</h2><span class="cnt">{{licenses|length}}</span></div>
    <div class="sbar">
      <input id="srch" placeholder="Müşteri, lisans anahtarı veya HW ID ara..." oninput="flt()">
      <div class="ftabs">
        <button class="ftab on" onclick="setF('all',this)">Tümü</button>
        <button class="ftab" onclick="setF('active',this)">Aktif</button>
        <button class="ftab" onclick="setF('expired',this)">Dolmuş</button>
        <button class="ftab" onclick="setF('revoked',this)">İptal</button>
      </div>
    </div>
    <div class="tbl">
      <table>
        <thead><tr>
          <th>#</th><th>Ürün</th><th>Müşteri</th><th>Paket</th>
          <th>Lisans Anahtarı</th><th>HW ID</th>
          <th>Son Geçerlilik</th><th>Son Görülme</th><th>Kullanım</th>
          <th>Durum</th><th>İşlemler</th>
        </tr></thead>
        <tbody>
        {% for l in licenses %}
        {% set is_exp = l.expires_at < now %}
        {% set status = 'revoked' if l.is_revoked else ('expired' if is_exp else 'active') %}
        {% set prod = l.product or 'gazi-hr' %}
        <tr data-s="{{ status }}"
            data-q="{{ ((l.customer_name or '') ~ ' ' ~ (l.customer_email or '') ~ ' ' ~ l.license_key ~ ' ' ~ l.hw_id)|lower }}">
          <td style="color:var(--t3);font-family:monospace">{{l.id}}</td>
          <td>
            {% if prod == 'autoservis-crm' %}<span class="prod-badge-asc">🔧 AutoServis</span>
            {% elif prod == 'fiyat-teklifi' %}<span class="prod-badge-ft">📊 Fiyat Teklifi</span>
            {% else %}<span class="prod-badge-hr">👥 Gazi HR</span>{% endif %}
          </td>
          <td>
            <div style="font-weight:600">{{l.customer_name or '—'}}</div>
            {% if l.customer_email %}<div style="font-size:11px;color:var(--t3)">{{l.customer_email}}</div>{% endif %}
            {% if l.customer_phone %}<div style="font-size:11px;color:var(--t3)">{{l.customer_phone}}</div>{% endif %}
          </td>
          <td>
            {% if l.package == 'starter' %}<span style="background:rgba(16,185,129,.1);color:#34d399;border:1px solid rgba(16,185,129,.2);padding:3px 8px;border-radius:20px;font-size:11px;font-weight:700">🥉 Başlangıç</span>
            {% elif l.package == 'standard' %}<span style="background:rgba(59,130,246,.1);color:#93c5fd;border:1px solid rgba(59,130,246,.2);padding:3px 8px;border-radius:20px;font-size:11px;font-weight:700">🥈 Standart</span>
            {% else %}<span style="background:rgba(245,158,11,.1);color:#fbbf24;border:1px solid rgba(245,158,11,.2);padding:3px 8px;border-radius:20px;font-size:11px;font-weight:700">🥇 Kurumsal</span>{% endif %}
          </td>
          <td><span class="kbox" onclick="cpKey('{{l.license_key}}')">{{l.license_key}} <span style="opacity:.4;font-size:9px">⌘</span></span></td>
          <td><span class="kbox" onclick="cpKey('{{l.hw_id}}')" style="max-width:180px">{{l.hw_id}} <span style="opacity:.4;font-size:9px">⌘</span></span></td>
          <td><div style="font-family:monospace;font-size:12px">{{l.expires_at[:10]}}</div></td>
          <td style="font-size:11px;color:var(--t3)">
            {% if l.last_seen %}{{l.last_seen[:10]}}<br>{{l.last_seen[11:16]}}{% else %}Henüz yok{% endif %}
          </td>
          <td style="text-align:center;font-family:monospace;color:var(--acc);font-weight:700">{{l.verify_count or 0}}</td>
          <td>
            {% if l.is_revoked %}<span class="badge br"><span class="bdot"></span>İptal</span>
            {% elif is_exp %}<span class="badge bo"><span class="bdot"></span>Doldu</span>
            {% else %}<span class="badge ba"><span class="bdot"></span>Aktif</span>{% endif %}
          </td>
          <td>
            <div class="acts">
              <button class="btn bg btn-sm" onclick="openM('uzat{{l.id}}')">Uzat</button>
              <button class="btn bv btn-sm" onclick="openM('duz{{l.id}}')">Düzenle</button>
              {% if not l.is_revoked %}
              <button class="btn bw btn-sm" onclick="openM('ipt{{l.id}}')">İptal</button>
              {% else %}
              <form method="POST" action="/restore/{{l.id}}" style="display:inline">
                <button type="submit" class="btn bg btn-sm">Aktifleştir</button>
              </form>{% endif %}
              <form method="POST" action="/delete/{{l.id}}" style="display:inline" onsubmit="return confirm('Kalıcı silinecek!')">
                <button type="submit" class="btn bd btn-xs">✕</button>
              </form>
            </div>
          </td>
        </tr>
        {% else %}
        <tr><td colspan="11" style="text-align:center;padding:48px;color:var(--t3)">
          <div style="font-size:24px;margin-bottom:8px">◈</div>Henüz lisans yok.
        </td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <div class="card-head"><h2>▸ Denetim Günlüğü</h2><span class="cnt">Son 25 işlem</span></div>
    <div class="card-body">
      <div class="loglist">
        {% for lg in logs %}
        <div class="logrow">
          <span class="logt">{{lg.created_at[:16].replace('T',' ')}}</span>
          <span class="loga">{{lg.action}}</span>
          <span class="logd">{{lg.detail or '—'}}</span>
        </div>
        {% else %}
        <div style="color:var(--t3);padding:10px 0">Henüz kayıt yok</div>
        {% endfor %}
      </div>
    </div>
  </div>
</div>

{% for l in licenses %}
<div id="uzat{{l.id}}" class="modal" onclick="if(event.target===this)closeM(this.id)">
  <div class="mbox">
    <div class="mhead"><h3>Süre Uzat</h3><button onclick="closeM('uzat{{l.id}}')">✕</button></div>
    <form method="POST" action="/extend/{{l.id}}">
      <label>Uzatma Süresi</label>
      <select name="days">
        <option value="365">+ 1 Yıl</option><option value="730">+ 2 Yıl</option>
        <option value="180">+ 6 Ay</option><option value="90">+ 90 Gün</option>
        <option value="30">+ 30 Gün</option>
      </select>
      <button type="submit" class="btn bg">Uzat →</button>
    </form>
  </div>
</div>
<div id="duz{{l.id}}" class="modal" onclick="if(event.target===this)closeM(this.id)">
  <div class="mbox">
    <div class="mhead"><h3>Düzenle</h3><button onclick="closeM('duz{{l.id}}')">✕</button></div>
    <form method="POST" action="/edit/{{l.id}}">
      <label>Müşteri Adı</label><input name="customer_name" value="{{l.customer_name or ''}}">
      <label>E-posta</label><input name="customer_email" value="{{l.customer_email or ''}}">
      <label>Telefon</label><input name="customer_phone" value="{{l.customer_phone or ''}}">
      <label>Not</label><input name="notes" value="{{l.notes or ''}}">
      <label>Paket</label>
      <select name="package" style="margin-bottom:12px">
        <option value="starter" {{'selected' if l.package=='starter' else ''}}>🥉 Başlangıç</option>
        <option value="standard" {{'selected' if l.package=='standard' else ''}}>🥈 Standart</option>
        <option value="enterprise" {{'selected' if not l.package or l.package=='enterprise' else ''}}>🥇 Kurumsal</option>
      </select>
      <button type="submit" class="btn bv">Kaydet →</button>
    </form>
  </div>
</div>
{% if not l.is_revoked %}
<div id="ipt{{l.id}}" class="modal" onclick="if(event.target===this)closeM(this.id)">
  <div class="mbox">
    <div class="mhead"><h3>Lisansı İptal Et</h3><button onclick="closeM('ipt{{l.id}}')">✕</button></div>
    <form method="POST" action="/revoke/{{l.id}}">
      <label>İptal Gerekçesi (opsiyonel)</label>
      <input name="reason" placeholder="Ödeme yapılmadı...">
      <button type="submit" class="btn bd">İptal Et →</button>
    </form>
  </div>
</div>
{% endif %}
{% endfor %}

<div id="toast">✓ Kopyalandı</div>

<script>
function openM(id){ document.getElementById(id).classList.add('open') }
function closeM(id){ document.getElementById(id).classList.remove('open') }
function cpKey(t){
  navigator.clipboard.writeText(t).then(()=>{
    var el=document.getElementById('toast')
    el.classList.add('show')
    setTimeout(()=>el.classList.remove('show'),2000)
  })
}
let cf='all'
function setF(f,btn){
  cf=f
  document.querySelectorAll('.ftab').forEach(b=>b.classList.remove('on'))
  btn.classList.add('on'); flt()
}
function flt(){
  var q=document.getElementById('srch').value.toLowerCase()
  document.querySelectorAll('tbody tr[data-s]').forEach(tr=>{
    var ms=cf==='all'||tr.dataset.s===cf
    var mq=!q||tr.dataset.q.includes(q)
    tr.style.display=ms&&mq?'':'none'
  })
}
function onProdChange(radio){
  var pkgField=document.getElementById('pkg-field')
  var btn=document.getElementById('createBtn')
  if(radio.value==='autoservis-crm'){
    pkgField.style.opacity='0.4'; pkgField.style.pointerEvents='none'
    btn.className='btn bp-asc'; btn.textContent='AutoServis Lisansı Oluştur →'
  } else if(radio.value==='fiyat-teklifi'){
    pkgField.style.opacity='0.4'; pkgField.style.pointerEvents='none'
    btn.className='btn bp-ft'; btn.textContent='Fiyat Teklifi Lisansı Oluştur →'
  } else {
    pkgField.style.opacity='1'; pkgField.style.pointerEvents=''
    btn.className='btn bp'; btn.textContent='Lisans Oluştur →'
  }
}
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') document.querySelectorAll('.modal.open').forEach(m=>m.classList.remove('open'))
})
</script>
</body></html>"""

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Gazi Medya Lisans Paneli — port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
