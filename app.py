# ============================================================================
# Gazi Medya — HR Lisans Yönetim Paneli v3
# Railway / gazimedya.net
# ============================================================================
from flask import Flask, request, jsonify, render_template_string, redirect, session, flash
import sqlite3, hashlib, hmac, json, os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'GaziMediaPanelSecret2026_v3')

DB_PATH  = os.environ.get('DB_PATH', 'licenses.db')
SIGN_KEY = os.environ.get('SIGN_KEY', 'GaziMediaHR2026SecretKey_DoNotShare')

# Admin bilgileri DB'den çekilir
DEFAULT_USER = os.environ.get('ADMIN_USER', 'gazi')
DEFAULT_PASS = os.environ.get('ADMIN_PASS', 'GaziMedia2026!')

# ── DB ────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT UNIQUE NOT NULL,
        hw_id TEXT NOT NULL,
        product TEXT DEFAULT 'gazi-hr',
        customer_name TEXT, customer_email TEXT, customer_phone TEXT,
        issued_at TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL,
        is_revoked INTEGER DEFAULT 0, revoke_reason TEXT,
        last_seen TEXT, verify_count INTEGER DEFAULT 0, notes TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS admin_settings (
        key TEXT PRIMARY KEY, value TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        detail TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    # Varsayılan admin şifresi (hash'li)
    existing = conn.execute("SELECT value FROM admin_settings WHERE key='admin_pass_hash'").fetchone()
    if not existing:
        h = hashlib.sha256(DEFAULT_PASS.encode()).hexdigest()
        conn.execute("INSERT INTO admin_settings VALUES ('admin_pass_hash',?)", (h,))
        conn.execute("INSERT OR IGNORE INTO admin_settings VALUES ('admin_user',?)", (DEFAULT_USER,))
    conn.commit()
    conn.close()

init_db()

# ── Yardımcı ──────────────────────────────────────────────────
def gen_key(hw_id, days=365):
    hw_hash = hashlib.sha256(hw_id.encode()).hexdigest()[:6].upper()
    ts = int((datetime.now() + timedelta(days=days)).timestamp())
    chars, n, r = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", ts, ""
    while n: r = chars[n % 36] + r; n //= 36
    data = f"GMHR-{hw_hash}-{r}"
    chk = hmac.new(SIGN_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()[:8].upper()
    return f"{data}-{chk}"

def log_action(action, detail=""):
    conn = get_db()
    conn.execute("INSERT INTO audit_log (action,detail) VALUES (?,?)", (action, detail))
    conn.commit(); conn.close()

def get_admin():
    conn = get_db()
    u = conn.execute("SELECT value FROM admin_settings WHERE key='admin_user'").fetchone()
    p = conn.execute("SELECT value FROM admin_settings WHERE key='admin_pass_hash'").fetchone()
    conn.close()
    return (u[0] if u else DEFAULT_USER), (p[0] if p else None)

def auth(f):
    @wraps(f)
    def d(*a, **k):
        if not session.get('logged_in'): return redirect('/login')
        return f(*a, **k)
    return d

def days_left(expires_at):
    try:
        exp = datetime.fromisoformat(expires_at)
        delta = (exp - datetime.now()).days
        return delta
    except: return -999

# ── Auth Routes ───────────────────────────────────────────────
@app.route('/login', methods=['GET','POST'])
def login():
    err = ''
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        admin_user, admin_hash = get_admin()
        given_hash = hashlib.sha256(password.encode()).hexdigest()
        if username == admin_user and given_hash == admin_hash:
            session['logged_in'] = True
            log_action('GİRİŞ', f'Kullanıcı: {username}')
            return redirect('/')
        err = 'Kullanıcı adı veya şifre hatalı'
        log_action('BAŞARISIZ GİRİŞ', f'Denenen: {username}')
    return render_template_string(LOGIN_HTML, error=err)

@app.route('/logout')
def logout():
    log_action('ÇIKIŞ')
    session.clear()
    return redirect('/login')

@app.route('/change-password', methods=['GET','POST'])
@auth
def change_password():
    msg, err = '', ''
    if request.method == 'POST':
        current = request.form.get('current','')
        new_pass = request.form.get('new_pass','')
        confirm  = request.form.get('confirm','')
        _, admin_hash = get_admin()
        if hashlib.sha256(current.encode()).hexdigest() != admin_hash:
            err = 'Mevcut şifre hatalı'
        elif len(new_pass) < 8:
            err = 'Yeni şifre en az 8 karakter olmalı'
        elif new_pass != confirm:
            err = 'Şifreler eşleşmiyor'
        else:
            new_hash = hashlib.sha256(new_pass.encode()).hexdigest()
            conn = get_db()
            conn.execute("UPDATE admin_settings SET value=? WHERE key='admin_pass_hash'", (new_hash,))
            conn.commit(); conn.close()
            log_action('ŞİFRE DEĞİŞTİRİLDİ')
            msg = 'Şifre başarıyla güncellendi'
    return render_template_string(CHANGE_PASS_HTML, msg=msg, err=err)

# ── Panel ─────────────────────────────────────────────────────
@app.route('/')
@auth
def index():
    conn = get_db()
    lics = conn.execute("SELECT * FROM licenses ORDER BY issued_at DESC").fetchall()
    now = datetime.now().isoformat()
    stats = {
        'total':   conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        'active':  conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=0 AND expires_at>?", (now,)).fetchone()[0],
        'expired': conn.execute("SELECT COUNT(*) FROM licenses WHERE expires_at<? AND is_revoked=0", (now,)).fetchone()[0],
        'revoked': conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=1").fetchone()[0],
    }
    # 30 gün içinde dolacaklar
    soon = (datetime.now() + timedelta(days=30)).isoformat()
    expiring_soon = conn.execute(
        "SELECT * FROM licenses WHERE is_revoked=0 AND expires_at>? AND expires_at<?",
        (now, soon)
    ).fetchall()
    # Son audit logları
    logs = conn.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 20").fetchall()
    conn.close()
    return render_template_string(PANEL_HTML, licenses=lics, stats=stats,
                                  now=now, expiring_soon=expiring_soon, logs=logs,
                                  days_left=days_left)

@app.route('/create', methods=['POST'])
@auth
def create():
    hw_id    = request.form.get('hw_id','').strip().upper()
    days     = int(request.form.get('days', 365))
    customer = request.form.get('customer_name','').strip()
    email    = request.form.get('customer_email','').strip()
    phone    = request.form.get('customer_phone','').strip()
    notes    = request.form.get('notes','').strip()
    if not hw_id: return "Donanım ID gerekli", 400
    key = gen_key(hw_id, days)
    exp = (datetime.now() + timedelta(days=days)).isoformat()
    conn = get_db()
    try:
        conn.execute("""INSERT INTO licenses
            (license_key,hw_id,customer_name,customer_email,customer_phone,expires_at,notes)
            VALUES(?,?,?,?,?,?,?)""",
            (key, hw_id, customer, email, phone, exp, notes))
        conn.commit()
        log_action('LİSANS OLUŞTURULDU', f'{customer} | {key}')
    except sqlite3.IntegrityError:
        conn.close()
        return "Bu donanım ID için zaten lisans var!", 400
    conn.close()
    return redirect('/')

@app.route('/revoke/<int:lid>', methods=['POST'])
@auth
def revoke(lid):
    reason = request.form.get('reason','')
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    conn.execute("UPDATE licenses SET is_revoked=1,revoke_reason=? WHERE id=?", (reason, lid))
    conn.commit(); conn.close()
    log_action('LİSANS İPTAL', f'ID:{lid} | {lic["customer_name"] if lic else ""} | {reason}')
    return redirect('/')

@app.route('/restore/<int:lid>', methods=['POST'])
@auth
def restore(lid):
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    conn.execute("UPDATE licenses SET is_revoked=0,revoke_reason=NULL WHERE id=?", (lid,))
    conn.commit(); conn.close()
    log_action('LİSANS AKTİFLEŞTİRİLDİ', f'ID:{lid} | {lic["customer_name"] if lic else ""}')
    return redirect('/')

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
        new_key = gen_key(lic['hw_id'], days)
        conn.execute("UPDATE licenses SET license_key=?,expires_at=?,is_revoked=0 WHERE id=?",
                     (new_key, new_exp.isoformat(), lid))
        conn.commit()
        log_action('LİSANS UZATILDI', f'ID:{lid} | {lic["customer_name"]} | +{days} gün → {new_exp.strftime("%d.%m.%Y")}')
    conn.close()
    return redirect('/')

@app.route('/edit/<int:lid>', methods=['POST'])
@auth
def edit(lid):
    conn = get_db()
    conn.execute("""UPDATE licenses SET customer_name=?,customer_email=?,
                    customer_phone=?,notes=? WHERE id=?""",
                 (request.form.get('customer_name',''),
                  request.form.get('customer_email',''),
                  request.form.get('customer_phone',''),
                  request.form.get('notes',''), lid))
    conn.commit(); conn.close()
    log_action('LİSANS DÜZENLENDI', f'ID:{lid}')
    return redirect('/')

@app.route('/delete/<int:lid>', methods=['POST'])
@auth
def delete(lid):
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    conn.execute("DELETE FROM licenses WHERE id=?", (lid,))
    conn.commit(); conn.close()
    log_action('LİSANS SİLİNDİ', f'ID:{lid} | {lic["customer_name"] if lic else ""}')
    return redirect('/')

@app.route('/api/stats')
@auth
def api_stats():
    conn = get_db()
    now = datetime.now().isoformat()
    return jsonify({
        'total':   conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        'active':  conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=0 AND expires_at>?", (now,)).fetchone()[0],
        'expired': conn.execute("SELECT COUNT(*) FROM licenses WHERE expires_at<? AND is_revoked=0", (now,)).fetchone()[0],
        'revoked': conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=1").fetchone()[0],
    })

# ── HR Doğrulama API ──────────────────────────────────────────
@app.route('/api/hr-license', methods=['POST'])
def verify():
    d = request.get_json(silent=True) or {}
    key = d.get('license_key','').strip().upper()
    hw  = d.get('hw_id','').strip()
    prod = d.get('product','')
    if prod != 'gazi-hr':
        return jsonify({"valid": False, "message": "Bilinmeyen ürün"}), 400
    conn = get_db()
    lic = conn.execute("SELECT * FROM licenses WHERE license_key=? AND product='gazi-hr'", (key,)).fetchone()
    if not lic:
        conn.close(); return jsonify({"valid": False, "message": "Lisans bulunamadı"})
    if lic['is_revoked']:
        conn.close(); return jsonify({"valid": False, "message": f"İptal edildi: {lic['revoke_reason'] or ''}"})
    if lic['hw_id'].upper() != hw.upper():
        conn.close(); return jsonify({"valid": False, "message": "Donanım eşleşmiyor"})
    exp = datetime.fromisoformat(lic['expires_at'])
    if datetime.now() > exp:
        conn.close(); return jsonify({"valid": False, "message": f"Süresi doldu ({exp.strftime('%d.%m.%Y')})"})
    conn.execute("UPDATE licenses SET last_seen=?,verify_count=verify_count+1 WHERE id=?",
                 (datetime.now().isoformat(), lic['id']))
    conn.commit(); conn.close()
    return jsonify({"valid": True, "expires": exp.strftime('%d.%m.%Y'),
                    "customer": lic['customer_name'], "message": "Geçerli"})


# ══════════════════════════════════════════════════════════════
# HTML ŞABLONLAR
# ══════════════════════════════════════════════════════════════

# ── Ortak CSS ─────────────────────────────────────────────────
BASE_CSS = """
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080c18;--nav:#0c1220;--surface:#111827;--s2:#161f30;--s3:#1c2a40;
  --border:#1e2a3a;--b2:#253347;--b3:#2d4060;
  --accent:#3b82f6;--a2:#06b6d4;--a3:#8b5cf6;
  --text:#e2e8f0;--t2:#94a3b8;--t3:#64748b;
  --green:#10b981;--red:#ef4444;--amber:#f59e0b;--purple:#8b5cf6;
}
body{background:var(--bg);min-height:100vh;font-family:'DM Sans',sans-serif;color:var(--text);line-height:1.5;font-size:14px}
body::before{content:'';position:fixed;inset:0;
  background:radial-gradient(ellipse 70% 50% at 50% -5%,rgba(59,130,246,.1),transparent),
             radial-gradient(ellipse 40% 30% at 90% 90%,rgba(6,182,212,.07),transparent);
  pointer-events:none;z-index:0}

/* NAV */
nav{background:var(--nav);border-bottom:1px solid var(--border);
  padding:0 32px;display:flex;align-items:center;height:60px;
  position:sticky;top:0;z-index:200;backdrop-filter:blur(16px)}
.nav-brand{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:700;letter-spacing:-.3px}
.nav-icon{width:32px;height:32px;background:linear-gradient(135deg,var(--accent),var(--a2));
  border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:15px}
.nav-sep{color:var(--border);margin:0 4px;font-size:18px}
.nav-subtitle{color:var(--t3);font-weight:400;font-size:13px}
.nav-right{display:flex;align-items:center;gap:8px;margin-left:auto}
.nav-btn{display:flex;align-items:center;gap:6px;padding:6px 14px;border-radius:7px;
  font-size:12px;font-weight:500;cursor:pointer;border:1px solid var(--border);
  color:var(--t2);background:transparent;text-decoration:none;font-family:inherit;transition:.15s}
.nav-btn:hover{border-color:var(--b2);color:var(--text);background:var(--s2)}
.nav-btn.primary{background:linear-gradient(135deg,var(--accent),#2563eb);color:#fff;border:none}
.nav-btn.primary:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(59,130,246,.3)}

/* WRAP */
.wrap{max-width:1500px;margin:0 auto;padding:28px 32px;position:relative;z-index:1}

/* ALERT BANNER */
.alert-banner{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);
  border-radius:10px;padding:12px 16px;margin-bottom:20px;
  display:flex;align-items:center;gap:10px;font-size:13px;color:#fbbf24}
.alert-banner .cnt{font-weight:700;background:rgba(245,158,11,.15);
  border-radius:20px;padding:2px 8px;margin-left:auto;font-size:12px}

/* STATS */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:20px 22px;transition:.2s;cursor:default;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;right:-20px;top:-20px;
  width:80px;height:80px;border-radius:50%;opacity:.06;pointer-events:none}
.stat.s-blue::before{background:var(--accent)}
.stat.s-green::before{background:var(--green)}
.stat.s-amber::before{background:var(--amber)}
.stat.s-red::before{background:var(--red)}
.stat:hover{border-color:var(--b2);transform:translateY(-2px)}
.stat-num{font-size:36px;font-weight:800;letter-spacing:-2px;line-height:1;margin-bottom:6px}
.stat-label{font-size:11px;color:var(--t2);text-transform:uppercase;letter-spacing:.8px;font-weight:600;
  display:flex;align-items:center;gap:6px}
.stat-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}

/* CARD */
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:20px;overflow:hidden}
.card-head{padding:16px 22px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:10px;background:var(--s2)}
.card-title{font-size:13px;font-weight:700;letter-spacing:-.1px}
.card-badge{background:var(--s3);border:1px solid var(--b2);color:var(--t2);
  font-size:11px;padding:2px 9px;border-radius:20px;font-family:'DM Mono',monospace}
.card-body{padding:20px 22px}
.card-actions{margin-left:auto;display:flex;gap:8px}

/* FORM */
.form-grid{display:grid;gap:14px;margin-bottom:16px}
.fg-3{grid-template-columns:repeat(3,1fr)}
.fg-2{grid-template-columns:repeat(2,1fr)}
.fg-1{grid-template-columns:1fr}
.field label{display:block;font-size:11px;font-weight:600;color:var(--t3);
  letter-spacing:.6px;text-transform:uppercase;margin-bottom:5px}
.field input,.field select,.field textarea{width:100%;background:rgba(255,255,255,.03);
  border:1px solid var(--border);border-radius:8px;padding:9px 13px;font-size:13px;
  color:var(--text);outline:none;transition:.2s;font-family:inherit}
.field input:focus,.field select:focus,.field textarea:focus{
  border-color:var(--accent);background:rgba(59,130,246,.06);
  box-shadow:0 0 0 3px rgba(59,130,246,.1)}
.field select option{background:var(--surface)}
.field input.mono{font-family:'DM Mono',monospace;letter-spacing:.5px;font-size:12px}

/* BUTTONS */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border:none;
  border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;
  font-family:inherit;transition:.15s;white-space:nowrap;text-decoration:none}
.btn-primary{background:linear-gradient(135deg,var(--accent),#2563eb);color:#fff;
  box-shadow:0 2px 8px rgba(59,130,246,.25)}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 4px 14px rgba(59,130,246,.35)}
.btn-success{background:rgba(16,185,129,.12);color:#34d399;border:1px solid rgba(16,185,129,.2)}
.btn-success:hover{background:rgba(16,185,129,.22)}
.btn-danger{background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.2)}
.btn-danger:hover{background:rgba(239,68,68,.22)}
.btn-warn{background:rgba(245,158,11,.12);color:#fbbf24;border:1px solid rgba(245,158,11,.2)}
.btn-warn:hover{background:rgba(245,158,11,.22)}
.btn-ghost{background:transparent;color:var(--t2);border:1px solid var(--border)}
.btn-ghost:hover{color:var(--text);border-color:var(--b2);background:var(--s2)}
.btn-purple{background:rgba(139,92,246,.12);color:#a78bfa;border:1px solid rgba(139,92,246,.2)}
.btn-purple:hover{background:rgba(139,92,246,.22)}
.btn-sm{padding:5px 11px;font-size:12px;border-radius:6px}
.btn-xs{padding:3px 8px;font-size:11px;border-radius:5px}

/* TABLE */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{padding:10px 14px;text-align:left;font-size:10.5px;font-weight:700;
  color:var(--t3);text-transform:uppercase;letter-spacing:.8px;
  background:var(--s2);border-bottom:1px solid var(--border);white-space:nowrap}
tbody tr{border-bottom:1px solid rgba(30,42,58,.5);transition:.12s}
tbody tr:hover{background:rgba(255,255,255,.02)}
tbody tr:last-child{border-bottom:none}
td{padding:11px 14px;vertical-align:middle}

/* BADGES */
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;
  border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.3px}
.b-active{background:rgba(16,185,129,.1);color:#34d399;border:1px solid rgba(16,185,129,.2)}
.b-expired{background:rgba(245,158,11,.1);color:#fbbf24;border:1px solid rgba(245,158,11,.2)}
.b-revoked{background:rgba(239,68,68,.1);color:#f87171;border:1px solid rgba(239,68,68,.2)}
.b-soon{background:rgba(139,92,246,.1);color:#a78bfa;border:1px solid rgba(139,92,246,.2)}
.bdot{width:5px;height:5px;border-radius:50%;background:currentColor}

/* KEY BOX */
.kbox{display:inline-flex;align-items:center;gap:6px;
  background:rgba(255,255,255,.04);border:1px solid var(--border);
  border-radius:6px;padding:5px 10px;cursor:pointer;transition:.15s;max-width:260px}
.kbox:hover{border-color:var(--accent);background:rgba(59,130,246,.07)}
.ktext{font-family:'DM Mono',monospace;font-size:11.5px;color:var(--t2);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.kcopy{font-size:10px;color:var(--t3);flex-shrink:0}

/* CUSTOMER */
.cname{font-weight:600;font-size:13px}
.csub{font-size:11px;color:var(--t3);margin-top:2px}

/* ACTIONS DROPDOWN */
.actions{display:flex;gap:5px;align-items:center;flex-wrap:wrap}
details.drop{position:relative}
details.drop summary{list-style:none;cursor:pointer}
details.drop summary::-webkit-details-marker{display:none}
details.drop .dpanel{position:absolute;right:0;top:calc(100%+6px);
  background:var(--s2);border:1px solid var(--b2);border-radius:10px;
  padding:14px;min-width:210px;z-index:1000;box-shadow:0 12px 32px rgba(0,0,0,.5)}
details.drop[open] .dpanel{display:block}
.dpanel h4{font-size:11px;color:var(--t3);text-transform:uppercase;
  letter-spacing:.7px;margin-bottom:10px;font-weight:700}
.dpanel select,.dpanel input{width:100%;background:rgba(255,255,255,.04);
  border:1px solid var(--border);border-radius:7px;padding:8px 11px;
  font-size:12px;color:var(--text);outline:none;margin-bottom:10px;font-family:inherit}

/* SEARCH */
.search-row{display:flex;align-items:center;gap:10px;padding:14px 22px;
  border-bottom:1px solid var(--border);background:var(--s2)}
.search-row input{flex:1;background:rgba(255,255,255,.03);border:1px solid var(--border);
  border-radius:8px;padding:8px 14px;font-size:13px;color:var(--text);
  outline:none;font-family:inherit;transition:.15s}
.search-row input:focus{border-color:var(--accent)}
.ftabs{display:flex;gap:4px}
.ftab{padding:5px 13px;border-radius:6px;font-size:12px;font-weight:600;
  cursor:pointer;border:1px solid transparent;color:var(--t3);
  background:transparent;font-family:inherit;transition:.15s}
.ftab:hover,.ftab.on{background:var(--s3);border-color:var(--b2);color:var(--text)}

/* AUDIT LOG */
.log-list{display:flex;flex-direction:column;gap:0}
.log-item{display:flex;align-items:center;gap:12px;padding:10px 0;
  border-bottom:1px solid rgba(30,42,58,.4);font-size:12px}
.log-item:last-child{border-bottom:none}
.log-time{font-family:'DM Mono',monospace;font-size:11px;color:var(--t3);white-space:nowrap;min-width:130px}
.log-action{font-weight:700;font-size:11px;padding:2px 8px;border-radius:5px;
  background:rgba(59,130,246,.1);color:#93c5fd;white-space:nowrap}
.log-detail{color:var(--t2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* MODAL */
.modal{position:fixed;inset:0;background:rgba(0,0,0,.7);backdrop-filter:blur(4px);
  z-index:500;display:flex;align-items:center;justify-content:center}
.modal-box{background:var(--s2);border:1px solid var(--b2);border-radius:14px;
  padding:24px;width:340px;box-shadow:0 24px 48px rgba(0,0,0,.6)}
.modal-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.modal-head h3{font-size:15px;font-weight:700}
.modal-head button{background:transparent;border:none;color:var(--t2);
  font-size:18px;cursor:pointer;line-height:1;padding:0 4px}
.modal-head button:hover{color:var(--text)}

/* TOAST */
#toast{position:fixed;bottom:24px;right:24px;display:flex;align-items:center;gap:8px;
  background:rgba(16,185,129,.9);backdrop-filter:blur(8px);
  border:1px solid rgba(16,185,129,.3);color:#fff;padding:11px 18px;
  border-radius:10px;font-size:13px;font-weight:600;
  opacity:0;transform:translateY(8px);transition:.3s;pointer-events:none;z-index:999}
#toast.show{opacity:1;transform:translateY(0)}

/* EXPIRY PROGRESS */
.exp-bar{height:3px;background:var(--border);border-radius:99px;overflow:hidden;margin-top:4px;width:80px}
.exp-fill{height:100%;border-radius:99px;transition:width .3s}

/* PAGE HEADER */
.page-header{margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
.page-header h1{font-size:22px;font-weight:800;letter-spacing:-.5px}
.page-header p{color:var(--t2);font-size:13px;margin-top:4px}

/* FORM CARD */
.form-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:28px;margin-bottom:20px}
.form-card h2{font-size:15px;font-weight:700;margin-bottom:20px;
  padding-bottom:14px;border-bottom:1px solid var(--border)}
.success-msg{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.2);
  color:#34d399;padding:12px 16px;border-radius:8px;font-size:13px;margin-bottom:16px}
.error-msg{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);
  color:#f87171;padding:12px 16px;border-radius:8px;font-size:13px;margin-bottom:16px}

@media(max-width:1000px){.stats{grid-template-columns:repeat(2,1fr)}.fg-3{grid-template-columns:1fr 1fr}}
</style>
"""

# ── Login ─────────────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gazi Medya — Giriş</title>
""" + BASE_CSS + """
<style>
body{display:flex;align-items:center;justify-content:center}
.login-box{width:400px;background:var(--surface);border:1px solid var(--border);
  border-radius:16px;padding:48px;box-shadow:0 24px 64px rgba(0,0,0,.6);position:relative}
.login-box::before{content:'';position:absolute;inset:0;border-radius:16px;
  background:linear-gradient(135deg,rgba(59,130,246,.04),rgba(6,182,212,.02));pointer-events:none}
.llogo{text-align:center;margin-bottom:40px}
.licon{width:56px;height:56px;background:linear-gradient(135deg,var(--accent),var(--a2));
  border-radius:14px;display:flex;align-items:center;justify-content:center;
  font-size:26px;margin:0 auto 16px;box-shadow:0 8px 24px rgba(59,130,246,.3)}
.llogo h1{font-size:22px;font-weight:800;letter-spacing:-.5px}
.llogo p{color:var(--t2);font-size:13px;margin-top:5px;font-weight:400}
</style>
</head>
<body>
<div class="login-box">
  <div class="llogo">
    <div class="licon">🔐</div>
    <h1>Gazi Medya</h1>
    <p>HR Lisans Yönetim Paneli</p>
  </div>
  {% if error %}<div class="error-msg">{{ error }}</div>{% endif %}
  <form method="POST">
    <div class="field" style="margin-bottom:16px">
      <label>Kullanıcı Adı</label>
      <input name="username" autocomplete="username" required autofocus placeholder="gazi">
    </div>
    <div class="field" style="margin-bottom:24px">
      <label>Şifre</label>
      <input name="password" type="password" autocomplete="current-password" required placeholder="••••••••">
    </div>
    <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;padding:12px">
      Giriş Yap →
    </button>
  </form>
</div>
</body>
</html>"""

# ── Şifre Değiştir ────────────────────────────────────────────
CHANGE_PASS_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Şifre Değiştir — Gazi Medya</title>
""" + BASE_CSS + """
</head>
<body>
<nav>
  <div class="nav-brand">
    <div class="nav-icon">🔐</div>
    Gazi Medya
    <span class="nav-sep">/</span>
    <span class="nav-subtitle">Lisans Paneli</span>
  </div>
  <div class="nav-right">
    <a href="/" class="nav-btn">← Panele Dön</a>
    <a href="/logout" class="nav-btn">Çıkış</a>
  </div>
</nav>
<div class="wrap" style="max-width:520px">
  <div class="page-header">
    <h1>Şifre Değiştir</h1>
    <p>Panel giriş şifrenizi güncelleyin</p>
  </div>
  <div class="form-card">
    {% if msg %}<div class="success-msg">✓ {{ msg }}</div>{% endif %}
    {% if err %}<div class="error-msg">✗ {{ err }}</div>{% endif %}
    <form method="POST">
      <div class="form-grid fg-1" style="gap:16px">
        <div class="field">
          <label>Mevcut Şifre</label>
          <input type="password" name="current" required placeholder="••••••••">
        </div>
        <div class="field">
          <label>Yeni Şifre (min. 8 karakter)</label>
          <input type="password" name="new_pass" required minlength="8" placeholder="Yeni şifre">
        </div>
        <div class="field">
          <label>Yeni Şifre Tekrar</label>
          <input type="password" name="confirm" required placeholder="Yeni şifre (tekrar)">
        </div>
      </div>
      <button type="submit" class="btn btn-primary">Şifreyi Güncelle →</button>
    </form>
  </div>
</div>
</body>
</html>"""

# ── Ana Panel ─────────────────────────────────────────────────
PANEL_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gazi Medya — Lisans Paneli</title>
""" + BASE_CSS + """
</head>
<body>

<nav>
  <div class="nav-brand">
    <div class="nav-icon">🔐</div>
    Gazi Medya
    <span class="nav-sep">/</span>
    <span class="nav-subtitle">HR Lisans Paneli</span>
  </div>
  <div class="nav-right">
    <a href="/change-password" class="nav-btn">🔑 Şifre Değiştir</a>
    <a href="/logout" class="nav-btn">Çıkış →</a>
  </div>
</nav>

<div class="wrap">

  <!-- Yaklaşan Sona Ermeler -->
  {% if expiring_soon %}
  <div class="alert-banner">
    <span>⚠️</span>
    <span>Yaklaşan 30 gün içinde sona erecek lisanslar var — müşterilere bildirim göndermeyi unutmayın.</span>
    <span class="cnt">{{ expiring_soon|length }} lisans</span>
  </div>
  {% endif %}

  <!-- İstatistikler -->
  <div class="stats">
    <div class="stat s-blue">
      <div class="stat-num" style="color:var(--accent)">{{ stats.total }}</div>
      <div class="stat-label"><span class="stat-dot" style="background:var(--accent)"></span>Toplam Lisans</div>
    </div>
    <div class="stat s-green">
      <div class="stat-num" style="color:var(--green)">{{ stats.active }}</div>
      <div class="stat-label"><span class="stat-dot" style="background:var(--green)"></span>Aktif</div>
    </div>
    <div class="stat s-amber">
      <div class="stat-num" style="color:var(--amber)">{{ stats.expired }}</div>
      <div class="stat-label"><span class="stat-dot" style="background:var(--amber)"></span>Süresi Dolmuş</div>
    </div>
    <div class="stat s-red">
      <div class="stat-num" style="color:var(--red)">{{ stats.revoked }}</div>
      <div class="stat-label"><span class="stat-dot" style="background:var(--red)"></span>İptal Edilmiş</div>
    </div>
  </div>

  <!-- Yeni Lisans -->
  <div class="card">
    <div class="card-head">
      <span style="font-size:16px;color:var(--accent)">＋</span>
      <span class="card-title">Yeni Lisans Oluştur</span>
    </div>
    <div class="card-body">
      <form method="POST" action="/create">
        <div class="form-grid fg-3">
          <div class="field">
            <label>Donanım ID *</label>
            <input name="hw_id" class="mono" placeholder="XXXXXX-XXXXXX-XXXXXX-XXXXXX" required>
          </div>
          <div class="field">
            <label>Müşteri Adı / Firma</label>
            <input name="customer_name" placeholder="ABC Şirketi A.Ş.">
          </div>
          <div class="field">
            <label>Lisans Süresi</label>
            <select name="days">
              <option value="365">1 Yıl (365 gün)</option>
              <option value="730">2 Yıl (730 gün)</option>
              <option value="9999">Süresiz</option>
              <option value="30">30 Gün — Deneme</option>
              <option value="90">90 Gün</option>
              <option value="180">6 Ay</option>
            </select>
          </div>
        </div>
        <div class="form-grid fg-3">
          <div class="field">
            <label>E-posta</label>
            <input name="customer_email" type="email" placeholder="info@firma.com">
          </div>
          <div class="field">
            <label>Telefon</label>
            <input name="customer_phone" placeholder="0212 000 00 00">
          </div>
          <div class="field">
            <label>Not / Sipariş No</label>
            <input name="notes" placeholder="Ödeme tarihi, fatura no…">
          </div>
        </div>
        <button type="submit" class="btn btn-primary">Lisans Oluştur →</button>
      </form>
    </div>
  </div>

  <!-- Lisans Listesi -->
  <div class="card">
    <div class="card-head">
      <span style="font-size:14px">◈</span>
      <span class="card-title">Lisanslar</span>
      <span class="card-badge">{{ licenses|length }}</span>
    </div>
    <div class="search-row">
      <input id="srch" placeholder="Müşteri, e-posta veya lisans anahtarı ara…" oninput="flt()">
      <div class="ftabs">
        <button class="ftab on" onclick="setF('all',this)">Tümü</button>
        <button class="ftab" onclick="setF('active',this)">Aktif</button>
        <button class="ftab" onclick="setF('expired',this)">Dolmuş</button>
        <button class="ftab" onclick="setF('revoked',this)">İptal</button>
        <button class="ftab" onclick="setF('soon',this)">⚡ Yaklaşan</button>
      </div>
    </div>
    <div class="tbl-wrap">
      <table id="ltbl">
        <thead>
          <tr>
            <th>#</th>
            <th>Müşteri</th>
            <th>Lisans Anahtarı</th>
            <th>Donanım ID</th>
            <th>Son Geçerlilik</th>
            <th>Son Görülme</th>
            <th>Kullanım</th>
            <th>Durum</th>
            <th>İşlemler</th>
          </tr>
        </thead>
        <tbody>
          {% for lic in licenses %}
          {% set dl = days_left(lic.expires_at) %}
          {% set is_exp = lic.expires_at < now %}
          {% set is_soon = not lic.is_revoked and not is_exp and dl <= 30 %}
          {% set status = 'revoked' if lic.is_revoked else ('expired' if is_exp else ('soon' if is_soon else 'active')) %}
          <tr data-s="{{ status }}"
              data-q="{{ ((lic.customer_name or '') ~ ' ' ~ (lic.customer_email or '') ~ ' ' ~ lic.license_key ~ ' ' ~ lic.hw_id)|lower }}">
            <td style="color:var(--t3);font-family:'DM Mono',monospace;font-size:12px">{{ lic.id }}</td>
            <td>
              <div class="cname">{{ lic.customer_name or '—' }}</div>
              {% if lic.customer_email %}<div class="csub">{{ lic.customer_email }}</div>{% endif %}
              {% if lic.customer_phone %}<div class="csub">{{ lic.customer_phone }}</div>{% endif %}
            </td>
            <td>
              <div class="kbox" onclick="cpKey('{{ lic.license_key }}')">
                <span class="ktext">{{ lic.license_key }}</span>
                <span class="kcopy">⌘</span>
              </div>
            </td>
            <td>
              <div class="kbox" onclick="cpKey('{{ lic.hw_id }}')" style="max-width:180px">
                <span class="ktext">{{ lic.hw_id }}</span>
                <span class="kcopy">⌘</span>
              </div>
            </td>
            <td>
              <div style="font-family:'DM Mono',monospace;font-size:12px">{{ lic.expires_at[:10] }}</div>
              {% if not lic.is_revoked %}
              <div class="exp-bar">
                <div class="exp-fill" style="width:{{ [0,[100, dl // 3 + 10]|min]|max }}%;
                  background:{% if dl < 0 %}var(--red){% elif dl < 30 %}var(--amber){% else %}var(--green){% endif %}"></div>
              </div>
              {% if dl >= 0 %}<div style="font-size:10px;color:var(--t3);margin-top:2px">{{ dl }} gün kaldı</div>
              {% else %}<div style="font-size:10px;color:var(--red);margin-top:2px">{{ -dl }} gün geçti</div>{% endif %}
              {% endif %}
            </td>
            <td>
              {% if lic.last_seen %}
                <div style="font-family:'DM Mono',monospace;font-size:12px">{{ lic.last_seen[:10] }}</div>
                <div style="font-size:11px;color:var(--t3)">{{ lic.last_seen[11:16] }}</div>
              {% else %}
                <span style="color:var(--t3);font-size:12px">Hiç</span>
              {% endif %}
            </td>
            <td>
              <span style="font-family:'DM Mono',monospace;font-size:13px;color:var(--accent)">{{ lic.verify_count }}</span>
              <span style="font-size:11px;color:var(--t3)">x</span>
            </td>
            <td>
              {% if lic.is_revoked %}
                <span class="badge b-revoked"><span class="bdot"></span>İptal</span>
              {% elif is_soon %}
                <span class="badge b-soon"><span class="bdot"></span>Yaklaşıyor</span>
              {% elif is_exp %}
                <span class="badge b-expired"><span class="bdot"></span>Doldu</span>
              {% else %}
                <span class="badge b-active"><span class="bdot"></span>Aktif</span>
              {% endif %}
            </td>
            <td>
              <div class="actions">
                <!-- UZAT -->
                <button type="button" class="btn btn-success btn-sm"
                  onclick="document.getElementById('m-uzat-'+{{ lic.id }}).style.display='flex'">Uzat</button>
                <!-- DÜZENLE -->
                <button type="button" class="btn btn-purple btn-sm"
                  onclick="document.getElementById('m-duzenle-'+{{ lic.id }}).style.display='flex'">Düzenle</button>
                <!-- İPTAL / AKTİFLEŞTİR -->
                {% if not lic.is_revoked %}
                <button type="button" class="btn btn-warn btn-sm"
                  onclick="document.getElementById('m-iptal-'+{{ lic.id }}).style.display='flex'">İptal</button>
                {% else %}
                <form method="POST" action="/restore/{{ lic.id }}" style="display:inline">
                  <button type="submit" class="btn btn-success btn-sm">Aktifleştir</button>
                </form>
                {% endif %}
                <!-- SİL -->
                <form method="POST" action="/delete/{{ lic.id }}" style="display:inline"
                      onsubmit="return confirm('Kalıcı silinecek! Emin misiniz?')">
                  <button type="submit" class="btn btn-danger btn-xs">✕</button>
                </form>
              </div>
            </td>
            <!-- MODALLER -->
            <td style="display:none">
              <!-- UZAT MODAL -->
              <div id="m-uzat-{{ lic.id }}" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);
                z-index:1000;align-items:center;justify-content:center">
                <div style="background:#1c2a40;border:1px solid #2d4060;border-radius:14px;padding:28px;width:340px">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px">
                    <b style="font-size:15px">Süre Uzat</b>
                    <button onclick="document.getElementById('m-uzat-'+{{ lic.id }}).style.display='none'"
                      style="background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer">✕</button>
                  </div>
                  <form method="POST" action="/extend/{{ lic.id }}">
                    <label style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.6px">Süre</label>
                    <select name="days" style="width:100%;background:#111827;border:1px solid #253347;border-radius:8px;
                      padding:9px 12px;color:#e2e8f0;font-size:13px;margin:6px 0 14px;outline:none">
                      <option value="365">+ 1 Yıl</option>
                      <option value="730">+ 2 Yıl</option>
                      <option value="180">+ 6 Ay</option>
                      <option value="90">+ 90 Gün</option>
                      <option value="30">+ 30 Gün</option>
                    </select>
                    <button type="submit" style="width:100%;padding:10px;background:linear-gradient(135deg,#10b981,#059669);
                      border:none;border-radius:8px;color:#fff;font-size:13px;font-weight:600;cursor:pointer">Uzat →</button>
                  </form>
                </div>
              </div>
              <!-- DÜZENLE MODAL -->
              <div id="m-duzenle-{{ lic.id }}" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);
                z-index:1000;align-items:center;justify-content:center">
                <div style="background:#1c2a40;border:1px solid #2d4060;border-radius:14px;padding:28px;width:360px">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px">
                    <b style="font-size:15px">Müşteri Bilgilerini Düzenle</b>
                    <button onclick="document.getElementById('m-duzenle-'+{{ lic.id }}).style.display='none'"
                      style="background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer">✕</button>
                  </div>
                  <form method="POST" action="/edit/{{ lic.id }}">
                    {% for fname,fval,fph in [
                      ('customer_name', lic.customer_name or '', 'Müşteri adı'),
                      ('customer_email', lic.customer_email or '', 'E-posta'),
                      ('customer_phone', lic.customer_phone or '', 'Telefon'),
                      ('notes', lic.notes or '', 'Not')
                    ] %}
                    <input name="{{ fname }}" value="{{ fval }}" placeholder="{{ fph }}"
                      style="width:100%;background:#111827;border:1px solid #253347;border-radius:8px;
                        padding:9px 12px;color:#e2e8f0;font-size:13px;margin-bottom:10px;outline:none">
                    {% endfor %}
                    <button type="submit" style="width:100%;padding:10px;background:linear-gradient(135deg,#8b5cf6,#7c3aed);
                      border:none;border-radius:8px;color:#fff;font-size:13px;font-weight:600;cursor:pointer;margin-top:4px">Kaydet →</button>
                  </form>
                </div>
              </div>
              <!-- İPTAL MODAL -->
              {% if not lic.is_revoked %}
              <div id="m-iptal-{{ lic.id }}" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);
                z-index:1000;align-items:center;justify-content:center">
                <div style="background:#1c2a40;border:1px solid #2d4060;border-radius:14px;padding:28px;width:340px">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px">
                    <b style="font-size:15px">Lisansı İptal Et</b>
                    <button onclick="document.getElementById('m-iptal-'+{{ lic.id }}).style.display='none'"
                      style="background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer">✕</button>
                  </div>
                  <form method="POST" action="/revoke/{{ lic.id }}">
                    <input name="reason" placeholder="İptal gerekçesi (opsiyonel)"
                      style="width:100%;background:#111827;border:1px solid #253347;border-radius:8px;
                        padding:9px 12px;color:#e2e8f0;font-size:13px;margin-bottom:14px;outline:none">
                    <button type="submit" style="width:100%;padding:10px;background:linear-gradient(135deg,#ef4444,#dc2626);
                      border:none;border-radius:8px;color:#fff;font-size:13px;font-weight:600;cursor:pointer">İptal Et →</button>
                  </form>
                </div>
              </div>
              {% endif %}
            </td>
          </tr>
          {% else %}
          <tr><td colspan="9" style="text-align:center;padding:60px;color:var(--t3)">
            <div style="font-size:28px;margin-bottom:10px">◈</div>
            <div>Henüz lisans yok. Yukarıdan oluşturun.</div>
          </td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Denetim Günlüğü -->
  <div class="card">
    <div class="card-head">
      <span style="font-size:14px;color:var(--t2)">▸</span>
      <span class="card-title">Denetim Günlüğü</span>
      <span class="card-badge">Son 20 işlem</span>
    </div>
    <div class="card-body">
      <div class="log-list">
        {% for log in logs %}
        <div class="log-item">
          <span class="log-time">{{ log.created_at[:16].replace('T',' ') }}</span>
          <span class="log-action">{{ log.action }}</span>
          <span class="log-detail">{{ log.detail or '—' }}</span>
        </div>
        {% else %}
        <div style="color:var(--t3);font-size:13px;padding:10px 0">Log kaydı yok</div>
        {% endfor %}
      </div>
    </div>
  </div>

</div><!-- wrap -->

<div id="toast">✓ Panoya kopyalandı</div>

<script>
function openModal(id) {
  document.getElementById(id).style.display = 'flex'
}
function closeModal(id) {
  document.getElementById(id).style.display = 'none'
}
// ESC ile kapat
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal').forEach(m => m.style.display = 'none')
  }
})
// Overlay tıklayınca kapat
document.addEventListener('click', e => {
  if (e.target.classList.contains('modal')) {
    e.target.style.display = 'none'
  }
})

function cpKey(t) {
  navigator.clipboard.writeText(t).then(() => {
    const el = document.getElementById('toast')
    el.classList.add('show')
    setTimeout(() => el.classList.remove('show'), 2200)
  })
}

let curF = 'all'
function setF(f, btn) {
  curF = f
  document.querySelectorAll('.ftab').forEach(b => b.classList.remove('on'))
  btn.classList.add('on')
  flt()
}
function flt() {
  const q = document.getElementById('srch').value.toLowerCase()
  document.querySelectorAll('#ltbl tbody tr[data-s]').forEach(tr => {
    const ms = curF === 'all' || tr.dataset.s === curF
    const mq = !q || tr.dataset.q.includes(q)
    tr.style.display = ms && mq ? '' : 'none'
  })
}

// Dropdown dışına tıklayınca kapat
document.addEventListener('click', e => {
  if (!e.target.closest('details.drop')) {
    document.querySelectorAll('details.drop[open]').forEach(d => d.removeAttribute('open'))
  }
})

// Summary tıklandığında diğer dropdownları kapat
document.addEventListener('click', e => {
  const clicked = e.target.closest('details.drop')
  document.querySelectorAll('details.drop[open]').forEach(d => {
    if (d !== clicked) d.removeAttribute('open')
  })
})
</script>
</body>
</html>"""

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    print("=" * 50)
    print(f" Gazi Medya HR Lisans Paneli v3 — port {port}")
    print("=" * 50)
    app.run(host='0.0.0.0', port=port, debug=False)
