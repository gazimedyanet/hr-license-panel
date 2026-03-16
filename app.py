# ============================================================================
# Gazi Medya HR Lisans Paneli — PythonAnywhere için optimize edilmiş versiyon
# ============================================================================
from flask import Flask, request, jsonify, render_template_string, redirect, session
import sqlite3, hashlib, hmac
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = "GaziMediaPanelSecret2026"

# PythonAnywhere'de DB dosyası tam yol ile belirtilmeli
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.path.join(BASE_DIR, "licenses.db")
SIGN_KEY  = "GaziMediaHR2026SecretKey_DoNotShare"
ADMIN_USER = "gazi"
ADMIN_PASS = "GaziMedia2026!"  # Bunu değiştir!

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key    TEXT UNIQUE NOT NULL,
            hw_id          TEXT NOT NULL,
            product        TEXT DEFAULT 'gazi-hr',
            customer_name  TEXT,
            customer_email TEXT,
            customer_phone TEXT,
            issued_at      TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at     TEXT NOT NULL,
            is_revoked     INTEGER DEFAULT 0,
            revoke_reason  TEXT,
            last_seen      TEXT,
            verify_count   INTEGER DEFAULT 0,
            notes          TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def generate_license_key(hw_id: str, days: int = 365) -> str:
    hw_hash = hashlib.sha256(hw_id.encode()).hexdigest()[:6].upper()
    expiry_ts = int((datetime.now() + timedelta(days=days)).timestamp())
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    n, result = expiry_ts, ""
    while n:
        result = chars[n % 36] + result
        n //= 36
    expiry_b36 = result
    data = f"GMHR-{hw_hash}-{expiry_b36}"
    checksum = hmac.new(SIGN_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()[:8].upper()
    return f"GMHR-{hw_hash}-{expiry_b36}-{checksum}"

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET','POST'])
def login():
    error = ''
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USER and request.form['password'] == ADMIN_PASS:
            session['logged_in'] = True
            return redirect('/')
        error = 'Hatalı giriş'
    return render_template_string(LOGIN_HTML, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/')
@login_required
def index():
    conn = get_db()
    licenses = conn.execute("SELECT * FROM licenses ORDER BY issued_at DESC").fetchall()
    now = datetime.now().isoformat()
    stats = {
        'total':   conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        'active':  conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=0 AND expires_at > ?", (now,)).fetchone()[0],
        'expired': conn.execute("SELECT COUNT(*) FROM licenses WHERE expires_at < ? AND is_revoked=0", (now,)).fetchone()[0],
        'revoked': conn.execute("SELECT COUNT(*) FROM licenses WHERE is_revoked=1").fetchone()[0],
    }
    conn.close()
    return render_template_string(PANEL_HTML, licenses=licenses, stats=stats,
                                  now=datetime.now().isoformat())

@app.route('/create', methods=['POST'])
@login_required
def create():
    hw_id    = request.form.get('hw_id','').strip().upper()
    days     = int(request.form.get('days', 365))
    customer = request.form.get('customer_name','').strip()
    email    = request.form.get('customer_email','').strip()
    phone    = request.form.get('customer_phone','').strip()
    notes    = request.form.get('notes','').strip()
    if not hw_id:
        return "Donanım ID gerekli", 400
    key     = generate_license_key(hw_id, days)
    expires = (datetime.now() + timedelta(days=days)).isoformat()
    conn = get_db()
    try:
        conn.execute("""INSERT INTO licenses
            (license_key,hw_id,customer_name,customer_email,customer_phone,expires_at,notes)
            VALUES (?,?,?,?,?,?,?)""", (key,hw_id,customer,email,phone,expires,notes))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return "<script>alert('Bu HW ID için zaten lisans var!');history.back()</script>"
    conn.close()
    return redirect('/')

@app.route('/revoke/<int:lid>', methods=['POST'])
@login_required
def revoke(lid):
    reason = request.form.get('reason','')
    conn = get_db()
    conn.execute("UPDATE licenses SET is_revoked=1, revoke_reason=? WHERE id=?", (reason,lid))
    conn.commit(); conn.close()
    return redirect('/')

@app.route('/extend/<int:lid>', methods=['POST'])
@login_required
def extend(lid):
    days = int(request.form.get('days', 365))
    conn = get_db()
    lic  = conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    if lic:
        cur = datetime.fromisoformat(lic['expires_at'])
        if cur < datetime.now(): cur = datetime.now()
        new_exp = cur + timedelta(days=days)
        new_key = generate_license_key(lic['hw_id'], days)
        conn.execute("UPDATE licenses SET license_key=?, expires_at=?, is_revoked=0 WHERE id=?",
                     (new_key, new_exp.isoformat(), lid))
        conn.commit()
    conn.close()
    return redirect('/')

@app.route('/delete/<int:lid>', methods=['POST'])
@login_required
def delete(lid):
    conn = get_db()
    conn.execute("DELETE FROM licenses WHERE id=?", (lid,))
    conn.commit(); conn.close()
    return redirect('/')

@app.route('/api/hr-license', methods=['POST'])
def verify():
    data        = request.get_json(silent=True) or {}
    license_key = data.get('license_key','').strip().upper()
    hw_id       = data.get('hw_id','').strip()
    product     = data.get('product','')
    if product != 'gazi-hr':
        return jsonify({"valid":False,"message":"Bilinmeyen ürün"})
    if not license_key or not hw_id:
        return jsonify({"valid":False,"message":"Eksik bilgi"})
    conn = get_db()
    lic  = conn.execute(
        "SELECT * FROM licenses WHERE license_key=? AND product='gazi-hr'",
        (license_key,)).fetchone()
    if not lic:
        conn.close()
        return jsonify({"valid":False,"message":"Lisans bulunamadı"})
    if lic['is_revoked']:
        conn.close()
        return jsonify({"valid":False,"message":f"Lisans iptal edildi: {lic['revoke_reason'] or ''}"})
    if lic['hw_id'].upper() != hw_id.upper():
        conn.close()
        return jsonify({"valid":False,"message":"Lisans bu donanım için değil"})
    expires_dt = datetime.fromisoformat(lic['expires_at'])
    if datetime.now() > expires_dt:
        conn.close()
        return jsonify({"valid":False,"message":f"Lisans süresi doldu ({expires_dt.strftime('%d.%m.%Y')})"})
    conn.execute("UPDATE licenses SET last_seen=?, verify_count=verify_count+1 WHERE id=?",
                 (datetime.now().isoformat(), lic['id']))
    conn.commit(); conn.close()
    return jsonify({"valid":True,"expires":expires_dt.strftime('%d.%m.%Y'),
                    "customer":lic['customer_name'],"message":"Lisans geçerli"})

LOGIN_HTML = """<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<title>Gazi Medya Lisans Paneli</title>
<style>*{box-sizing:border-box;margin:0;padding:0;font-family:system-ui}
body{background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:#fff;border-radius:12px;padding:36px;width:360px;box-shadow:0 4px 20px rgba(0,0,0,.1)}
h1{color:#1a1f2e;font-size:20px;margin-bottom:6px;text-align:center}
p{color:#9ca3af;font-size:13px;text-align:center;margin-bottom:24px}
label{font-size:12px;color:#6b7280;display:block;margin-bottom:4px}
input{width:100%;padding:10px 12px;border:1px solid #e5e7eb;border-radius:8px;
      font-size:14px;margin-bottom:14px;outline:none}
input:focus{border-color:#1677ff}
button{width:100%;padding:11px;background:#1677ff;color:#fff;border:none;
       border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
.err{color:#dc2626;font-size:13px;text-align:center;margin-bottom:12px}
</style></head><body><div class="box">
<h1>🔐 Gazi Medya</h1><p>HR Lisans Yönetim Paneli</p>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="POST">
<label>Kullanıcı Adı</label><input name="username" required autofocus>
<label>Şifre</label><input name="password" type="password" required>
<button>Giriş Yap</button></form></div></body></html>"""

PANEL_HTML = """<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<title>Lisans Paneli</title>
<style>*{box-sizing:border-box;margin:0;padding:0;font-family:system-ui,sans-serif}
body{background:#f0f2f5}
nav{background:#1a1f2e;padding:14px 24px;display:flex;justify-content:space-between;align-items:center}
nav h1{color:#fff;font-size:17px}nav a{color:#64748b;text-decoration:none;font-size:13px}
nav a:hover{color:#fff}
.wrap{max-width:1300px;margin:0 auto;padding:24px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.stat{background:#fff;border-radius:10px;padding:16px;border:1px solid #e5e7eb;text-align:center}
.stat b{font-size:28px;display:block}.stat span{font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px}
.card{background:#fff;border-radius:10px;border:1px solid #e5e7eb;padding:20px;margin-bottom:20px}
.card h2{font-size:15px;margin-bottom:16px;color:#1a1f2e}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}
label{font-size:11px;color:#6b7280;display:block;margin-bottom:3px}
input,select,textarea{width:100%;padding:8px 10px;border:1px solid #e5e7eb;border-radius:6px;font-size:13px;outline:none}
input:focus,select:focus{border-color:#1677ff}
.btn{padding:7px 14px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600}
.bp{background:#1677ff;color:#fff}.bd{background:#dc2626;color:#fff}
.bw{background:#d97706;color:#fff}.bg{background:#16a34a;color:#fff}
.btn:hover{opacity:.85}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#f8fafc;padding:9px 12px;text-align:left;border-bottom:2px solid #e5e7eb;
   font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#6b7280}
td{padding:9px 12px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
.key{font-family:monospace;font-size:11px;background:#f8fafc;padding:3px 7px;
     border-radius:4px;cursor:pointer;user-select:all}
.badge{padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;display:inline-block}
.ba{background:#dcfce7;color:#16a34a}.br{background:#fee2e2;color:#dc2626}
.bo{background:#fef3c7;color:#d97706}
.acts{display:flex;gap:5px;flex-wrap:wrap}
details summary{cursor:pointer;color:#1677ff;font-size:11px;list-style:none}
.df{background:#f8fafc;padding:10px;border-radius:7px;border:1px solid #e5e7eb;margin-top:6px}
</style></head><body>
<nav><h1>🔐 Gazi Medya — HR Lisans Paneli</h1><a href="/logout">Çıkış</a></nav>
<div class="wrap">
<div class="stats">
  <div class="stat"><b style="color:#1677ff">{{stats.total}}</b><span>Toplam</span></div>
  <div class="stat"><b style="color:#16a34a">{{stats.active}}</b><span>Aktif</span></div>
  <div class="stat"><b style="color:#d97706">{{stats.expired}}</b><span>Süresi Dolmuş</span></div>
  <div class="stat"><b style="color:#dc2626">{{stats.revoked}}</b><span>İptal</span></div>
</div>
<div class="card"><h2>➕ Yeni Lisans Oluştur</h2>
<form method="POST" action="/create">
<div class="grid3">
  <div><label>Donanım ID * (müşteriden alın)</label>
       <input name="hw_id" placeholder="XXXXXX-XXXXXX-XXXXXX-XXXXXX" required style="font-family:monospace"></div>
  <div><label>Müşteri / Firma Adı</label><input name="customer_name" placeholder="ABC Şirketi A.Ş."></div>
  <div><label>Lisans Süresi</label>
       <select name="days">
         <option value="365">1 Yıl (365 gün)</option>
         <option value="730">2 Yıl</option>
         <option value="9999">Süresiz</option>
         <option value="30">30 Gün — Deneme</option>
         <option value="90">90 Gün</option>
       </select></div>
  <div><label>E-posta</label><input name="customer_email" type="email" placeholder="info@firma.com"></div>
  <div><label>Telefon</label><input name="customer_phone" placeholder="0212 000 00 00"></div>
  <div><label>Not (ödeme, sipariş no vb.)</label><input name="notes" placeholder="..."></div>
</div>
<button type="submit" class="btn bp">Lisans Oluştur</button>
</form></div>
<div class="card"><h2>📋 Lisans Listesi</h2>
<table><tr>
  <th>#</th><th>Müşteri</th><th>Lisans Anahtarı</th><th>HW ID</th>
  <th>Son Geçerlilik</th><th>Son Görülme</th><th>Doğrulama</th><th>Durum</th><th>İşlem</th>
</tr>
{% for l in licenses %}
<tr>
  <td>{{l.id}}</td>
  <td><b>{{l.customer_name or '—'}}</b><br><small style="color:#9ca3af">{{l.customer_email or ''}}</small></td>
  <td><span class="key" onclick="navigator.clipboard.writeText('{{l.license_key}}');this.style.background='#dcfce7'" title="Kopyala">{{l.license_key}}</span></td>
  <td><span class="key">{{l.hw_id[:18]}}...</span></td>
  <td>{{l.expires_at[:10]}}</td>
  <td style="color:#9ca3af;font-size:11px">{{l.last_seen[:16] if l.last_seen else 'Henüz yok'}}</td>
  <td style="text-align:center">{{l.verify_count or 0}}</td>
  <td>
    {% if l.is_revoked %}<span class="badge br">İptal</span>
    {% elif l.expires_at < now %}<span class="badge bo">Süresi Dolmuş</span>
    {% else %}<span class="badge ba">Aktif</span>{% endif %}
  </td>
  <td><div class="acts">
    <details><summary>Uzat</summary>
      <div class="df"><form method="POST" action="/extend/{{l.id}}" style="display:flex;gap:6px">
        <select name="days" style="width:120px">
          <option value="365">+1 Yıl</option><option value="730">+2 Yıl</option>
          <option value="90">+90 Gün</option>
        </select>
        <button type="submit" class="btn bg">Uzat</button>
      </form></div>
    </details>
    {% if not l.is_revoked %}
    <details><summary style="color:#dc2626">İptal</summary>
      <div class="df"><form method="POST" action="/revoke/{{l.id}}">
        <input name="reason" placeholder="Gerekçe" style="margin-bottom:6px">
        <button type="submit" class="btn bd"
                onclick="return confirm('Lisans iptal edilecek!')">İptal Et</button>
      </form></div>
    </details>
    {% endif %}
    <form method="POST" action="/delete/{{l.id}}"
          onsubmit="return confirm('Kalıcı silinecek!')">
      <button type="submit" class="btn bd" style="font-size:10px;padding:4px 7px">Sil</button>
    </form>
  </div></td>
</tr>
{% else %}
<tr><td colspan="9" style="text-align:center;padding:40px;color:#9ca3af">Henüz lisans yok</td></tr>
{% endfor %}
</table></div></div></body></html>"""

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
