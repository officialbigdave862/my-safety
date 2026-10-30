import os, sqlite3, json
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, render_template, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-before-deploying')
DB_PATH = os.environ.get('DATABASE_PATH', 'guardian.db')

def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    conn = g.pop('db', None)
    if conn is not None: conn.close()

with app.app_context():
    conn = db()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, label TEXT NOT NULL, last_lat REAL, last_lon REAL, last_seen TEXT, created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, device_id INTEGER, kind TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
    ''')
    conn.commit()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            if request.path.startswith('/api/'): return jsonify(error='Please sign in'), 401
            return redirect('/login')
        return fn(*args, **kwargs)
    return wrapped

def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')

@app.get('/')
def home(): return redirect('/dashboard' if session.get('user_id') else '/login')

@app.route('/register', methods=['GET','POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if len(username) < 3 or len(password) < 8: error = 'Use a username with at least 3 characters and a password with at least 8 characters.'
        else:
            try:
                db().execute('INSERT INTO users(username,password_hash) VALUES(?,?)',(username,generate_password_hash(password)))
                db().commit()
                user = db().execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()
                session['user_id'] = user['id']; session['username'] = username
                return redirect('/dashboard')
            except sqlite3.IntegrityError: error = 'That username is already taken.'
    return render_template('auth.html', mode='Create account', error=error)

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        user = db().execute('SELECT * FROM users WHERE username=?',(request.form.get('username','').strip(),)).fetchone()
        if user and check_password_hash(user['password_hash'], request.form.get('password','')):
            session.clear(); session['user_id']=user['id']; session['username']=user['username']
            return redirect('/dashboard')
        error = 'Username or password was incorrect.'
    return render_template('auth.html', mode='Sign in', error=error)

@app.get('/logout')
def logout(): session.clear(); return redirect('/login')

@app.get('/dashboard')
@login_required
def dashboard():
    uid=session['user_id']
    devices=db().execute('SELECT * FROM devices WHERE user_id=? ORDER BY id DESC',(uid,)).fetchall()
    events=db().execute('SELECT * FROM events WHERE user_id=? ORDER BY id DESC LIMIT 25',(uid,)).fetchall()
    return render_template('dashboard.html', username=session.get('username',''), devices=devices, events=events)

@app.post('/api/devices')
@login_required
def create_device():
    data=request.get_json(silent=True) or {}
    label=(data.get('label') or 'My phone').strip()[:80]
    cur=db().execute('INSERT INTO devices(user_id,label,created_at) VALUES(?,?,?)',(session['user_id'],label,now()))
    db().commit()
    log_event(None,'device_registered',f'Registered device: {label}')
    return jsonify(id=cur.lastrowid,label=label),201

def log_event(device_id,kind,details):
    db().execute('INSERT INTO events(user_id,device_id,kind,details,created_at) VALUES(?,?,?,?,?)',(session['user_id'],device_id,kind,details[:500],now()))
    db().commit()

@app.post('/api/location')
@login_required
def location():
    data=request.get_json(silent=True) or {}
    try: lat=float(data['latitude']); lon=float(data['longitude']); device_id=int(data['device_id'])
    except (KeyError,TypeError,ValueError): return jsonify(error='Valid coordinates and device_id are required'),400
    if not (-90 <= lat <= 90 and -180 <= lon <= 180): return jsonify(error='Coordinates out of range'),400
    dev=db().execute('SELECT id FROM devices WHERE id=? AND user_id=?',(device_id,session['user_id'])).fetchone()
    if not dev: return jsonify(error='Device not found'),404
    stamp=now()
    db().execute('UPDATE devices SET last_lat=?,last_lon=?,last_seen=? WHERE id=?',(lat,lon,stamp,device_id))
    log_event(device_id,'location_update','Location updated with the device owner’s permission')
    return jsonify(ok=True,last_seen=stamp)

@app.post('/api/event')
@login_required
def event():
    data=request.get_json(silent=True) or {}
    kind=(data.get('kind') or 'security_note')[:50]
    details=(data.get('details') or 'User recorded a security event')[:500]
    device_id=data.get('device_id')
    if device_id:
        try: device_id=int(device_id)
        except ValueError: return jsonify(error='Invalid device id'),400
        if not db().execute('SELECT id FROM devices WHERE id=? AND user_id=?',(device_id,session['user_id'])).fetchone(): return jsonify(error='Device not found'),404
    log_event(device_id,kind,details)
    return jsonify(ok=True)

@app.post('/api/device/<int:device_id>/delete')
@login_required
def delete_device(device_id):
    dev=db().execute('SELECT * FROM devices WHERE id=? AND user_id=?',(device_id,session['user_id'])).fetchone()
    if not dev: return jsonify(error='Device not found'),404
    db().execute('DELETE FROM events WHERE user_id=? AND device_id=?',(session['user_id'],device_id))
    db().execute('DELETE FROM devices WHERE id=? AND user_id=?',(device_id,session['user_id']))
    db().commit(); log_event(None,'device_removed',f'Removed device: {dev["label"]}')
    return jsonify(ok=True)

if __name__ == '__main__': app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)), debug=False)
