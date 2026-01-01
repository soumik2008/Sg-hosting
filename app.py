import os
import subprocess
import threading
import re
import signal
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_hosting'
UPLOAD_FOLDER = 'hosted_files'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Database Setup ---
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY, 
                     username TEXT UNIQUE, 
                     email TEXT, 
                     password TEXT, 
                     role TEXT, 
                     plan TEXT, 
                     file_limit INTEGER)''')
    conn.execute('CREATE TABLE IF NOT EXISTS deployments (id INTEGER PRIMARY KEY, user_id INTEGER, filename TEXT, status TEXT, pid INTEGER)')
    
    # Create admin if not exists
    admin_exists = conn.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
    if not admin_exists:
        hashed_pw = generate_password_hash('admin@12')
        conn.execute('INSERT INTO users (username, email, password, role, plan, file_limit) VALUES (?, ?, ?, ?, ?, ?)', 
                     ('admin', 'admin@pyhost.com', hashed_pw, 'admin', 'premium', 999))
    conn.commit()
    conn.close()

init_db()

# --- Hosting Logic ---
processes = {} # Store active processes {deployment_id: subprocess_obj}

def install_requirements(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    imports = re.findall(r'^(?:import|from)\s+(\w+)', content, re.MULTILINE)
    standard_libs = ['os', 'sys', 'time', 're', 'json', 'threading', 'math', 'random']
    for lib in set(imports):
        if lib not in standard_libs:
            subprocess.run(['pip', 'install', lib])

def run_script(dep_id, filepath):
    print(f"[v0] Deploying script: {filepath} (ID: {dep_id})")
    install_requirements(filepath)
    try:
        proc = subprocess.Popen(['python', filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes[dep_id] = proc
        # Keep process status synced in DB
        conn = get_db_connection()
        conn.execute('UPDATE deployments SET pid = ?, status = ? WHERE id = ?', (proc.pid, 'Running', dep_id))
        conn.commit()
        conn.close()
        
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            print(f"[v0] Error in {filepath}: {stderr.decode()}")
    except Exception as e:
        print(f"[v0] Critical error running script {dep_id}: {str(e)}")
    finally:
        if dep_id in processes:
            del processes[dep_id]
        conn = get_db_connection()
        conn.execute('UPDATE deployments SET status = ?, pid = NULL WHERE id = ?', ('Stopped', dep_id))
        conn.commit()
        conn.close()

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form.get('email', '')
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long')
            return render_template('login.html', type='Register')
        
        if not email or '@' not in email:
            flash('Please provide a valid email address')
            return render_template('login.html', type='Register')
        
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('login.html', type='Register')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long')
            return render_template('login.html', type='Register')
        
        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, email, password, role, plan, file_limit) VALUES (?, ?, ?, ?, ?, ?)', 
                         (username, email, hashed_password, 'user', 'free', 3))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Registration failed: Username may already exist')
            print(f"[v0] Registration error: {str(e)}")
        finally:
            conn.close()
    return render_template('login.html', type='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        flash('Invalid Credentials')
    return render_template('login.html', type='Login')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    files = conn.execute('SELECT * FROM deployments WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('dashboard.html', user=user, files=files)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session: return redirect(url_for('login'))
    file = request.files['file']
    if file and file.filename.endswith('.py'):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        count = conn.execute('SELECT COUNT(*) FROM deployments WHERE user_id = ?', (session['user_id'],)).fetchone()[0]
        
        if count >= user['file_limit']:
            flash('File limit reached! Upgrade to Premium.')
            return redirect(url_for('dashboard'))

        filename = secure_filename(file.filename)
        path = os.path.join(UPLOAD_FOLDER, f"{session['user_id']}_{filename}")
        file.save(path)
        
        cur = conn.execute('INSERT INTO deployments (user_id, filename, status) VALUES (?, ?, ?)', 
                     (session['user_id'], path, 'Stopped'))
        conn.commit()
        conn.close()
    return redirect(url_for('dashboard'))

@app.route('/action/<int:id>/<action>')
def file_action(id, action):
    conn = get_db_connection()
    dep = conn.execute('SELECT * FROM deployments WHERE id = ?', (id,)).fetchone()
    
    if action == 'start':
        thread = threading.Thread(target=run_script, args=(id, dep['filename']))
        thread.start()
        conn.execute('UPDATE deployments SET status = ? WHERE id = ?', ('Running', id))
    elif action == 'stop':
        if id in processes:
            processes[id].terminate()
            del processes[id]
        conn.execute('UPDATE deployments SET status = ? WHERE id = ?', ('Stopped', id))
    elif action == 'delete':
        if id in processes: processes[id].terminate()
        if os.path.exists(dep['filename']): os.remove(dep['filename'])
        conn.execute('DELETE FROM deployments WHERE id = ?', (id,))
    
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

# --- Admin Section ---
@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin': return "Access Denied", 403
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users WHERE role = "user"').fetchall()
    conn.close()
    return render_template('admin.html', users=users)

@app.route('/admin/update/<int:id>', methods=['POST'])
def admin_update(id):
    if session.get('role') != 'admin': return redirect('/')
    plan = request.form['plan']
    limit = request.form['limit']
    conn = get_db_connection()
    conn.execute('UPDATE users SET plan = ?, file_limit = ? WHERE id = ?', (plan, limit, id))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/premium')
def premium():
    return render_template('premium.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
