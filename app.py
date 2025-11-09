# app.py (cleaned & fixed)
from flask import Flask, render_template, request, redirect, url_for, flash, session
from dotenv import load_dotenv
import os
import pyodbc
from datetime import datetime, timedelta
import webbrowser
import threading

# Flask-Login + utilities
from flask_login import (
    LoginManager, UserMixin,
    login_user, logout_user, login_required, current_user
)

# Security / LDAP
from passlib.hash import bcrypt
from ldap3 import Server, Connection, ALL

# load env
load_dotenv()

# --- Config from .env ---
DB_HOST = os.getenv("DB_HOST")
DB_DATABASE = os.getenv("DB_DATABASE")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_ENCRYPT = os.getenv("DB_ENCRYPT", "no")
AD_SERVER = os.getenv("AD_SERVER")
AD_PORT = int(os.getenv("AD_PORT", "389"))
AD_USE_SSL = os.getenv("AD_USE_SSL", "no").lower() == "yes"
AD_USER_DOMAIN = os.getenv("AD_USER_DOMAIN", "")
AD_TEST_USER = os.getenv("AD_TEST_USER")
AD_TEST_PASS = os.getenv("AD_TEST_PASS")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

# --- App init ---
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY or os.urandom(24)

# --- DB connection helper ---
def get_db_connection():
    """
    Returns a pyodbc connection using ODBC Driver 17 for SQL Server.
    """
    driver = '{ODBC Driver 17 for SQL Server}'
    encrypt_option = 'yes' if DB_ENCRYPT.lower() == 'yes' else 'no'

    conn_str = (
        f'DRIVER={driver};'
        f'SERVER={DB_HOST};'
        f'DATABASE={DB_DATABASE};'
        f'UID={DB_USERNAME};'
        f'PWD={DB_PASSWORD};'
        f'Encrypt={encrypt_option};'
        f'TrustServerCertificate=yes;'
    )
    return pyodbc.connect(conn_str, autocommit=False)

# --- Flask-Login setup ---
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# --- User model for session ---
class User(UserMixin):
    def __init__(self, id, username, email=None, display_name=None, role='user'):
        self.id = str(id)
        self.username = username
        self.email = email
        self.display_name = display_name or username
        self.role = role

    def is_admin(self):
        return (self.role or '').lower() == 'admin'


@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, display_name, role FROM dbo.users WHERE id = ?",
            (int(user_id),)
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            uid, username, email, display_name, role = row
            return User(uid, username, email, display_name, role)
    except Exception as e:
        print("⚠️ load_user error:", e)
    return None

# --- Audit logging helper ---
def log_audit(action, details=None):
    """
    Insert a record into dbo.audit_log.
    If table doesn't exist or DB is unreachable, fail silently and print error.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        username = "system"
        try:
            if current_user and getattr(current_user, "is_authenticated", False):
                username = current_user.username
        except Exception:
            username = "system"

        ip = request.remote_addr if request else "127.0.0.1"
        try:
            cursor.execute("""
                INSERT INTO dbo.audit_log (username, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            """, (username, action, details, ip))
            conn.commit()
        except Exception as e:
            # likely missing table or permissions issue
            print("⚠️ Audit log insert failed (check dbo.audit_log exists):", e)
        finally:
            conn.close()
    except Exception as e:
        print("⚠️ Audit logging failed (DB connection):", e)

# --- Helper: ensure default admin exists ---
def ensure_default_admin():
    """
    Ensure there is at least one admin record in dbo.users.
    Note: Default admin authenticates via AD. Optionally you may add a local password_hash for dev.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM dbo.users WHERE role = 'admin'")
        row = cursor.fetchone()
        admin_count = row[0] if row else 0

        if admin_count == 0:
            default_admin = "admin"  # must exist in AD if AD mode is used
            cursor.execute("""
                INSERT INTO dbo.users (username, display_name, email, role, status)
                VALUES (?, ?, ?, 'admin', 'active')
            """, (default_admin, 'System Administrator', f'{default_admin}@{AD_USER_DOMAIN or "local"}'))
            conn.commit()
            print(f"🛠️ Default admin '{default_admin}' created (domain auth expected).")
        conn.close()
    except Exception as e:
        print("⚠️ ensure_default_admin error:", e)

# --- Authentication helpers ---
def authenticate_local(username, password):
    """
    Verify local password hash (if stored).
    Returns a User object on success, else None.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash, email, display_name, role FROM dbo.users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        uid, uname, pw_hash, email, display_name, role = row
        if not pw_hash:
            return None
        if bcrypt.verify(password, pw_hash):
            return User(uid, uname, email, display_name, role)
    except Exception as e:
        print("⚠️ authenticate_local error:", e)
    return None

def authenticate_ldap(username, password, timeout=3):
    """
    Try a direct bind to AD using the provided username/password.
    Returns True on success, False otherwise.
    """
    if not AD_SERVER:
        return False

    user_principal = username if ('@' in username or '\\' in username) else f"{username}@{AD_USER_DOMAIN}" if AD_USER_DOMAIN else username

    try:
        server = Server(AD_SERVER, port=AD_PORT, use_ssl=AD_USE_SSL, get_info=ALL, connect_timeout=timeout)
        conn_ldap = Connection(server, user=user_principal, password=password, auto_bind=True)
        conn_ldap.unbind()
        return True
    except Exception as e:
        print("⚠️ LDAP bind failed:", e)
        return False

# --- Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already authenticated, go to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('main_menu'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Basic presence check
        if not username or not password:
            flash("Please enter username and password.")
            return redirect(url_for('login'))

        # Check local registration
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, email, display_name, role, status, password_hash
                FROM dbo.users WHERE username = ?
            """, (username,))
            row = cursor.fetchone()
            conn.close()
        except Exception as e:
            print("⚠️ DB error during login lookup:", e)
            flash("System error. Contact administrator.")
            return redirect(url_for('login'))

        if not row:
            flash("❌ User not registered. Contact admin.")
            log_audit("LOGIN_FAILED", f"Unregistered user attempted login: {username}")
            return redirect(url_for('login'))

        user_id, uname, email, display_name, role, status, password_hash = row

        if (status or '').lower() != 'active':
            flash("⚠️ Account inactive. Contact administrator.")
            log_audit("LOGIN_FAILED", f"Inactive user attempted login: {username}")
            return redirect(url_for('login'))

        # Try LDAP (domain) authentication first
        ad_ok = False
        if AD_SERVER:
            ad_ok = authenticate_ldap(username, password)

        # If AD failed, try local password (dev fallback)
        auth_source = "Active Directory"

        if not ad_ok:
            if password_hash and bcrypt.verify(password, password_hash):
                ad_ok = True
                auth_source = "Local DB"
                print("🔑 Local password fallback used.")
            else:
                flash("❌ Invalid credentials.")
                log_audit("LOGIN_FAILED", f"Invalid credentials for {username}")
                return redirect(url_for('login'))

        # Successful login
        user = User(user_id, uname, email, display_name, role)
        session['auth_source'] = auth_source
        login_user(user)
        flash(f"✅ Welcome {display_name or uname}!")
        log_audit("LOGIN_SUCCESS", f"User {username} logged in via {auth_source}")
        return redirect(url_for('main_menu'))



    # GET -> render form
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit("LOGOUT", f"User {current_user.username} logged out.")
    logout_user()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

# User maintenance (admin-only)
@app.route('/user_maintenance', methods=['GET', 'POST'])
@login_required
def user_maintenance():
    if not current_user.is_admin():
        flash("Access denied: Admins only.")
        return redirect(url_for('main_menu'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # POST -> add user
        if request.method == 'POST':
            username = request.form['username'].strip()
            email = request.form.get('email')
            display_name = request.form.get('display_name')
            role = request.form.get('role', 'user')
            status = request.form.get('status', 'active')

            cursor.execute("SELECT COUNT(*) FROM dbo.users WHERE username = ?", (username,))
            (exists,) = cursor.fetchone() or (0,)
            if exists:
                flash(f"⚠️ User {username} already exists.")
            else:
                cursor.execute("""
                    INSERT INTO dbo.users (username, email, display_name, role, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, GETDATE(), GETDATE())
                """, (username, email, display_name, role, status))
                conn.commit()
                flash(f"✅ User {username} added successfully.")
                log_audit("USER_ADDED", f"Added user {username} with role {role}")

        # Load all users
        cursor.execute("""
                       SELECT u.id,
                              u.username,
                              u.display_name,
                              u.email,
                              u.role,
                              u.status,
                              u.created_at,
                              ISNULL((SELECT TOP 1
                                  CASE
                                  WHEN details LIKE '%Active Directory%' THEN 'Active Directory'
                                  ELSE 'Local DB'
                                  END
                                  FROM dbo.audit_log a
                                  WHERE a.username = u.username AND a.action = 'LOGIN_SUCCESS'
                                  ORDER BY a.created_at DESC ), 'Never') AS last_login_source
                       FROM dbo.users u
                       ORDER BY u.created_at DESC
                       """)
        users = cursor.fetchall()

        users = cursor.fetchall()
        conn.close()
        return render_template('user_maintenance.html', users=users)
    except Exception as e:
        print("⚠️ user_maintenance error:", e)
        flash("System error while loading users.")
        return redirect(url_for('main_menu'))

@app.route('/user_edit/<int:user_id>', methods=['POST'])
@login_required
def user_edit(user_id):
    if not current_user.is_admin():
        flash("Access denied: Admins only.")
        return redirect(url_for('main_menu'))

    display_name = request.form.get('display_name')
    email = request.form.get('email')
    role = request.form.get('role')
    status = request.form.get('status')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE dbo.users
            SET display_name = ?, email = ?, role = ?, status = ?, updated_at = GETDATE()
            WHERE id = ?
        """, (display_name, email, role, status, user_id))
        conn.commit()
        conn.close()
        log_audit("USER_UPDATED", f"Updated user ID {user_id} ({display_name})")
        flash("✅ User updated successfully.")
    except Exception as e:
        print("⚠️ user_edit error:", e)
        flash("System error while updating user.")
    return redirect(url_for('user_maintenance'))

@app.route('/user_delete/<int:user_id>', methods=['POST'])
@login_required
def user_delete(user_id):
    if not current_user.is_admin():
        flash("Access denied: Admins only.")
        return redirect(url_for('main_menu'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM dbo.users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        log_audit("USER_DELETED", f"Deleted user ID {user_id}")
        flash("🗑️ User deleted successfully.")
    except Exception as e:
        print("⚠️ user_delete error:", e)
        flash("System error while deleting user.")
    return redirect(url_for('user_maintenance'))

# Public (or post-login) rooms list route (rename of previous index)
@app.route('/rooms')
def room_list():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, capacity, location, description, status FROM dbo.rooms WHERE status = 'Active'")
        rooms = cursor.fetchall()
        conn.close()
    except Exception as e:
        print("⚠️ room_list error:", e)
        rooms = []
    return render_template('index.html', rooms=rooms)

# Reservation page
@app.route('/reserve/<int:room_id>', methods=['GET', 'POST'])
@login_required
def reserve(room_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, capacity, location FROM dbo.rooms WHERE id = ?", (room_id,))
        room = cursor.fetchone()
    except Exception as e:
        print("⚠️ reserve load error:", e)
        flash("System error loading room.")
        return redirect(url_for('main_menu'))

    if request.method == 'POST':
        reserved_by = request.form['reserved_by']
        email = request.form['email']
        start_time = request.form['start_time'].replace('T', ' ') + ':00'
        end_time = request.form['end_time'].replace('T', ' ') + ':00'
        remarks = request.form.get('remarks', '')

        try:
            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            now = datetime.now()

            if end_dt <= start_dt:
                flash("⚠️ End time must be later than start time.")
                return redirect(url_for('reserve', room_id=room_id))

            if start_dt < now:
                flash("⚠️ You cannot book a room in the past.")
                return redirect(url_for('reserve', room_id=room_id))

            # check overlap
            cursor.execute("""
                SELECT COUNT(*) FROM dbo.reservations
                WHERE room_id = ? AND status IN ('Pending', 'Approved') AND
                      ((start_time <= ? AND end_time > ?) OR
                       (start_time < ? AND end_time >= ?))
            """, (room_id, start_time, start_time, end_time, end_time))
            (conflict_count,) = cursor.fetchone() or (0,)
            if conflict_count > 0:
                flash("⚠️ This room is already booked during the selected time.")
                return redirect(url_for('reserve', room_id=room_id))

            # insert reservation
            cursor.execute("""
                INSERT INTO dbo.reservations (room_id, reserved_by, email, start_time, end_time, remarks, status)
                VALUES (?, ?, ?, ?, ?, ?, 'Pending')
            """, (room_id, reserved_by, email, start_time, end_time, remarks))
            cursor.connection.commit()
            flash("✅ Reservation submitted successfully! Awaiting approval.")
            log_audit("RESERVATION_CREATED", f"Room {room_id} reserved by {reserved_by}")
            return redirect(url_for('confirm'))
        except Exception as e:
            print("⚠️ reserve POST error:", e)
            flash("System error while creating reservation.")
            return redirect(url_for('reserve', room_id=room_id))
        finally:
            try:
                cursor.close()
                conn.close()
            except Exception:
                pass

    # GET
    try:
        conn.close()
    except Exception:
        pass
    return render_template('reserve.html', room=room)

@app.route('/confirm')
@login_required
def confirm():
    return render_template('confirmation.html')

# --- Admin dashboard ---
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        flash("Access denied: Admins only.")
        return redirect(url_for('main_menu'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                r.id,
                rm.name AS room_name,
                r.reserved_by,
                r.email,
                CONVERT(VARCHAR(19), r.start_time, 120) AS start_time,
                CONVERT(VARCHAR(19), r.end_time, 120) AS end_time,
                r.status,
                r.remarks
            FROM dbo.reservations r
            INNER JOIN dbo.rooms rm ON r.room_id = rm.id
            ORDER BY r.start_time DESC
        """)
        reservations = cursor.fetchall()
        conn.close()
    except Exception as e:
        print("⚠️ admin_dashboard error:", e)
        reservations = []
    return render_template('admin.html', reservations=reservations)

@app.route('/update_status/<int:res_id>/<string:new_status>', methods=['POST'])
@login_required
def update_status(res_id, new_status):
    if not current_user.is_admin():
        flash("Access denied: Admins only.")
        return redirect(url_for('main_menu'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT room_id, start_time, end_time FROM dbo.reservations WHERE id = ?", (res_id,))
        reservation = cursor.fetchone()
        if not reservation:
            flash("❌ Reservation not found.")
            conn.close()
            return redirect(url_for('admin_dashboard'))

        room_id, start_time, end_time = reservation

        if new_status.lower() == 'approved':
            cursor.execute("""
                SELECT COUNT(*) FROM dbo.reservations
                WHERE room_id = ? AND id <> ? AND status = 'Approved' AND
                      ((start_time <= ? AND end_time > ?) OR
                       (start_time < ? AND end_time >= ?))
            """, (room_id, res_id, start_time, start_time, end_time, end_time))
            (conflict_count,) = cursor.fetchone() or (0,)
            if conflict_count > 0:
                flash("⚠️ Cannot approve: another reservation already exists for this time slot.")
                conn.close()
                return redirect(url_for('admin_dashboard'))

        cursor.execute("""
            UPDATE dbo.reservations
            SET status = ?, remarks = CONCAT(ISNULL(remarks,''), CHAR(13) + CHAR(10),
                '[Status changed to ' + ? + ' on ' + CONVERT(VARCHAR(19), GETDATE(), 120) + ']')
            WHERE id = ?
        """, (new_status, new_status, res_id))
        conn.commit()
        conn.close()
        log_audit(f"RESERVATION_{new_status.upper()}", f"Reservation ID {res_id} -> {new_status}")
        flash(f"✅ Reservation #{res_id} has been marked as {new_status}.")
    except Exception as e:
        print("⚠️ update_status error:", e)
        flash("System error while updating reservation.")
    return redirect(url_for('admin_dashboard'))

# --- Dashboard (menu) ---
@app.route('/menu')
@login_required
def main_menu():
    # System status checks
    db_status = "❌ Database Connection Failed"
    ad_status = "⚠️ AD Test Credentials Missing"
    try:
        # DB check
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        db_status = "🟢 Database Connected"
        conn.close()
    except Exception as e:
        print("⚠️ DB check failed:", e)

    try:
        if AD_SERVER and AD_TEST_USER and AD_TEST_PASS:
            server = Server(AD_SERVER, port=AD_PORT, use_ssl=AD_USE_SSL, get_info=ALL, connect_timeout=3)
            conn_ldap = Connection(server, user=AD_TEST_USER, password=AD_TEST_PASS, auto_bind=True)
            ad_status = "🔒 AD Connection OK"
            conn_ldap.unbind()
        else:
            ad_status = "⚠️ AD Test Credentials Missing in .env"
    except Exception as e:
        print("⚠️ AD connection test failed:", e)
        ad_status = "❌ AD Unreachable"

    # Dashboard stats / chart
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM dbo.rooms WHERE status = 'Active'")
        row = cursor.fetchone(); room_count = row[0] if row else 0

        cursor.execute("SELECT COUNT(*) FROM dbo.reservations WHERE status = 'Pending'")
        row = cursor.fetchone(); pending_count = row[0] if row else 0

        cursor.execute("SELECT COUNT(*) FROM dbo.reservations WHERE status = 'Approved'")
        row = cursor.fetchone(); approved_count = row[0] if row else 0

        cursor.execute("SELECT COUNT(*) FROM dbo.reservations WHERE status = 'Cancelled'")
        row = cursor.fetchone(); cancelled_count = row[0] if row else 0

        cursor.execute("""
            SELECT CONVERT(VARCHAR(10), start_time, 120) AS date, status, COUNT(*) AS count
            FROM dbo.reservations
            WHERE start_time >= DATEADD(DAY, -6, CAST(GETDATE() AS date))
            GROUP BY CONVERT(VARCHAR(10), start_time, 120), status
            ORDER BY date ASC
        """)
        rows = cursor.fetchall()
        conn.close()
    except Exception as e:
        print("⚠️ Error loading dashboard data:", e)
        room_count = pending_count = approved_count = cancelled_count = 0
        rows = []

    date_list = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
    date_map = {d: {'Approved': 0, 'Pending': 0} for d in date_list}
    for row in rows:
        date, status, count = row
        if date in date_map:
            date_map[date][status] = count

    chart_labels = date_list
    chart_pending = [date_map[d]['Pending'] for d in date_list]
    chart_approved = [date_map[d]['Approved'] for d in date_list]

    user_info = f"{current_user.display_name or current_user.username} ({current_user.role})"

    auth_source = session.get('auth_source', 'Local DB')  # fallback
    return render_template(
        'menu.html',
        room_count=room_count,
        pending_count=pending_count,
        approved_count=approved_count,
        cancelled_count=cancelled_count,
        chart_labels=chart_labels,
        chart_pending=chart_pending,
        chart_approved=chart_approved,
        db_status=db_status,
        ad_status=ad_status,
        user_info=f"{current_user.display_name or current_user.username} ({current_user.role}, {auth_source})"
    )

# --- Root redirect to login (or menu if already authenticated) ---
@app.route('/')
def root_redirect():
    if current_user.is_authenticated:
        return redirect(url_for('main_menu'))
    return redirect(url_for('login'))

# --- Auto open login page on local dev start ---
def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000/login")

if __name__ == '__main__':
    print("🧩 Initializing WebAXIS System...")
    ensure_default_admin()
    print("🚀 WebAXIS RoomSys running at http://127.0.0.1:5000/login")
    threading.Timer(1.5, open_browser).start()
    app.run(debug=True)
