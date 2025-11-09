# app.py (cleaned & fixed)
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
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

app.permanent_session_lifetime = timedelta(days=7)

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

def rows_to_dicts(cursor):
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]

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

# ✅ Correct version of login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login for AD or local DB users."""
    # If already logged in, go straight to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('main_menu'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        remember = bool(request.form.get('remember'))

        if not username or not password:
            flash("Please enter username and password.")
            return redirect(url_for('login'))

        # --- Authentication Logic ---
        user = None
        ad_ok = False

        # 1. Try LDAP / AD login first (if configured)
        if AD_SERVER:
            ad_ok = authenticate_ldap(username, password)

        # 2. Fallback: local DB authentication
        if ad_ok:
            # pull user details from DB
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, display_name, role FROM dbo.users WHERE username = ?",
                (username,))
            row = cursor.fetchone()
            conn.close()
            if row:
                uid, uname, email, display_name, role = row
                user = User(uid, uname, email, display_name, role)
        else:
            user = authenticate_local(username, password)

        # --- Handle failures ---
        if not user:
            flash("❌ Invalid username or password.")
            log_audit("LOGIN_FAILED", f"Failed login for {username}")
            return redirect(url_for('login'))

        # --- Success ---
        login_user(user, remember=remember)
        log_audit("LOGIN_SUCCESS", f"User {user.username} logged in")
        flash(f"✅ Welcome {user.display_name or user.username}!")
        return redirect(url_for('main_menu'))

    # --- GET request → show login page ---
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_audit("LOGOUT", f"User {current_user.username} logged out.")
    logout_user()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

# User maintenance (admin-only)
# --- Edit User ---
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin():
        flash("Access denied: Admins only.", "warning")
        return redirect(url_for('main_menu'))

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        display_name = request.form['display_name'].strip()
        email = request.form['email'].strip()
        role = request.form['role']
        status = request.form['status']

        try:
            cur.execute("""
                UPDATE dbo.users
                SET display_name = ?, email = ?, role = ?, status = ?, updated_at = GETDATE()
                WHERE id = ?
            """, (display_name, email, role, status, user_id))
            conn.commit()
            flash("✅ User updated successfully.", "success")
            print(f"✅ Updated user ID {user_id}")
            return redirect(url_for('user_maintenance'))
        except Exception as e:
            import traceback
            traceback.print_exc()
            flash(f"⚠️ Error updating user: {e}", "danger")
        finally:
            cur.close()
            conn.close()

    # For GET requests: load the user details into the edit form
    cur.execute("SELECT id, username, display_name, email, role, status FROM dbo.users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()

    if not user:
        flash("⚠️ User not found.", "warning")
        return redirect(url_for('user_maintenance'))

    return render_template('edit_user.html', user=user)



# --- Delete User ---
@app.route('/delete_user/<int:user_id>', methods=['POST', 'GET'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        flash("Access denied: Admins only.")
        return redirect(url_for('main_menu'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM dbo.users WHERE id = ?", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash("🗑️ User deleted successfully.")
    return redirect(url_for('user_maintenance'))


@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if request.method == 'POST':
        print("🧩 Received Add User POST")
        print("Form data:", request.form)

    if not current_user.is_admin():
        flash("Access denied: Admins only.")
        return redirect(url_for('main_menu'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

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

    except Exception as e:
        flash(f"Error adding user: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('user_maintenance'))

@app.route('/user_maintenance', methods=['GET', 'POST'])
@login_required
def user_maintenance():
    if not current_user.is_admin():
        flash("Access denied: Admins only.", "warning")
        return redirect(url_for('main_menu'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Handle POST (Add new user)
        if request.method == 'POST':
            username = request.form['username'].strip()
            email = request.form.get('email')
            display_name = request.form.get('display_name')
            role = request.form.get('role', 'user')
            status = request.form.get('status', 'active')

            cursor.execute("SELECT COUNT(*) FROM dbo.users WHERE username = ?", (username,))
            (exists,) = cursor.fetchone() or (0,)
            if exists:
                flash(f"⚠️ User {username} already exists.", "warning")
            else:
                cursor.execute("""
                    INSERT INTO dbo.users (username, email, display_name, role, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, GETDATE(), GETDATE())
                """, (username, email, display_name, role, status))
                conn.commit()
                flash(f"✅ User {username} added successfully.", "success")
                log_audit("USER_ADDED", f"Added user {username} with role {role}")

        # Fetch all users
        cursor.execute("""
            SELECT id, username, display_name, email, role, status, last_login, last_login_ip
            FROM dbo.users
            ORDER BY created_at DESC
        """)
        users = cursor.fetchall()
        conn.close()

        print(f"📋 Loaded {len(users)} users.")
        return render_template('user_maintenance.html', users=users)

    # except Exception as e:
    #     print("⚠️ user_maintenance error:", e)
    #     flash("System error while loading users.", "danger")
    #     # ✅ Add this redirect or fallback render:
    #     return redirect(url_for('main_menu'))

    except Exception as e:
        print("⚠️ user_maintenance error:", e)
        # Log and show descriptive error
        flash(f"⚠️ A system error occurred while loading users.<br><small>{e}</small>", "danger")
        # ✅ Render the page with an empty user list (so it won't break)
        return render_template('user_maintenance.html', users=[])



@app.route('/user_edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def user_edit(user_id):
    if not current_user.is_admin():
        flash("Access denied: Admins only.")
        return redirect(url_for('main_menu'))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        display_name = request.form.get('display_name')
        email = request.form.get('email')
        role = request.form.get('role')
        status = request.form.get('status')

        try:
            cursor.execute("""
                UPDATE dbo.users
                SET display_name = ?, email = ?, role = ?, status = ?, updated_at = GETDATE()
                WHERE id = ?
            """, (display_name, email, role, status, user_id))
            conn.commit()
            flash("✅ User updated successfully.", "success")
            log_audit("USER_UPDATED", f"Updated user ID {user_id} ({display_name})")
            return redirect(url_for('user_maintenance'))
        except Exception as e:
            flash(f"⚠️ Error updating user: {e}", "danger")
        finally:
            conn.close()

    # --- For GET: Load user info for the form ---
    cursor.execute("SELECT id, username, display_name, email, role, status FROM dbo.users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        flash("⚠️ User not found.", "warning")
        return redirect(url_for('user_maintenance'))

    return render_template("edit_user.html", user=user)


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
from datetime import datetime

@app.route('/rooms')
@login_required
def room_list():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, name, capacity, location, description
            FROM rooms
            ORDER BY location, name
        """)
        rows = cur.fetchall()

        # Convert Row objects into dictionaries for JSON-safe use
        rooms = []
        for r in rows:
            rooms.append({
                "id": r.id,
                "name": r.name,
                "capacity": r.capacity,
                "location": r.location,
                "description": r.description
            })

        conn.close()

        # ✅ Pass rooms + now() function for the date picker
        return render_template("index.html", rooms=rooms, now=datetime.utcnow)

    except Exception as e:
        print(f"⚠️ Error loading room list: {e}")
        flash("Error loading rooms.", "danger")
        return redirect(url_for("main_menu"))


@app.route('/reserve/<int:room_id>', methods=['GET', 'POST'])
@login_required
def reserve(room_id):
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # 🧩 Fetch all rooms with parent and subgroup info
        cur.execute("""
            SELECT id, name, capacity, location, description, group_name, parent_group
            FROM rooms
            ORDER BY parent_group, group_name, name
        """)
        all_rooms = [
            {
                "id": r[0],
                "name": r[1],
                "capacity": r[2],
                "location": r[3],
                "description": r[4],
                "group_name": r[5] or "General",
                "parent_group": r[6] or "Unassigned"
            }
            for r in cur.fetchall()
        ]

        # 🧱 Nest by parent_group → group_name
        room_hierarchy = {}
        for r in all_rooms:
            parent = r["parent_group"]
            group = r["group_name"]
            room_hierarchy.setdefault(parent, {}).setdefault(group, []).append(r)

        # 🎯 Get current room info
        cur.execute("""
            SELECT id, name, capacity, location, description, group_name, parent_group
            FROM rooms
            WHERE id = ?
        """, (room_id,))
        row = cur.fetchone()
        if not row:
            flash("Room not found.", "warning")
            return redirect(url_for('room_list'))

        room = {
            "id": row[0],
            "name": row[1],
            "capacity": row[2],
            "location": row[3],
            "description": row[4],
            "group_name": row[5],
            "parent_group": row[6]
        }

        # 🧾 Handle reservation submission
        if request.method == 'POST':
            reserved_by = request.form['reserved_by']
            email = request.form['email']
            start_time = request.form['start_time']
            end_time = request.form['end_time']
            remarks = request.form.get('remarks', '')

            from datetime import datetime
            start_dt = datetime.strptime(start_time, "%Y-%m-%dT%H:%M")
            end_dt = datetime.strptime(end_time, "%Y-%m-%dT%H:%M")

            # Check overlap
            cur.execute("""
                SELECT COUNT(*) FROM reservations
                WHERE room_id = ? AND status != 'Cancelled'
                AND ((start_time < ? AND end_time > ?)
                     OR (start_time >= ? AND start_time < ?)
                     OR (end_time > ? AND end_time <= ?))
            """, (room_id, end_dt, start_dt, start_dt, end_dt, start_dt, end_dt))
            (conflict,) = cur.fetchone()
            if conflict > 0:
                flash("⚠️ Schedule conflict: This slot is already booked.", "warning")
                return redirect(url_for('reserve', room_id=room_id))

            # Insert new reservation
            cur.execute("""
                INSERT INTO reservations (room_id, reserved_by, email, start_time, end_time, status, remarks, created_at)
                VALUES (?, ?, ?, ?, ?, 'Pending', ?, GETDATE())
            """, (room_id, reserved_by, email, start_dt, end_dt, remarks))
            conn.commit()
            flash("✅ Reservation successfully submitted and pending approval.", "success")
            return redirect(url_for('room_list'))

        # Fetch today's booked slots
        cur.execute("""
            SELECT reserved_by,
                   CONVERT(VARCHAR(5), start_time, 108) AS start_time,
                   CONVERT(VARCHAR(5), end_time, 108) AS end_time,
                   status
            FROM reservations
            WHERE room_id = ? AND CONVERT(date, start_time) = CONVERT(date, GETDATE())
              AND status != 'Cancelled'
            ORDER BY start_time
        """, (room_id,))
        booked_slots = cur.fetchall()

        conn.close()
        return render_template(
            'reserve.html',
            room=room,
            room_hierarchy=room_hierarchy,
            booked_slots=booked_slots
        )

    except Exception as e:
        print(f"⚠️ reserve error: {e}")
        flash("System error while loading reservation page.", "danger")
        return redirect(url_for('room_list'))

@app.route('/reservation/<int:reservation_id>/<string:action>', methods=['GET'])
@login_required
def update_reservation_status(reservation_id, action):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if action == 'approve':
            cur.execute("""
                UPDATE reservations
                SET status = 'Approved', updated_at = GETDATE()
                WHERE id = ?
            """, (reservation_id,))
            conn.commit()
            flash("✅ Reservation approved successfully!", "success")

        elif action == 'cancel':
            cur.execute("""
                UPDATE reservations
                SET status = 'Cancelled', updated_at = GETDATE()
                WHERE id = ?
            """, (reservation_id,))
            conn.commit()
            flash("❌ Reservation cancelled.", "warning")

        conn.close()
    except Exception as e:
        print(f"⚠️ Error updating reservation: {e}")
        flash("⚠️ Error while updating reservation.", "danger")

    return redirect(url_for('admin_dashboard'))


@app.route('/api/booked_slots')
@login_required
def api_booked_slots():
    """Return all bookings for a given room and date for visual timeline."""
    try:
        room_id = int(request.args.get('room_id', 0))
        date_str = request.args.get('date')
        if not room_id or not date_str:
            return jsonify({'error': 'Missing parameters'}), 400

        conn = get_db_connection()
        cur = conn.cursor()
        sql = """
            SELECT reserved_by,
                   CONVERT(VARCHAR(5), start_time, 108) AS start_time,
                   CONVERT(VARCHAR(5), end_time, 108) AS end_time,
                   status
            FROM reservations
            WHERE room_id = ?
              AND CONVERT(date, start_time) = ?
              AND status != 'Cancelled'
            ORDER BY start_time
        """
        cur.execute(sql, (room_id, date_str))
        rows = cur.fetchall()
        conn.close()

        slots = [
            {
                'reserved_by': r[0],
                'start_time': r[1],
                'end_time': r[2],
                'status': r[3]
            }
            for r in rows
        ]
        return jsonify({'slots': slots})
    except Exception as e:
        print(f"⚠️ api_booked_slots error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route("/api/room_availability/<int:room_id>")
@login_required
def api_room_availability(room_id):
    try:
        selected_date = request.args.get("date")
        if not selected_date:
            from datetime import datetime
            selected_date = datetime.now().strftime("%Y-%m-%d")

        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Add reserved_by column
        sql = """
            SELECT 
                CONVERT(VARCHAR(5), start_time, 108) AS start_time,
                CONVERT(VARCHAR(5), end_time, 108) AS end_time,
                reserved_by,
                status
            FROM reservations
            WHERE room_id = ? AND CAST(start_time AS DATE) = ?
        """
        cur.execute(sql, (room_id, selected_date))
        rows = cur.fetchall()
        conn.close()

        results = []
        for r in rows:
            results.append({
                "start": r.start_time,
                "end": r.end_time,
                "reserved_by": r.reserved_by,
                "status": r.status
            })

        return jsonify(results)
    except Exception as e:
        print(f"⚠️ Error loading room availability for {room_id}: {e}")
        return jsonify([])




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

    conn = get_db_connection()
    cur = conn.cursor()
    parent_filter = request.args.get('parent_group', '')

    # --- Base Query ---
    sql = """
        SELECT r.id, rm.name AS room_name, rm.parent_group, r.reserved_by, r.email, 
               r.start_time, r.end_time, r.status, r.remarks
        FROM reservations r
        JOIN rooms rm ON r.room_id = rm.id
    """
    params = []
    if parent_filter:
        sql += " WHERE rm.parent_group = ?"
        params.append(parent_filter)

    sql += " ORDER BY r.created_at DESC"
    cur.execute(sql, params)
    reservations = cur.fetchall()

    # --- Stats for cards ---
    cur.execute("SELECT COUNT(*) FROM reservations")
    (total_reservations,) = cur.fetchone()

    cur.execute("SELECT COUNT(*) FROM reservations WHERE status='Approved'")
    (total_approved,) = cur.fetchone()

    cur.execute("SELECT COUNT(*) FROM reservations WHERE status='Pending'")
    (total_pending,) = cur.fetchone()

    cur.execute("SELECT COUNT(*) FROM reservations WHERE status='Cancelled'")
    (total_cancelled,) = cur.fetchone()

    # --- Chart 1: Reservation Status Distribution ---
    cur.execute("""
        SELECT status, COUNT(*) 
        FROM reservations
        GROUP BY status
    """)
    status_data = cur.fetchall()
    status_labels = [row[0] for row in status_data]
    status_counts = [row[1] for row in status_data]

    # --- Chart 2: Room Utilization by Location ---
    cur.execute("""
        SELECT rm.parent_group, COUNT(*) 
        FROM reservations r
        JOIN rooms rm ON r.room_id = rm.id
        GROUP BY rm.parent_group
        ORDER BY rm.parent_group
    """)
    loc_data = cur.fetchall()
    loc_labels = [row[0] for row in loc_data]
    loc_counts = [row[1] for row in loc_data]

    # --- Load parent groups for filter dropdown ---
    cur.execute("SELECT DISTINCT parent_group FROM rooms ORDER BY parent_group")
    parent_groups = [r[0] for r in cur.fetchall()]

    conn.close()

    return render_template(
        'admin.html',
        reservations=reservations,
        parent_groups=parent_groups,
        total_reservations=total_reservations,
        total_approved=total_approved,
        total_pending=total_pending,
        total_cancelled=total_cancelled,
        status_labels=status_labels,
        status_counts=status_counts,
        loc_labels=loc_labels,
        loc_counts=loc_counts
    )



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



# helper to parse HTML datetime-local format 'YYYY-MM-DDTHH:MM'
def _parse_local_dt(dt_str):
    # dt_str comes like "2025-11-09T17:33"
    try:
        return datetime.strptime(dt_str, '%Y-%m-%dT%H:%M')
    except Exception:
        return None

@app.route('/api/check_slot', methods=['POST', 'GET'])
@login_required
def api_check_slot():
    """
    POST JSON: { room_id: int, start_time: 'YYYY-MM-DDTHH:MM', end_time: 'YYYY-MM-DDTHH:MM' }
    Querystring also supported for quick testing.
    """
    try:
        if request.is_json:
            payload = request.get_json()
            room_id = int(payload.get('room_id'))
            start_s = payload.get('start_time')
            end_s = payload.get('end_time')
        else:
            room_id = int(request.values.get('room_id'))
            start_s = request.values.get('start_time')
            end_s = request.values.get('end_time')

        start_dt = _parse_local_dt(start_s)
        end_dt = _parse_local_dt(end_s)

        if not room_id or not start_dt or not end_dt:
            return jsonify({'error': 'invalid parameters'}), 400

        if end_dt <= start_dt:
            return jsonify({'available': False, 'reason': 'end_before_start', 'conflicts': 0})

        conn = get_db_connection()
        cur = conn.cursor()

        sql = """
            SELECT COUNT(*) FROM reservations
            WHERE room_id = ?
              AND status != 'Cancelled'
              AND NOT (end_time <= ? OR start_time >= ?)
        """
        # Use dt.isoformat(' ') : SQL Server accepts 'YYYY-MM-DD HH:MM:SS' string
        params = (room_id, end_dt.strftime('%Y-%m-%d %H:%M:%S'), start_dt.strftime('%Y-%m-%d %H:%M:%S'))
        cur.execute(sql, params)
        (conflicts,) = cur.fetchone() or (0,)

        conn.close()
        return jsonify({'available': (conflicts == 0), 'conflicts': int(conflicts)})
    except Exception as e:
        app.logger.exception("api_check_slot error")
        return jsonify({'error': str(e)}), 500

@app.route('/room_schedule', methods=['GET'])
@login_required
def room_schedule():
    conn = get_db_connection()
    cur = conn.cursor()

    date_str = request.args.get('date')
    if date_str:
        try:
            selected_date = datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            selected_date = datetime.utcnow()
    else:
        selected_date = datetime.utcnow()

    # day window
    start_day = selected_date.replace(hour=0, minute=0, second=0, microsecond=0)
    end_day = start_day + timedelta(days=1)

    # fetch rooms
    cur.execute("SELECT id, name, building, capacity, location, description FROM dbo.rooms ORDER BY building, name")
    raw_rooms = cur.fetchall()
    rooms = []
    for r in raw_rooms:
        rooms.append({
            "id": r.id,
            "name": getattr(r, 'name', r[1]) if hasattr(r,'id') else r[1],
            "building": getattr(r, 'building', r[2]) if hasattr(r,'id') else r[2],
            "capacity": getattr(r, 'capacity', r[3]) if hasattr(r,'id') else r[3],
            "location": getattr(r, 'location', r[4]) if hasattr(r,'id') else r[4],
            "description": getattr(r, 'description', r[5]) if hasattr(r,'id') else r[5],
        })

    # fetch reservations for selected day
    cur.execute("""
        SELECT id, room_id, reserved_by, email, start_time, end_time, status, remarks, purpose
        FROM dbo.reservations
        WHERE start_time < ? AND end_time > ?
    """, (end_day, start_day))
    raw_res = cur.fetchall()
    reservations = []
    for rr in raw_res:
        # convert DB row to dictionary and format datetimes to ISO strings
        reservations.append({
            "id": rr.id,
            "room_id": rr.room_id,
            "reserved_by": rr.reserved_by,
            "email": rr.email,
            "start_time": rr.start_time.isoformat() if isinstance(rr.start_time, datetime) else str(rr.start_time),
            "end_time": rr.end_time.isoformat() if isinstance(rr.end_time, datetime) else str(rr.end_time),
            "status": rr.status,
            "remarks": rr.remarks,
            "purpose": getattr(rr, 'purpose', None),
        })

    conn.close()
    return render_template('room_schedule.html',
                           rooms=rooms,
                           reservations=reservations,
                           selected_date=selected_date)

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
    """Root route — sends authenticated users to dashboard, others to login."""
    try:
        if current_user.is_authenticated:
            return redirect(url_for('main_menu'))
    except Exception:
        pass
    return redirect(url_for('login'))


# --- Auto open login page on local dev start ---
def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000/login")


if __name__ == '__main__':
    print("🧩 Initializing WebAXIS System...")
    ensure_default_admin()

    is_dev = os.getenv("FLASK_ENV", "development").lower() == "development"
    print(f"💻 Running in {'Development' if is_dev else 'Production'} mode")
    print("🚀 WebAXIS RoomSys available at http://127.0.0.1:5000/login")

    # ✅ Auto-open only in dev mode (avoids Docker/server issues)
    if is_dev and os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        threading.Timer(1.5, open_browser).start()

    app.run(debug=is_dev, use_reloader=False)
