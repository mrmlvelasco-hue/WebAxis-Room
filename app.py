# app.py (final)
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from dotenv import load_dotenv
import os
import pyodbc
from datetime import datetime, timedelta, timezone, date, time as datetime_time
import webbrowser
import threading
from dateutil import parser as dateparser  # pip install python-dateutil

from dateutil.rrule import rrule, rruleset, DAILY, WEEKLY, MONTHLY
from dateutil.relativedelta import relativedelta


import uuid



from flask_login import (
    LoginManager, UserMixin,
    login_user, logout_user, login_required, current_user
)

from passlib.hash import bcrypt
from ldap3 import Server, Connection, ALL

load_dotenv()

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

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY or os.urandom(24)
app.permanent_session_lifetime = timedelta(days=7)
NATIONAL_ADMINS = ['admin', 'systemadmin']  # add more if needed


def get_db_connection():
    """
    Cross-platform SQL Server connection.
    FreeTDS for Linux (Docker), ODBC17/18/NativeClient for Windows.
    Compatible with SQL Server 2008.
    """
    import platform

    # --- Windows (PyCharm local dev) ---
    if platform.system() == "Windows":
        # Try Driver 17/18
        possible_drivers = [
            "{ODBC Driver 18 for SQL Server}",
            "{ODBC Driver 17 for SQL Server}",
            "{SQL Server Native Client 11.0}",
            "{SQL Server}"
        ]
        driver = None

        for d in possible_drivers:
            try:
                pyodbc.connect(
                    f"DRIVER={d};SERVER={DB_HOST};UID={DB_USERNAME};PWD={DB_PASSWORD};",
                    timeout=1
                )
                driver = d
                break
            except:
                pass

        if not driver:
            raise Exception("No usable SQL Server ODBC driver found in Windows.")

        conn_str = (
            f"DRIVER={driver};"
            f"SERVER={DB_HOST};"
            f"DATABASE={DB_DATABASE};"
            f"UID={DB_USERNAME};"
            f"PWD={DB_PASSWORD};"
            "Encrypt=no;"
            "TrustServerCertificate=yes;"
        )
        return pyodbc.connect(conn_str, autocommit=False)

    # --- Linux (Docker) → Use FreeTDS ---
    else:
        conn_str = (
            "DRIVER={FreeTDS};"
            f"SERVER={DB_HOST};"
            f"DATABASE={DB_DATABASE};"
            f"UID={DB_USERNAME};"
            f"PWD={DB_PASSWORD};"
            "Port=1433;"
            "TDS_Version=7.3;"
        )
        return pyodbc.connect(conn_str, autocommit=False)



login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

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

def get_group_approver(group_code):
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT TOP 1 approver_username FROM dbo.group_approvers WHERE group_code = ? AND is_primary = 1 ORDER BY id DESC", (group_code,))
        row = cur.fetchone(); conn.close()
        return row[0] if row else None
    except Exception as e:
        print("⚠️ get_group_approver error:", e)
        return None
def get_approvers_for_location(location_name):
    """
    Returns list of approvers for a given location.
    Uses group_approvers table where group_code == location_name.
    Only returns active approvers.
    """
    print("⚠️ Approver Location_name:", location_name)
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT approver_username
            FROM dbo.group_approvers
            WHERE group_code = ? AND is_active = 1
        """, (location_name,))
        rows = cur.fetchall()
        conn.close()
        return [r[0] for r in rows]
    except Exception as e:
        print("⚠️ get_approvers_for_location error:", e)
        return []

def is_user_group_admin(username, group_code):
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM dbo.group_approvers WHERE group_code = ? AND approver_username = ?", (group_code, username))
        row = cur.fetchone(); conn.close()
        return (row[0] if row else 0) > 0
    except Exception as e:
        print("⚠️ is_user_group_admin error:", e)
        return False
# is_admin = (current_user.username.lower() == "admin")
@app.route('/approvals/<int:res_id>/approve', methods=['POST'])
@login_required
def approve_reservation(res_id):
    username = current_user.username.lower()

    is_national_admin = username in [a.lower() for a in NATIONAL_ADMINS]

    conn = get_db_connection()
    cur = conn.cursor()
    # Load user's assigned locations
    cur = conn.cursor()
    cur.execute("""
        SELECT ul.location_name
        FROM user_locations ul
        JOIN users u ON ul.user_id = u.id
        WHERE u.username = ?
    """, (username,))
    assigned_locations = [row[0] for row in cur.fetchall()]


    # Fetch reservation + location
    cur.execute("""
        SELECT r.room_id, rm.location, r.status
        FROM reservations r
        JOIN rooms rm ON r.room_id = rm.id
        WHERE r.id = ?
    """, (res_id,))
    row = cur.fetchone()

    if not row:
        conn.close()
        flash("Reservation not found.", "danger")
        return redirect(url_for('approvals'))

    room_id, location, status = row

    if status != 'Pending':
        conn.close()
        flash("Reservation no longer pending.", "warning")
        return redirect(url_for('approvals'))

    # National admin → full approve rights
    if is_national_admin:
        cur.execute("""
            UPDATE reservations
            SET status='Approved', approved_by=?, approved_at=GETDATE()
            WHERE id=?
        """, (username, res_id))
        conn.commit()
        conn.close()
        flash("✔ Approved (National Admin)", "success")
        return redirect(url_for('approvals'))

    # Local approver check
    cur.execute("""
        SELECT COUNT(*)
        FROM group_approvers
        WHERE group_code = ? AND approver_username = ? AND is_active = 1
    """, (location, username))
    (is_approver,) = cur.fetchone()

    # Location assignment check
    cur.execute("""
        SELECT COUNT(*)
        FROM user_locations ul
        JOIN users u ON ul.user_id = u.id
        WHERE ul.location_name = ? AND u.username = ?
    """, (location, username))
    (in_location,) = cur.fetchone()

    # # Load user’s assigned locations
    # cur = conn.cursor()
    # cur.execute("""
    #     SELECT ul.location_name
    #     FROM user_locations ul
    #     JOIN users u ON ul.user_id = u.id
    #     WHERE u.username = ?
    # """, (username,))
    # assigned_locations = [row[0] for row in cur.fetchall()]

    if not (is_approver and in_location):
        conn.close()
        flash("❌ You are not authorized to approve this reservation.", "danger")
        return redirect(url_for('approvals'))

    # Authorized approver approves
    cur.execute("""
        UPDATE reservations
        SET status='Approved', approved_by=?, approved_at=GETDATE()
        WHERE id=?
    """, (username, res_id))
    conn.commit()
    conn.close()

    flash("✔ Reservation approved", "success")
    return redirect(url_for('approvals'))

@app.route('/approvals')
@login_required
def approvals():
    username = current_user.username.lower()
    is_national_admin = username in [a.lower() for a in NATIONAL_ADMINS]

    filter_location = request.args.get("location", "").strip()
    filter_room = request.args.get("room", "").strip()
    search_text = request.args.get("search", "").strip()
    filter_date = request.args.get("date", "").strip()

    conn = get_db_connection()
    cur = conn.cursor()

    # Load user’s assigned locations (SECTION C1)
    cur.execute("""
        SELECT ul.location_name
        FROM user_locations ul
        JOIN users u ON ul.user_id = u.id
        WHERE u.username = ?
    """, (username,))
    assigned_locations = [row[0] for row in cur.fetchall()]

    # Base SQL
    sql = """
        SELECT r.id, r.room_id, rm.name AS room_name, rm.location,
               r.reserved_by, r.start_time, r.end_time, r.remarks,
               r.status, r.approver_username
        FROM dbo.reservations r
        JOIN dbo.rooms rm ON r.room_id = rm.id
        WHERE r.status = 'Pending'
    """
    params = []

    # National admin sees ALL
    if not is_national_admin:
        sql += """
            AND (
                r.approver_username = ?
                OR ? IN (
                    SELECT approver_username
                    FROM dbo.group_approvers
                    WHERE group_code = rm.location AND is_active = 1
                )
            )
            AND rm.location IN (
                SELECT ul.location_name 
                FROM user_locations ul 
                JOIN users u ON ul.user_id = u.id
                WHERE u.username = ?
            )
        """
        params.extend([username, username, username])

    # Filters
    if filter_location:
        sql += " AND rm.location = ?"
        params.append(filter_location)

    if filter_room:
        sql += " AND rm.name = ?"
        params.append(filter_room)

    if filter_date:
        sql += " AND CAST(r.start_time AS DATE) = ?"
        params.append(filter_date)

    if search_text:
        sql += " AND (r.reserved_by LIKE ? OR rm.name LIKE ? OR r.remarks LIKE ?)"
        s = f"%{search_text}%"
        params.extend([s, s, s])

    sql += " ORDER BY rm.location, r.start_time"
    cur.execute(sql, params)
    rows = rows_to_dicts(cur)

    # Dropdown lists
    cur.execute("SELECT DISTINCT location FROM rooms ORDER BY location")
    locations = [r[0] for r in cur.fetchall()]

    cur.execute("SELECT DISTINCT name FROM rooms ORDER BY name")
    rooms = [r[0] for r in cur.fetchall()]

    # Pending count for sidebar
    cur.execute("SELECT COUNT(*) FROM reservations WHERE status='Pending'")
    (pending_count,) = cur.fetchone()

    conn.close()

    # PASS assigned_locations TO TEMPLATE (SECTION C2)
    return render_template(
        "approvals.html",
        reservations=rows,
        locations=locations,
        rooms=rooms,
        assigned_locations=assigned_locations,
        pending_count=pending_count,
        filter_location=filter_location,
        filter_room=filter_room,
        filter_date=filter_date,
        search_text=search_text,
        is_admin=is_national_admin
    )



# @app.route('/approvals/<int:res_id>/approve', methods=['POST'])
# @login_required
# def approve_reservation(res_id):
#     username = current_user.username
#     # is_admin = (current_user.role.lower() == "admin")
#     is_admin = (current_user.username.lower() == "admin")
#
#     conn = get_db_connection()
#     cur = conn.cursor()
#
#     # Fetch reservation & room info
#     cur.execute("""
#         SELECT r.room_id, rm.location, r.status
#         FROM reservations r
#         JOIN rooms rm ON r.room_id = rm.id
#         WHERE r.id = ?
#     """, (res_id,))
#     row = cur.fetchone()
#
#     if not row:
#         conn.close()
#         flash("Reservation not found.", "danger")
#         return redirect(url_for('approvals'))
#
#     room_id, location, status = row
#
#     # Cannot approve cancelled/approved items
#     if status != 'Pending':
#         conn.close()
#         flash("Reservation is not pending.", "warning")
#         return redirect(url_for('approvals'))
#
#     # Admin override — can approve everything
#     if is_admin:
#         cur.execute("""
#             UPDATE reservations
#             SET status = 'Approved', approved_by = ?, approved_at = GETDATE()
#             WHERE id = ?
#         """, (username, res_id))
#         conn.commit()
#         conn.close()
#         flash("✔ Reservation approved (Admin override).", "success")
#         return redirect(url_for('approvals'))
#
#     # Check if user is location approver
#     cur.execute("""
#         SELECT COUNT(*) FROM group_approvers
#         WHERE group_code = ? AND approver_username = ? AND is_active = 1
#     """, (location, username))
#     (is_location_approver,) = cur.fetchone()
#
#     # Check if user is assigned to the location
#     cur.execute("""
#         SELECT COUNT(*)
#         FROM user_locations ul
#         JOIN users u ON ul.user_id = u.id
#         WHERE ul.location_name = ? AND u.username = ?
#     """, (location, username))
#     (is_assigned_to_location,) = cur.fetchone()
#
#     if not (is_location_approver and is_assigned_to_location):
#         conn.close()
#         flash("❌ You are not authorized to approve this reservation.", "danger")
#         return redirect(url_for('approvals'))
#
#     # Authorized approver
#     cur.execute("""
#         UPDATE reservations
#         SET status = 'Approved', approved_by = ?, approved_at = GETDATE()
#         WHERE id = ?
#     """, (username, res_id))
#     conn.commit()
#     conn.close()
#
#     flash("✔ Reservation approved successfully!", "success")
#     return redirect(url_for('approvals'))


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

@app.route('/approvals/<int:res_id>/deny', methods=['POST'])
@login_required
def deny_reservation(res_id):
    username = current_user.username.lower()
    is_national_admin = username in [a.lower() for a in NATIONAL_ADMINS]

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT r.room_id, rm.location, r.status
        FROM reservations r
        JOIN rooms rm ON r.room_id = rm.id
        WHERE r.id = ?
    """, (res_id,))
    row = cur.fetchone()

    if not row:
        conn.close()
        flash("Not found", "danger")
        return redirect(url_for('approvals'))

    room_id, location, status = row

    if status != 'Pending':
        conn.close()
        flash("Reservation not pending.", "warning")
        return redirect(url_for('approvals'))

    if is_national_admin:
        cur.execute("""
            UPDATE reservations
            SET status='Cancelled', approved_by=?, approved_at=GETDATE()
            WHERE id=?
        """, (username, res_id))
        conn.commit()
        conn.close()
        flash("❌ Denied (National Admin)", "info")
        return redirect(url_for('approvals'))

    cur.execute("""
        SELECT COUNT(*)
        FROM group_approvers
        WHERE group_code = ? AND approver_username = ? AND is_active = 1
    """, (location, username))
    (is_approver,) = cur.fetchone()

    cur.execute("""
        SELECT COUNT(*)
        FROM user_locations ul
        JOIN users u ON ul.user_id = u.id
        WHERE ul.location_name = ? AND u.username = ?
    """, (location, username))
    (in_location,) = cur.fetchone()

    if not (is_approver and in_location):
        conn.close()
        flash("❌ Not authorized to deny this.", "danger")
        return redirect(url_for('approvals'))

    cur.execute("""
        UPDATE reservations
        SET status='Cancelled', approved_by=?, approved_at=GETDATE()
        WHERE id=?
    """, (username, res_id))
    conn.commit()
    conn.close()

    flash("❌ Reservation denied", "info")
    return redirect(url_for('approvals'))



@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, display_name, role FROM dbo.users WHERE id = ?", (int(user_id),))
        row = cursor.fetchone(); conn.close()
        if row:
            uid, username, email, display_name, role = row
            return User(uid, username, email, display_name, role)
    except Exception as e:
        print("⚠️ load_user error:", e)
    return None

def log_audit(action, details=None):
    try:
        conn = get_db_connection(); cursor = conn.cursor()
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
            print("⚠️ Audit log insert failed (check dbo.audit_log exists):", e)
        finally:
            conn.close()
    except Exception as e:
        print("⚠️ Audit logging failed (DB connection):", e)

def ensure_default_admin():
    try:
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM dbo.users WHERE role = 'admin'")
        row = cursor.fetchone(); admin_count = row[0] if row else 0
        if admin_count == 0:
            default_admin = "admin"
            cursor.execute("""
                INSERT INTO dbo.users (username, display_name, email, role, status)
                VALUES (?, ?, ?, 'admin', 'active')
            """, (default_admin, 'System Administrator', f'{default_admin}@{AD_USER_DOMAIN or "local"}'))
            conn.commit()
            print(f"🛠️ Default admin '{default_admin}' created.")
        conn.close()
    except Exception as e:
        print("⚠️ ensure_default_admin error:", e)

def authenticate_local(username, password):
    try:
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, email, display_name, role FROM dbo.users WHERE username = ?", (username,))
        row = cursor.fetchone(); conn.close()
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
def is_approval_required_for_room(room_id):
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT approvals_required, location FROM rooms WHERE id = ?", (room_id,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return True  # default safety

        room_flag = row[0]     # may be NULL
        location = row[1]

        # room override
        if room_flag is not None:
            return bool(room_flag)

        # fallback: location approval rule
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT approvals_required FROM locations WHERE name = ?", (location,))
        loc_row = cur.fetchone()
        conn.close()

        if loc_row is not None:
            return bool(loc_row[0])

        return True
    except:
        return True


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main_menu'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        remember = bool(request.form.get('remember'))
        if not username or not password:
            flash("Please enter username and password.")
            return redirect(url_for('login'))
        user = None
        ad_ok = False
        if AD_SERVER:
            ad_ok = True
            # ad_ok = authenticate_ldap(username, password)
        if ad_ok:
            conn = get_db_connection(); cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, display_name, role FROM dbo.users WHERE username = ?", (username,))
            row = cursor.fetchone(); conn.close()
            if row:
                uid, uname, email, display_name, role = row
                user = User(uid, uname, email, display_name, role)
        else:
            user = authenticate_local(username, password)
        if not user:
            flash("❌ Invalid username or password.")
            log_audit("LOGIN_FAILED", f"Failed login for {username}")
            return redirect(url_for('login'))
        login_user(user, remember=remember)
        log_audit("LOGIN_SUCCESS", f"User {user.username} logged in")
        flash(f"✅ Welcome {user.display_name or user.username}!")
        return redirect(url_for('main_menu'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit("LOGOUT", f"User {current_user.username} logged out.")
    logout_user()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

@app.route('/rooms/maintenance')
@login_required
def room_maintenance():
    if not current_user.is_admin():
        flash("Not authorized.", "danger")
        return redirect(url_for('main_menu'))

    conn = get_db_connection()
    cur = conn.cursor()

    # Load rooms
    cur.execute("""
        SELECT id, name, location, group_code, capacity, is_combined, status,
               approvals_required
        FROM rooms
        ORDER BY location, name
    """)
    rooms = rows_to_dicts(cur)

    # Load locations for dropdowns
    cur.execute("SELECT DISTINCT location FROM rooms ORDER BY location")
    locations = [row[0] for row in cur.fetchall()]

    # Try to load room_approvers if table exists, otherwise keep empty dict
    room_approvers = {}
    try:
        cur.execute("""
            SELECT room_id, approver_username
            FROM room_approvers
            WHERE is_active = 1
        """)
        for r in cur.fetchall():
            room_id = r[0]
            approver = r[1]
            room_approvers.setdefault(room_id, []).append(approver)
    except Exception as e:
        # If table missing or other error, log and continue with empty approvers map
        print("⚠️ room_approvers not available or query failed:", e)
        room_approvers = {}

    conn.close()

    return render_template(
        "room_maintenance.html",
        rooms=rooms,
        locations=locations,
        room_approvers=room_approvers
    )


@app.route('/rooms/add', methods=['POST'])
@login_required
def add_room():
    if not getattr(current_user, 'is_admin', lambda: False)():
        flash("Not authorized.", "danger"); return redirect(url_for('menu'))
    name = request.form['name']
    group_code = request.form.get('group_code') or None
    capacity = int(request.form.get('capacity') or 0)
    approver = request.form.get('approver') or None
    is_combined = 1 if request.form.get('is_combined') else 0
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("INSERT INTO dbo.rooms (name, location, capacity, group_code, description, status, is_combined) VALUES (?, ?, ?, ?, ?, 'Active', ?)",
                (name, group_code or name, capacity, group_code, '', is_combined))
    conn.commit()
    if approver and group_code:
        cur.execute("INSERT INTO dbo.group_approvers (group_code, approver_username, is_primary) VALUES (?, ?, 1)", (group_code, approver))
        conn.commit()
    conn.close()
    flash("Room added.", "success")
    return redirect(url_for('room_maintenance'))

@app.route('/rooms/edit/<int:id>', methods=['POST'])
@login_required
def edit_room(id):
    if getattr(current_user, 'role', '').lower() != 'admin':
        flash("Not authorized.", "danger")
        return redirect(url_for('room_maintenance'))
    name = request.form['name']
    location = request.form['location']
    group_code = request.form.get('group_code') or None
    capacity = int(request.form.get('capacity') or 0)
    is_combined = 1 if request.form.get('is_combined') else 0
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        UPDATE dbo.rooms
        SET name=?, location=?, group_code=?, capacity=?, is_combined=?
        WHERE id=?
    """, (name, location, group_code, capacity, is_combined, id))
    conn.commit(); conn.close()
    flash("✅ Room updated successfully.", "success")
    return redirect(url_for('room_maintenance'))

@app.route('/rooms/deactivate/<int:id>')
@login_required
def deactivate_room(id):
    if not getattr(current_user, 'is_admin', lambda: False)():
        flash("Not authorized.", "danger"); return redirect(url_for('menu'))
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("UPDATE dbo.rooms SET status = 'Inactive' WHERE id = ?", (id,))
    conn.commit(); conn.close()
    flash("Room deactivated.", "warning")
    return redirect(url_for('room_maintenance'))



def get_room_availability_for_date(room_id, date,
                                   start_hour=None, end_hour=None):
    # Default fallback from .env if not provided
    if start_hour is None:
        start_hour = int(os.getenv("TIMELINE_START", 6))
    if end_hour is None:
        end_hour = int(os.getenv("TIMELINE_END", 22))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, reserved_by, email, start_time, end_time,
               status, remarks, recurrence_id
        FROM reservations (NOLOCK)
        WHERE room_id = ?
          AND CAST(start_time AS DATE) = ?
    """, (room_id, date))

    rows = cursor.fetchall()

    slots = {}
    for hour in range(start_hour, end_hour):
        for minute in [0, 30]:
            t = f"{hour:02d}:{minute:02d}"
            slots[t] = "available"

    for r in rows:
        st = r.start_time
        et = r.end_time

        cur = datetime.combine(date, datetime_time(start_hour, 0))
        end_day = datetime.combine(date, datetime_time(end_hour, 0))

        while cur < end_day:
            slot = cur.strftime("%H:%M")
            if st <= cur < et:
                slots[slot] = {
                    "status": r.status.lower(),
                    "by": r.reserved_by,
                    "remarks": r.remarks,
                    "id": r.id,
                    "reserved_by": r.reserved_by
                }
            cur += timedelta(minutes=30)

    return slots


def get_all_room_ids():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM rooms (NOLOCK) WHERE status='Active'")
    rows = cur.fetchall()
    conn.close()
    return [r[0] for r in rows]


# --- ROOM LIST WITH LOCATION + ROOM FILTERING -------------------------------
# --- ROOM LIST (FINAL PATCH) ---------------------------------------------------
# --- ROOM LIST (HARDENED PATCH) --------------------------------------------
import traceback
from datetime import date, timedelta

@app.route("/rooms")
@login_required
def room_list():
    try:
        # ----------------------------------------
        # 1. READ INPUTS (safe)
        # ----------------------------------------
        raw_date = request.args.get("date") or date.today().isoformat()
        selected_location = request.args.get("location", "all")
        selected_room = request.args.get("room", "all")
        focus_room = request.args.get("focus")

        # parse date safely (fall back to today if invalid)
        try:
            view_date = date.fromisoformat(raw_date)
        except Exception:
            # invalid incoming date format, fallback to today
            view_date = date.today()
            raw_date = view_date.isoformat()

        # timeline range (ints)
        start_hour = int(os.getenv("TIMELINE_START", 6))
        end_hour = int(os.getenv("TIMELINE_END", 22))

        # ----------------------------------------
        # 2. DB CONNECTION
        # ----------------------------------------
        conn = get_db_connection()
        cur = conn.cursor()

        # ----------------------------------------
        # 3. GET USER-ASSIGNED LOCATIONS
        # ----------------------------------------
        if current_user.is_admin():
            cur.execute("SELECT DISTINCT location FROM rooms WHERE status='Active'")
            allowed_locations = [r[0] for r in cur.fetchall()]
        else:
            cur.execute("""
                SELECT DISTINCT ul.location_name
                FROM user_locations ul
                WHERE ul.user_id = ?
            """, (current_user.id,))
            allowed_locations = [r[0] for r in cur.fetchall()]

        # safe default if nothing found
        if not allowed_locations:
            allowed_locations = ["Axis T1"]

        # ----------------------------------------
        # 4. GET ALL ROOMS UNDER ALLOWED LOCATIONS
        # ----------------------------------------
        placeholders = ",".join(["?"] * len(allowed_locations))
        sql = f"""
            SELECT id, name, location, capacity, description,
                   group_code, is_combined
            FROM rooms
            WHERE status='Active'
              AND location IN ({placeholders})
            ORDER BY location, name
        """
        cur.execute(sql, tuple(allowed_locations))
        rows = cur.fetchall()

        all_rooms = [
            {
                "id": r[0],
                "name": r[1],
                "location": r[2],
                "capacity": r[3],
                "description": r[4],
                "group_code": r[5],
                "is_combined": bool(r[6]),
            }
            for r in rows
        ]

        # ----------------------------------------
        # 5. APPLY LOCATION FILTER
        # ----------------------------------------
        if selected_location != "all":
            filtered_rooms = [r for r in all_rooms if r["location"] == selected_location]
        else:
            filtered_rooms = all_rooms[:]

        # ----------------------------------------
        # 6. APPLY ROOM FILTER
        # ----------------------------------------
        if selected_room != "all":
            rooms = [r for r in filtered_rooms if r["name"] == selected_room]
        else:
            rooms = filtered_rooms[:]

        # if no rooms left, show empty timeline (no DB reservations)
        if not rooms:
            conn.close()
            return render_template(
                "index.html",
                rooms=[],
                all_rooms=all_rooms,
                allowed_locations=allowed_locations,
                availability={},
                selected_date=view_date,
                selected_room=selected_room,
                selected_location=selected_location,
                focus_room=focus_room,
                start_hour=start_hour,
                end_hour=end_hour,
            )

        room_ids = [r["id"] for r in rooms]

        # ----------------------------------------
        # 7. LOAD RESERVATIONS FOR SELECTED DATE
        # ----------------------------------------
        placeholders = ",".join(["?"] * (1 + len(room_ids)))  # one for date + N room ids
        sql = f"""
            SELECT id, room_id, reserved_by, start_time, end_time,
                   status, remarks
            FROM reservations
            WHERE CAST(start_time AS DATE) = ?
              AND room_id IN ({','.join(['?']*len(room_ids))})
        """
        params = [raw_date] + room_ids
        cur.execute(sql, params)
        reservations = cur.fetchall()

        # ----------------------------------------
        # 8. BUILD AVAILABILITY GRID
        # ----------------------------------------
        availability = {rid: {} for rid in room_ids}
        for r in rooms:
            for hour in range(start_hour, end_hour):
                for minute in (0, 30):
                    t = f"{hour:02d}:{minute:02d}"
                    availability[r["id"]][t] = {
                        "status": "available",
                        "reserved_by": "",
                        "remarks": "",
                        "id": "",
                    }

        # Apply reservations to availability
        for (res_id, rid, by, s, e, status, remarks) in reservations:
            cur_time = s
            while cur_time < e:
                t = cur_time.strftime("%H:%M")
                if rid in availability and t in availability[rid]:
                    availability[rid][t] = {
                        "status": (status or "booked").lower(),
                        "reserved_by": by or "",
                        "remarks": remarks or "",
                        "id": res_id,
                    }
                cur_time += timedelta(minutes=30)

        conn.close()

        return render_template(
            "index.html",
            rooms=rooms,
            all_rooms=all_rooms,
            allowed_locations=allowed_locations,
            availability=availability,
            selected_room=selected_room,
            selected_location=selected_location,
            selected_date=view_date,
            focus_room=focus_room,
            start_hour=start_hour,
            end_hour=end_hour,
        )

    except Exception as exc:
        # log full traceback to server log so you can troubleshoot in prod
        traceback.print_exc()
        # return a friendly page instead of raw 500 text (helps avoid blank white)
        try:
            return render_template(
                "index.html",
                rooms=[],
                all_rooms=[],
                allowed_locations=[],
                availability={},
                selected_date=date.today(),
                selected_room="all",
                selected_location="all",
                focus_room=None,
                start_hour=int(os.getenv("TIMELINE_START", 6)),
                end_hour=int(os.getenv("TIMELINE_END", 22)),
                error_message="An unexpected server error occurred. Administrators have been notified."
            ), 500
        except Exception:
            # fallback: simple text response
            return "Internal Server Error", 500



@app.route("/calendar_view")
@login_required
def calendar_view():
    try:
        selected_date = request.args.get("date")
        selected_location = request.args.get("location")

        if not selected_date:
            selected_date = datetime.now().strftime("%Y-%m-%d")

        conn = get_db_connection()
        cur = conn.cursor()

        # Determine allowed locations
        if current_user.is_admin():
            cur.execute("SELECT DISTINCT location FROM rooms WHERE status='Active'")
            allowed_locations = [row[0] for row in cur.fetchall()]
        else:
            cur.execute("""
                SELECT DISTINCT ul.location_name
                FROM user_locations ul
                WHERE ul.user_id = ?
            """, (current_user.id,))
            allowed_locations = [row[0] for row in cur.fetchall()]

        # Validate requested location
        if not selected_location or selected_location not in allowed_locations:
            selected_location = allowed_locations[0]

        # Load rooms for this user/location
        cur.execute("""
            SELECT *
            FROM rooms
            WHERE status='Active'
              AND location = ?
        """, (selected_location,))
        rows = cur.fetchall()

        rooms = [
            {desc[0]: value for desc, value in zip(cur.description, row)}
            for row in rows
        ]

        # Group rooms for dropdown
        grouped_rooms = {}
        for r in rooms:
            grouped_rooms.setdefault(r["location"], []).append(r["name"])

        conn.close()

        return render_template(
            "calendar_view.html",
            rooms=rooms,
            grouped_rooms=grouped_rooms,
            current_location=selected_location,
            locations=allowed_locations,
            selected_date=selected_date
        )
    except Exception as e:
        print("❌ ERROR in calendar_view:", e)
        return "Calendar Error", 500


def get_room_by_id(conn, room_id):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, name, group_code, location, is_combined
        FROM dbo.rooms
        WHERE id = ?
    """, (room_id,))
    row = cursor.fetchone()

    if row:
        return {
            "id": row[0],
            "name": row[1],
            "group_code": row[2],
            "location": row[3],          # <-- FIXED
            "is_combined": bool(row[4])
        }
    return None


def get_linked_rooms(conn, group_code, exclude_id=None):
    cursor = conn.cursor()
    if exclude_id:
        cursor.execute("SELECT id FROM dbo.zs WHERE group_code = ? AND id <> ?", (group_code, exclude_id))
    else:
        cursor.execute("SELECT id FROM dbo.rooms WHERE group_code = ?", (group_code,))
    return [r[0] for r in cursor.fetchall()]

@app.route('/confirm')
@login_required
def confirm():
    return render_template('confirmation.html')

# --- Helper: get_combined_group_rooms ---
import uuid
# from datetime import datetime, timedelta

def get_combined_group_rooms(room_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT group_code, is_combined
        FROM rooms
        WHERE id = ?
    """, (room_id,))
    row = cursor.fetchone()

    if not row:
        cursor.close()
        conn.close()
        return [room_id]

    group_code, is_combined = row

    # If this room is NOT combined → do not block others
    if not group_code or is_combined != 1:
        cursor.close()
        conn.close()
        return [room_id]

    # Combined room → block all rooms in same group_code
    cursor.execute("""
        SELECT id
        FROM rooms
        WHERE group_code = ?
    """, (group_code,))
    rooms = [r[0] for r in cursor.fetchall()]

    cursor.close()
    conn.close()
    return rooms



# @app.route('/reserve_post/<int:room_id>', methods=['POST'])
# @login_required
# def reserve_post(room_id):
#     try:
#         conn = get_db_connection();
#         cur = conn.cursor()
#
#         # Parse payload
#         payload = request.get_json() if request.is_json else request.form.to_dict()
#
#         start_time = payload.get("start_time")
#         end_time = payload.get("end_time")
#         remarks = payload.get("remarks", "")
#         email = payload.get("email") or current_user.email
#         reserved_by = payload.get("reserved_by") or current_user.display_name
#
#         recurrence_type = payload.get("recurrence_type", "none")
#         weekdays = payload.get("weekdays", "")  # CSV "MO,FR"
#         weekly_interval = int(payload.get("weekly_interval", 1))
#
#         end_mode = payload.get("end_mode", "never")
#         end_on_date = payload.get("end_on_date")
#         after_count = payload.get("end_after_count")
#
#         if not start_time or not end_time:
#             return jsonify(success=False, message="Missing start/end"), 400
#
#         # Convert strings -> datetime
#         start_dt = datetime.fromisoformat(start_time)
#         end_dt = datetime.fromisoformat(end_time)
#         base_duration = end_dt - start_dt
#
#         # --- Build all recurrence dates ---
#         all_dates = []
#         current = start_dt
#
#         recurrence_id = str(uuid.uuid4()) if recurrence_type != "none" else None
#
#         def add_if_match(dt):
#             # Ensure dt <= end-limit rules
#             if end_mode == "on" and dt.date() > datetime.fromisoformat(end_on_date).date():
#                 return False
#             return True
#
#         count = 0
#         MAX_LIMIT = 370  # 1 year
#
#         if recurrence_type == "none":
#             all_dates = [start_dt]
#
#         elif recurrence_type == "daily":
#             while count < MAX_LIMIT:
#                 if add_if_match(current):
#                     all_dates.append(current)
#                 count += 1
#                 if end_mode == "after" and len(all_dates) >= int(after_count):
#                     break
#                 current += timedelta(days=1)
#                 if end_mode == "on" and current.date() > datetime.fromisoformat(end_on_date).date():
#                     break
#
#         elif recurrence_type == "weekly":
#             weekday_map = ["MO","TU","WE","TH","FR","SA","SU"]
#             target_days = weekdays.split(",") if weekdays else []
#             if not target_days:
#                 target_days = [weekday_map[start_dt.weekday()]]
#
#             # First: include the start date
#             if weekday_map[start_dt.weekday()] in target_days:
#                 all_dates.append(start_dt)
#
#             cur_dt = start_dt
#             while len(all_dates) < MAX_LIMIT:
#                 cur_dt += timedelta(days=1)
#                 wd = weekday_map[cur_dt.weekday()]
#
#                 if wd in target_days:
#                     if not add_if_match(cur_dt):
#                         break
#                     all_dates.append(cur_dt)
#
#                 if end_mode == "after" and len(all_dates) >= int(after_count):
#                     break
#                 if end_mode == "on" and cur_dt.date() > datetime.fromisoformat(end_on_date).date():
#                     break
#
#         # MONTHLY—can add later if needed
#         elif recurrence_type == "monthly":
#             all_dates = [start_dt]  # TODO: support monthly rules
#
#         # =====================================================================
#         # Insert reservations + auto-block for combined AXIS_HALL rooms
#         # =====================================================================
#         group_rooms = get_combined_group_rooms(room_id)
#
#         created_count = 0
#         skipped = []
#
#         for dt in all_dates:
#             new_start = dt
#             new_end = dt + base_duration
#
#             # Check conflict in the main room
#             cur.execute("""
#                 SELECT COUNT(*)
#                 FROM reservations
#                 WHERE room_id=?
#                 AND NOT (end_time <= ? OR start_time >= ?)
#                 AND status IN ('Pending','Approved','Blocked')
#             """, (room_id, new_start, new_end))
#             if cur.fetchone()[0] > 0:
#                 skipped.append(new_start.isoformat())
#                 continue
#
#             # Insert main reservation
#             cur.execute("""
#                 INSERT INTO reservations
#                     (room_id, reserved_by, email, start_time, end_time, status,
#                      remarks, created_at, time_zone, recurrence_id)
#                 VALUES (?, ?, ?, ?, ?, 'Pending', ?, GETDATE(),
#                         'GMT+08:00 (Beijing, Singapore, Taipei)', ?)
#             """, (
#                 room_id,
#                 reserved_by,
#                 email,
#                 new_start,
#                 new_end,
#                 remarks,
#                 recurrence_id
#             ))
#             created_count += 1
#
#             # Auto-block AXIS_HALL rooms except main one
#             for rid in group_rooms:
#                 if rid == room_id:
#                     continue
#
#                 cur.execute("""
#                     SELECT COUNT(*) FROM reservations
#                     WHERE room_id=? AND NOT (end_time <= ? OR start_time >= ?)
#                     AND status IN ('Pending','Approved','Blocked')
#                 """, (rid, new_start, new_end))
#                 if cur.fetchone()[0] > 0:
#                     continue  # skip conflicts
#
#                 cur.execute("""
#                     INSERT INTO reservations
#                         (room_id, reserved_by, email, start_time, end_time, status,
#                          remarks, created_at, time_zone, recurrence_id)
#                     VALUES (?, ?, ?, ?, ?, 'Blocked', ?, GETDATE(),
#                             'GMT+08:00 (Beijing, Singapore, Taipei)', ?)
#                 """, (
#                     rid,
#                     f"[AUTO BLOCK] {reserved_by}",
#                     email,
#                     new_start,
#                     new_end,
#                     f"Blocked by combined booking of room {room_id}",
#                     recurrence_id
#                 ))
#
#         conn.commit()
#
#         return jsonify(
#             success=True,
#             created_count=created_count,
#             skipped=skipped,
#             message="Recurring booking result"
#         )
#
#     except Exception as e:
#         print("⚠️ Error Post", e)
#         try:
#             if 'conn' in locals() and conn:
#                 conn.rollback()
#         except:
#             pass
#
#         return jsonify(success=False, message=str(e)), 500

@app.route('/reserve_post/<int:room_id>', methods=['POST'])
@login_required
def reserve_post(room_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Parse payload
        payload = request.get_json() if request.is_json else request.form.to_dict()

        start_time = payload.get("start_time")
        end_time = payload.get("end_time")
        remarks = payload.get("remarks", "")
        email = payload.get("email") or getattr(current_user, "email", None)
        reserved_by = payload.get("reserved_by") or getattr(current_user, "display_name", "") or getattr(current_user, "username", "")

        recurrence_type = payload.get("recurrence_type", "none")
        weekdays = payload.get("weekdays", "")  # CSV "MO,FR"
        weekly_interval = int(payload.get("weekly_interval", 1) or 1)

        end_mode = payload.get("end_mode", "never")
        end_on_date = payload.get("end_on_date")
        after_count = payload.get("end_after_count")

        if not start_time or not end_time:
            return jsonify(success=False, message="Missing start/end"), 400

        # Convert strings -> datetime
        start_dt = datetime.fromisoformat(start_time)
        end_dt = datetime.fromisoformat(end_time)
        base_duration = end_dt - start_dt

        # --- Load room info (location, approval setting) ---
        cur.execute("SELECT id, name, location, approvals_required FROM rooms WHERE id = ?", (room_id,))
        row = cur.fetchone()
        if not row:
            return jsonify(success=False, message="Room not found"), 404

        room_location = row[2] or ""
        approvals_required_raw = row[3]  # may be 'Auto', 'Yes', 'No' or NULL

        # Normalize approvals_required
        approvals_required = str(approvals_required_raw).strip().lower() if approvals_required_raw is not None else "auto"
        if approvals_required not in ("auto", "yes", "no"):
            approvals_required = "auto"

        # --- Fetch approvers for this location from group_approvers ---
        cur.execute("""
            SELECT approver_username
            FROM group_approvers
            WHERE group_code = ? AND is_active = 1
        """, (room_location,))
        approver_rows = cur.fetchall()
        approvers = [r[0] for r in approver_rows] if approver_rows else []

        # Helper: determine status for a single created reservation
        def decide_status():
            # approvals_required: "no" | "yes" | "auto"
            if approvals_required == "no":
                return "Approved"
            if approvals_required == "yes":
                # always pending for manual approval (route to approvers or admin)
                return "Pending"
            # auto
            if approvals_required == "auto":
                return "Pending" if approvers else "Approved"
            # fallback
            return "Pending"

        # --- Build recurrence dates ---
        all_dates = []
        current = start_dt

        recurrence_id = str(uuid.uuid4()) if recurrence_type != "none" else None

        def add_if_match(dt):
            if end_mode == "on" and end_on_date:
                try:
                    end_limit = datetime.fromisoformat(end_on_date).date()
                except Exception:
                    return False
                return dt.date() <= end_limit
            return True

        count = 0
        MAX_LIMIT = 370  # about 1 year

        if recurrence_type == "none":
            all_dates = [start_dt]

        elif recurrence_type == "daily":
            while count < MAX_LIMIT:
                if add_if_match(current):
                    all_dates.append(current)
                count += 1
                if end_mode == "after" and after_count and len(all_dates) >= int(after_count):
                    break
                current += timedelta(days=1)
                if end_mode == "on" and end_on_date and current.date() > datetime.fromisoformat(end_on_date).date():
                    break

        elif recurrence_type == "weekly":
            weekday_map = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"]
            target_days = [d for d in (weekdays.split(",") if weekdays else []) if d]
            if not target_days:
                target_days = [weekday_map[start_dt.weekday()]]

            # include start date if it matches
            if weekday_map[start_dt.weekday()] in target_days:
                all_dates.append(start_dt)

            cur_dt = start_dt
            while len(all_dates) < MAX_LIMIT:
                cur_dt += timedelta(days=1)
                wd = weekday_map[cur_dt.weekday()]
                if wd in target_days:
                    if not add_if_match(cur_dt):
                        break
                    all_dates.append(cur_dt)

                if end_mode == "after" and after_count and len(all_dates) >= int(after_count):
                    break
                if end_mode == "on" and end_on_date and cur_dt.date() > datetime.fromisoformat(end_on_date).date():
                    break

        elif recurrence_type == "monthly":
            # minimal support: keep just the single start date for now
            all_dates = [start_dt]

        # =====================================================================
        # Insert reservations + auto-block for combined group rooms
        # =====================================================================
        group_rooms = get_combined_group_rooms(room_id)  # keep your helper

        created_count = 0
        skipped = []

        for dt in all_dates:
            new_start = dt
            new_end = dt + base_duration

            # conflict check for the main room
            cur.execute("""
                SELECT COUNT(*)
                FROM reservations
                WHERE room_id=?
                  AND NOT (end_time <= ? OR start_time >= ?)
                  AND status IN ('Pending','Approved','Blocked')
            """, (room_id, new_start, new_end))
            if cur.fetchone()[0] > 0:
                skipped.append(new_start.isoformat())
                continue

            # decide status based on approver presence and room setting
            status_to_use = decide_status()  # "Pending" or "Approved"

            # Insert main reservation (status varies)
            cur.execute("""
                INSERT INTO reservations
                    (room_id, reserved_by, email, start_time, end_time, status,
                     remarks, created_at, time_zone, recurrence_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, GETDATE(), 'GMT+08:00 (Beijing, Singapore, Taipei)', ?)
            """, (
                room_id,
                reserved_by,
                email,
                new_start,
                new_end,
                status_to_use,
                remarks,
                recurrence_id
            ))
            created_count += 1

            # Optional: If status is Pending and approvers is empty for "yes", you may want to notify admin here.
            # (You said you have admin users — implement notification outside this function.)

            # Auto-block combined group rooms (same as before)
            for rid in group_rooms:
                if rid == room_id:
                    continue

                cur.execute("""
                    SELECT COUNT(*) FROM reservations
                    WHERE room_id=? AND NOT (end_time <= ? OR start_time >= ?)
                    AND status IN ('Pending','Approved','Blocked')
                """, (rid, new_start, new_end))
                if cur.fetchone()[0] > 0:
                    continue  # skip conflicts

                cur.execute("""
                    INSERT INTO reservations
                        (room_id, reserved_by, email, start_time, end_time, status,
                         remarks, created_at, time_zone, recurrence_id)
                    VALUES (?, ?, ?, ?, ?, 'Blocked', ?, GETDATE(),
                            'GMT+08:00 (Beijing, Singapore, Taipei)', ?)
                """, (
                    rid,
                    f"[AUTO BLOCK] {reserved_by}",
                    email,
                    new_start,
                    new_end,
                    f"Blocked by combined booking of room {room_id}",
                    recurrence_id
                ))

        conn.commit()
        conn.close()

        return jsonify(
            success=True,
            created_count=created_count,
            skipped=skipped,
            message="Recurring booking result"
        )

    except Exception as e:
        print("⚠️ Error Post", e)
        try:
            if 'conn' in locals() and conn:
                conn.rollback()
                conn.close()
        except:
            pass

        return jsonify(success=False, message=str(e)), 500


@app.route('/api/cancel_reservation/<int:res_id>', methods=['POST'])
@login_required
def api_cancel_reservation(res_id):
    try:

        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT id, room_id, reserved_by, status, start_time, end_time FROM dbo.reservations WHERE id = ?", (res_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"success": False, "message": "Reservation not found."}), 404
        rid = row[1]; reserved_by = row[2] or ""; status = row[3] or ""; start_time = row[4]; end_time = row[5]

        # get room group_code for approver checks
        cur.execute("SELECT group_code FROM dbo.rooms WHERE id = ?", (rid,))
        room_row = cur.fetchone()
        group_code = room_row[0] if room_row else None

        # Authorization: admin OR initiator OR group approver
        allowed = False
        if getattr(current_user, 'role', '').lower() == 'admin':
            allowed = True
        elif current_user.username.lower() == (reserved_by or "").lower():
            allowed = True
        elif group_code and is_user_group_admin(current_user.username, group_code):
            allowed = True

        if not allowed:
            return jsonify({"success": False, "message": "Unauthorized to cancel this reservation."}), 403

        if status == "Cancelled":
            return jsonify({"success": False, "message": "Reservation already cancelled."}), 400

        cur.execute("UPDATE dbo.reservations SET status = 'Cancelled', updated_at = GETDATE() WHERE id = ?", (res_id,))
        # Cancel any auto-blocks tied to this booking (by reserved_by marker and exact start/end)
        auto_marker = f"[AUTO BLOCK] {reserved_by}"
        cur.execute("""
            UPDATE dbo.reservations
            SET status = 'Cancelled', updated_at = GETDATE()
            WHERE reserved_by LIKE ? AND start_time = ? AND end_time = ? AND status = 'Blocked'
        """, (auto_marker + '%', start_time, end_time))
        conn.commit()
        log_audit("RESERVATION_CANCELLED", f"Reservation ID {res_id} cancelled by {current_user.username}")
        return jsonify({"success": True, "room_id": rid, "res_id": res_id, "message": "Reservation cancelled successfully."})
    except Exception as e:
        print("⚠️ api_cancel_reservation error:", e)
        return jsonify({"success": False, "message": f"System error: {e}"}), 500
    finally:
        conn.close()

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
    # 4. GET ALL ROOMS FOR DROPDOWN (based on user's allowed locations)
    cur.execute("""
        SELECT id, name, location, capacity, description, group_code, is_combined
        FROM rooms
        WHERE status='Active'
          AND location IN ({})
        ORDER BY location, name
    """.format(",".join("?" * len(allowed_locations))), allowed_locations)

    all_room_rows = cur.fetchall()

    # Convert ALL rooms to list (for dropdown)
    all_rooms = [
        {
            "id": r[0],
            "name": r[1],
            "location": r[2],
            "capacity": r[3],
            "description": r[4],
            "group_code": r[5],
            "is_combined": bool(r[6]),
        }
        for r in all_room_rows
    ]

    # 5. FILTER ROOMS BASED ON SELECTED LOCATION
    if selected_location and selected_location != "all":
        filtered_rooms = [r for r in all_rooms if r["location"] == selected_location]
    else:
        filtered_rooms = all_rooms[:]  # all rooms by default

    # 6. FILTER ROOMS AGAIN BASED ON SELECTED ROOM
    if selected_room and selected_room != "all":
        rooms = [r for r in filtered_rooms if r["name"] == selected_room]
    else:
        rooms = filtered_rooms[:]

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

@app.route('/export_excel')
@login_required
def export_excel():
    start = request.args.get('start')
    end = request.args.get('end')
    room = request.args.get('room', 'all')
    group = request.args.get('group', 'all')

    # --- Parse date range safely ---
    try:
        start_date = datetime.strptime(start, "%Y-%m-%d")
        end_date = datetime.strptime(end, "%Y-%m-%d") + timedelta(days=1)
    except Exception as e:
        print("⚠️ Invalid date params:", e)
        return "Invalid date format. Expected YYYY-MM-DD", 400

    # --- Connect DB ---
    conn = get_db_connection()
    cursor = conn.cursor()

    # --- Build SQL ---
    query = """
        SELECT rm.name AS Room, rm.location AS Location,
               r.reserved_by AS ReservedBy,
               CONVERT(VARCHAR(19), r.start_time, 120) AS StartTime,
               CONVERT(VARCHAR(19), r.end_time, 120) AS EndTime,
               ISNULL(r.remarks,'') AS Remarks,
               r.status AS Status
        FROM dbo.reservations r
        INNER JOIN dbo.rooms rm ON rm.id = r.room_id
        WHERE r.start_time >= ? AND r.end_time < ?
    """
    params = [start_date, end_date]

    if group and group != "all":
        query += " AND rm.location = ?"
        params.append(group)
    if room and room != "all":
        query += " AND rm.name = ?"
        params.append(room)

    query += " ORDER BY rm.name, r.start_time"

    print(f"\n🧾 Export Query:\n{query}\nParams: {params}")

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    # --- Build grouped data ---
    reservations_by_room = {}
    for row in rows:
        room_name = row[0]
        reservations_by_room.setdefault(room_name, []).append(row)

    # --- Create Excel output ---
    output = BytesIO()
    workbook = pd.ExcelWriter(output, engine="xlsxwriter")
    wb = workbook.book

    # --- Styles ---
    title_fmt = wb.add_format({
        "bold": True, "font_size": 14, "align": "center",
        "valign": "vcenter", "bg_color": "#0047AB", "font_color": "white"
    })
    time_fmt = wb.add_format({"align": "center", "valign": "vcenter", "border": 1, "bold": True})
    available_fmt = wb.add_format({"align": "center", "valign": "vcenter", "border": 1, "bg_color": "#E8F5E9"})
    booked_fmt = wb.add_format({
        "align": "center", "valign": "vcenter", "border": 1, "bg_color": "#BBDEFB", "text_wrap": True
    })
    pending_fmt = wb.add_format({
        "align": "center", "valign": "vcenter", "border": 1, "bg_color": "#FFE0B2", "text_wrap": True
    })

    # --- Case: No data ---
    if not reservations_by_room:
        ws = wb.add_worksheet("No Data")
        ws.merge_range("A1:C1", f"No reservations found between {start} and {end}", title_fmt)
        ws.set_column("A:C", 40)
        workbook.close()
        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name=f"Room_Schedule_{start}_to_{end}.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

    # --- Create one sheet per room ---
    for room_name, bookings in reservations_by_room.items():
        ws = wb.add_worksheet(room_name[:31])
        ws.merge_range("A1:D1",
            f"{room_name} — Schedule ({start} to {end})",
            title_fmt
        )
        ws.write("A3", "Time", time_fmt)
        ws.write("B3", "Reservation Details", time_fmt)
        ws.set_column("A:A", 12)
        ws.set_column("B:B", 60)

        # Generate half-hour grid (6:00–20:00)
        row_idx = 3
        base = datetime.strptime(start, "%Y-%m-%d")
        for h in range(6, 20):
            for m in [0, 30]:
                slot_label = f"{h:02d}:{m:02d}"
                ws.write(row_idx, 0, slot_label, time_fmt)

                slot_start = base.replace(hour=h, minute=m)
                slot_end = slot_start + timedelta(minutes=30)
                matched = None

                for b in bookings:
                    b_start = datetime.strptime(b[3], "%Y-%m-%d %H:%M:%S")
                    b_end = datetime.strptime(b[4], "%Y-%m-%d %H:%M:%S")
                    if b_start < slot_end and b_end > slot_start:
                        matched = b
                        break

                if matched:
                    details = f"{matched[2]} ({matched[6]})\n{matched[5]}"
                    fmt = booked_fmt if matched[6] == "Approved" else pending_fmt
                    ws.write(row_idx, 1, details, fmt)
                else:
                    ws.write(row_idx, 1, "", available_fmt)

                row_idx += 1

        # --- Print settings for posting ---
        ws.fit_to_pages(1, 1)
        ws.set_landscape()
        ws.set_paper(9)  # A4
        ws.center_horizontally()
        ws.set_margins(left=0.3, right=0.3, top=0.5, bottom=0.5)

    # --- Finalize workbook ---
    workbook.close()
    output.seek(0)
    filename = f"Room_Schedule_{start}_to_{end}.xlsx"

    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

@app.route("/api/reservations")
@login_required
def api_reservations():
    room = request.args.get("room", "all")
    group = request.args.get("group", "all")
    start = request.args.get("start")
    end = request.args.get("end")

    # --- Parse FullCalendar range ---
    try:
        start_dt = dateparser.isoparse(start)
        end_dt = dateparser.isoparse(end)
    except Exception as e:
        print("⚠️ Invalid date range:", e)
        return jsonify([])

    conn = get_db_connection()
    cursor = conn.cursor()

    # ==========================================================
    # 1️⃣ Base SQL – Admin sees all, User limited to assigned locations
    # ==========================================================
    if current_user.role == "admin":
        query = """
            SELECT r.id AS reservation_id,
                   rm.id AS room_id,
                   rm.name AS room_name,
                   rm.location,
                   r.reserved_by,
                   r.start_time,
                   r.end_time,
                   ISNULL(r.remarks,'') AS remarks,
                   r.status
            FROM reservations r
            INNER JOIN rooms rm ON rm.id = r.room_id
            WHERE r.status IN ('Approved','Pending')
              AND r.start_time >= ? AND r.start_time < ?
        """
        params = [start_dt, end_dt]

    else:
        query = """
            SELECT r.id AS reservation_id,
                   rm.id AS room_id,
                   rm.name AS room_name,
                   rm.location,
                   r.reserved_by,
                   r.start_time,
                   r.end_time,
                   ISNULL(r.remarks,'') AS remarks,
                   r.status
            FROM reservations r
            INNER JOIN rooms rm ON rm.id = r.room_id
            INNER JOIN user_locations ul
                ON ul.location_name = rm.location
            WHERE ul.user_id = ?
              AND r.status IN ('Approved','Pending')
              AND r.start_time >= ? AND r.start_time < ?
        """
        params = [current_user.id, start_dt, end_dt]

    # ==========================================================
    # 2️⃣ Apply UI filters (location + room)
    # ==========================================================
    if group and group.lower() != "all":
        query += " AND rm.location = ?"
        params.append(group)

    if room and room.lower() != "all":
        query += " AND rm.name = ?"
        params.append(room)

    query += " ORDER BY r.start_time"

    # Debug logs
    print("🧩 SQL:", query)
    print("🧩 PARAMS:", params)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    # ==========================================================
    # 3️⃣ Build FullCalendar Events
    # ==========================================================
    tz = timezone(timedelta(hours=8))
    events = []

    for (reservation_id, room_id, room_name, location,
         reserved_by, start_time, end_time, remarks, status) in rows:

        start_local = start_time.replace(tzinfo=tz)
        end_local = end_time.replace(tzinfo=tz)

        color = "#0047AB" if status == "Approved" else "#FFA726"

        events.append({
            "id": reservation_id,         # FIXED
            "room_id": room_id,
            "title": f"{room_name} - {reserved_by}",
            "start": start_local.isoformat(),
            "end": end_local.isoformat(),
            "room": room_name,
            "location": location,
            "description": remarks,
            "status": status,
            "color": color
        })

    print(f"✅ Returned {len(events)} events (Group={group}, Room={room})")
    return jsonify(events)

@app.route("/api/room_availability/<int:room_id>")
@login_required
def api_room_availability(room_id):
    try:
        selected_date = request.args.get("date")
        if not selected_date:
            # from datetime import datetime
            selected_date = datetime.now().strftime("%Y-%m-%d")

        conn = get_db_connection()
        cur = conn.cursor()

        sql = """
            SELECT 
                id,
                reserved_by,
                email,
                CONVERT(VARCHAR(5), start_time, 108) AS start_time,
                CONVERT(VARCHAR(5), end_time, 108) AS end_time,
                status,
                remarks
            FROM reservations
            WHERE room_id = ?
              AND CAST(start_time AS DATE) = ?
              AND status != 'Cancelled'
            ORDER BY start_time
        """
        cur.execute(sql, (room_id, selected_date))
        rows = cur.fetchall()
        conn.close()

        results = []
        for r in rows:
            results.append({
                "id": r.id,
                "reserved_by": r.reserved_by,
                "email": r.email,
                "start": r.start_time,
                "end": r.end_time,
                "status": r.status,
                "remarks": r.remarks,
            })

        return jsonify(results)
    except Exception as e:
        print(f"⚠️ Error loading room availability for {room_id}: {e}")
        return jsonify([])

# (remaining routes & functions—api_reservations, api_room_availability, api_booked_slots, room_schedule, admin dashboard, etc.—should remain as in your working copy)
# Keep the rest of your original file unchanged below this line (export_excel, api_reservations, api_room_availability, api_booked_slots, room_schedule, etc.)

def assign_user_locations(user_id, locations):
   """Replace all user-location assignments."""
   try:
       conn = get_db_connection(); cur = conn.cursor()
       cur.execute("DELETE FROM dbo.user_locations WHERE user_id = ?", (user_id,))
       for loc in locations:
           cur.execute(
               "INSERT INTO dbo.user_locations (user_id, location_name) VALUES (?, ?)",
               (user_id, loc)
           )
       conn.commit()
   except Exception as e:
       print("⚠ assign_user_locations error:", e)
   finally:
       conn.close()
def get_user_locations(user_id):
   try:
       conn = get_db_connection(); cur = conn.cursor()
       cur.execute("SELECT location_name FROM dbo.user_locations WHERE user_id = ?", (user_id,))
       rows = [r[0] for r in cur.fetchall()]
       conn.close()
       return rows
   except:
       return []
def assign_location_approvers(location, usernames):
   """Replace all approvers of a location."""
   try:
       conn = get_db_connection(); cur = conn.cursor()
       cur.execute("DELETE FROM dbo.group_approvers WHERE group_code = ?", (location,))
       for user in usernames:
           cur.execute("""
               INSERT INTO dbo.group_approvers (group_code, approver_username, is_active)
               VALUES (?, ?, 1)
           """, (location, user))
       conn.commit()
   except Exception as e:
       print("⚠ assign_location_approvers error:", e)
   finally:
       conn.close()
def get_location_approvers(location):
   try:
       conn = get_db_connection(); cur = conn.cursor()
       cur.execute("""
           SELECT approver_username
           FROM dbo.group_approvers
           WHERE group_code = ? AND is_active = 1
       """, (location,))
       rows = [r[0] for r in cur.fetchall()]
       conn.close()
       return rows
   except:
       return []
def get_all_room_locations():
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT DISTINCT location FROM dbo.rooms WHERE location IS NOT NULL")
        rows = [r[0] for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        print("⚠️ get_all_room_locations error:", e)
        return []

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
    #
    # return render_template('edit_user.html', user=user)
    locations = get_all_room_locations()
    user_locations = get_user_locations(user_id)

    username = user[1]  # from SELECT id, username, display_name...
    approver_locations = []
    for loc in locations:
        if username in get_location_approvers(loc):
            approver_locations.append(loc)

    return render_template(
        "edit_user.html",
        user=user,
        locations=locations,
        user_locations=user_locations,
        approver_locations=approver_locations
    )


# @app.route('/user_edit/<int:user_id>', methods=['GET', 'POST'])
# @login_required
# def user_edit(user_id):
#     if not current_user.is_admin():
#         flash("Access denied: Admins only.")
#         return redirect(url_for('main_menu'))
#
#     conn = get_db_connection()
#     cursor = conn.cursor()
#
#     if request.method == 'POST':
#         display_name = request.form.get('display_name')
#         email = request.form.get('email')
#         role = request.form.get('role')
#         status = request.form.get('status')
#
#         try:
#             cursor.execute("""
#                 UPDATE dbo.users
#                 SET display_name = ?, email = ?, role = ?, status = ?, updated_at = GETDATE()
#                 WHERE id = ?
#             """, (display_name, email, role, status, user_id))
#             conn.commit()
#             flash("✅ User updated successfully.", "success")
#             log_audit("USER_UPDATED", f"Updated user ID {user_id} ({display_name})")
#             return redirect(url_for('user_maintenance'))
#         except Exception as e:
#             flash(f"⚠️ Error updating user: {e}", "danger")
#         finally:
#             conn.close()
#
#     # --- For GET: Load user info for the form ---
#     cursor.execute("SELECT id, username, display_name, email, role, status FROM dbo.users WHERE id = ?", (user_id,))
#     user = cursor.fetchone()
#     conn.close()
#
#     if not user:
#         flash("⚠️ User not found.", "warning")
#         return redirect(url_for('user_maintenance'))
#
#     return render_template("edit_user.html", user=user)
# --- Admin dashboard ---
@app.route('/user_edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def user_edit(user_id):
    if not current_user.is_admin():
        flash("Access denied: Admins only.")
        return redirect(url_for('main_menu'))

    conn = get_db_connection(); cursor = conn.cursor()

    if request.method == 'POST':
        display_name = request.form.get('display_name', '').strip()
        email = request.form.get('email', '').strip()
        role = request.form.get('role', 'user')
        status = request.form.get('status', 'active')
        locations = request.form.getlist('locations') or []
        approver_locations = request.form.getlist('approver_locations') or []

        try:
            # update basic fields
            cursor.execute("""
                UPDATE dbo.users
                SET display_name = ?, email = ?, role = ?, status = ?, updated_at = GETDATE()
                WHERE id = ?
            """, (display_name, email, role, status, user_id))
            conn.commit()

            # update user locations
            assign_user_locations(user_id, locations)

            # update approver assignments:
            # we'll merge this user into approver lists for selected approver_locations,
            # and remove them from locations unchecked.
            all_locations = get_all_room_locations()
            for loc in all_locations:
                existing = get_location_approvers(loc)
                if loc in approver_locations:
                    # ensure username present
                    if current_user.username not in existing:
                        # but we need to know the username of edited user
                        pass

            # *** We need the username of the edited user to add/remove approver rows: fetch it ***
            cursor.execute("SELECT username FROM dbo.users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            username = row[0] if row else None

            # Add user to approver lists for approver_locations
            for loc in approver_locations:
                existing = get_location_approvers(loc)
                if username and username not in existing:
                    new_list = existing + [username]
                    assign_location_approvers(loc, new_list)

            # Remove user as approver from locations that were unchecked
            for loc in get_all_room_locations():
                if loc not in approver_locations:
                    existing = get_location_approvers(loc)
                    if username and username in existing:
                        new_list = [u for u in existing if u != username]
                        assign_location_approvers(loc, new_list)

            log_audit("USER_UPDATED", f"Updated user {username}: locations={locations}, approver_locations={approver_locations}")
            flash("✅ User updated successfully.", "success")
            return redirect(url_for('user_maintenance'))
        except Exception as e:
            import traceback
            traceback.print_exc()
            flash(f"⚠️ Error updating user: {e}", "danger")
        finally:
            cursor.close()
            conn.close()

    # GET: show form — load user & context
    cursor.execute("SELECT id, username, display_name, email, role, status FROM dbo.users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash("⚠️ User not found.", "warning")
        return redirect(url_for('user_maintenance'))

    # data for form
    locations = get_all_room_locations()
    user_locations = get_user_locations(user_id)
    username = user[1]
    approver_locations = [loc for loc in locations if username in get_location_approvers(loc)]

    return render_template("edit_user.html", user=user, locations=locations, user_locations=user_locations, approver_locations=approver_locations)

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

# User maintenance (admin-only)
@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin():
        flash("Access denied: Admins only.", "warning")
        return redirect(url_for('main_menu'))

    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    display_name = request.form.get('display_name', '').strip()
    role = request.form.get('role', 'user')
    status = request.form.get('status', 'active')

    locations = request.form.getlist('locations') or []
    approver_locations = request.form.getlist('approver_locations') or []

    print("\n🔍 ADD USER DEBUG")
    print("username:", username)
    print("locations:", locations)
    print("approver_locations:", approver_locations)

    if not username:
        flash("Username required.", "warning")
        return redirect(url_for('user_maintenance'))

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Check duplicate
        cur.execute("SELECT COUNT(*) FROM dbo.users WHERE username = ?", (username,))
        exists = cur.fetchone()[0]
        if exists:
            flash(f"⚠️ User {username} already exists.", "warning")
            return redirect(url_for('user_maintenance'))

        # Insert user
        cur.execute("""
            INSERT INTO dbo.users (username, display_name, email, role, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, GETDATE(), GETDATE())
        """, (username, display_name, email, role, status))
        conn.commit()

        # Fetch new ID
        cur.execute("SELECT id FROM dbo.users WHERE username = ?", (username,))
        row = cur.fetchone()

        if not row:
            flash("⚠️ Failed to fetch new user ID!", "danger")
            print("❌ ERROR: Could not fetch inserted user row.")
            return redirect(url_for('user_maintenance'))

        new_user_id = row[0]
        print("✔ New user_id:", new_user_id)

        # Assign locations
        assign_user_locations(new_user_id, locations)

        # Assign approver roles — merge, don't overwrite others
        for loc in approver_locations:
            existing = get_location_approvers(loc)
            if username not in existing:
                assign_location_approvers(loc, existing + [username])

        log_audit("USER_ADDED", f"Added user {username} with {locations}")
        flash(f"✅ User {username} added successfully.", "success")

    except Exception as e:
        print("❌ add_user ERROR:", e)
        flash(f"⚠️ Error adding user: {e}", "danger")
        try: conn.rollback()
        except: pass
    finally:
        try:
            conn.close()
        except:
            pass

    return redirect(url_for('user_maintenance'))


# @app.route('/add_user', methods=['POST'])
# @login_required
# def add_user():
#     if request.method == 'POST':
#         print("🧩 Received Add User POST")
#         print("Form data:", request.form)
#
#     if not current_user.is_admin():
#         flash("Access denied: Admins only.")
#         return redirect(url_for('main_menu'))
#
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#
#         username = request.form['username'].strip()
#         email = request.form.get('email')
#         display_name = request.form.get('display_name')
#         role = request.form.get('role', 'user')
#         status = request.form.get('status', 'active')
#
#
#         cursor.execute("SELECT COUNT(*) FROM dbo.users WHERE username = ?", (username,))
#         (exists,) = cursor.fetchone() or (0,)
#         if exists:
#             flash(f"⚠️ User {username} already exists.")
#         else:
#             cursor.execute("""
#                 INSERT INTO dbo.users (username, email, display_name, role, status, created_at, updated_at)
#                 VALUES (?, ?, ?, ?, ?, GETDATE(), GETDATE())
#             """, (username, email, display_name, role, status))
#             conn.commit()
#             flash(f"✅ User {username} added successfully.")
#             log_audit("USER_ADDED", f"Added user {username} with role {role}")
#
#     except Exception as e:
#         flash(f"Error adding user: {e}", "danger")
#     finally:
#         cursor.close()
#         conn.close()
#
#     return redirect(url_for('user_maintenance'))


# # 2. Save location mapping
#         assign_user_locations(user_id, locations)
# # 3. Read approver locations
# approver_locs = request.form.getlist("approver_locations")
# # 4. For each location selected, add user as approver
# for loc in approver_locs:
#    assign_location_approvers(loc, [username])   # Only assign THIS user

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

@app.route('/user_maintenance', methods=['GET', 'POST'])
@login_required
def user_maintenance():
    if not current_user.is_admin():
        flash("Access denied: Admins only.", "warning")
        return redirect(url_for('main_menu'))

    conn = get_db_connection()
    cur = conn.cursor()

    # ---------- POST = Add User ----------
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        display_name = request.form.get('display_name', '').strip()
        email = request.form.get('email', '').strip()
        role = request.form.get('role', 'user')
        status = request.form.get('status', 'active')

        locations = request.form.getlist('locations')
        approver_locations = request.form.getlist('approver_locations')

        print("\n🟦 DEBUG ADD USER")
        print("username:", username)
        print("locations:", locations)
        print("approver_locations:", approver_locations)

        try:
            if not username:
                flash("Username required.", "warning")
                return redirect(url_for('user_maintenance'))

            # Check if exists
            cur.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            if cur.fetchone()[0] > 0:
                flash(f"⚠️ User {username} already exists.", "warning")
                return redirect(url_for('user_maintenance'))

            # Insert user
            cur.execute("""
                INSERT INTO users (username, display_name, email, role, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, GETDATE(), GETDATE())
            """, (username, display_name, email, role, status))
            conn.commit()

            # fetch ID
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            new_id = cur.fetchone()[0]

            # assign locations
            assign_user_locations(new_id, locations)

            # assign approver
            for loc in approver_locations:
                existing = get_location_approvers(loc)
                if username not in existing:
                    assign_location_approvers(loc, existing + [username])

            flash("✅ User added successfully!", "success")

        except Exception as e:
            print("❌ Add User Error:", e)
            flash(f"Error adding user: {e}", "danger")

        finally:
            cur.close()
            conn.close()

        return redirect(url_for('user_maintenance'))

    # ---------- GET = Load Page ----------

    # Reload connection for GET
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, username, display_name, email, role, status, last_login, last_login_ip
        FROM users ORDER BY created_at DESC
    """)
    users = cur.fetchall()

    locations = get_all_room_locations()

    cur.close()
    conn.close()

    return render_template(
        'user_maintenance.html',
        users=users,
        locations=locations
    )


# @app.route('/user_maintenance', methods=['GET', 'POST'])
# @login_required
# def user_maintenance():
#     if not current_user.is_admin():
#         flash("Access denied: Admins only.", "warning")
#         return redirect(url_for('main_menu'))
#
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#
#         # Handle POST (Add new user)
#         if request.method == 'POST':
#             username = request.form['username'].strip()
#             email = request.form.get('email')
#             display_name = request.form.get('display_name')
#             role = request.form.get('role', 'user')
#             status = request.form.get('status', 'active')
#             # # 1. Read user locations
#             locations = request.form.getlist("locations")
#
#             cursor.execute("SELECT COUNT(*) FROM dbo.users WHERE username = ?", (username,))
#             (exists,) = cursor.fetchone() or (0,)
#             if exists:
#                 flash(f"⚠️ User {username} already exists.", "warning")
#             else:
#                 cursor.execute("""
#                     INSERT INTO dbo.users (username, email, display_name, role, status, created_at, updated_at)
#                     VALUES (?, ?, ?, ?, ?, GETDATE(), GETDATE())
#                 """, (username, email, display_name, role, status))
#                 conn.commit()
#                 flash(f"✅ User {username} added successfully.", "success")
#                 log_audit("USER_ADDED", f"Added user {username} with role {role}")
#
#         # Fetch all users
#         cursor.execute("""
#             SELECT id, username, display_name, email, role, status, last_login, last_login_ip
#             FROM dbo.users
#             ORDER BY created_at DESC
#         """)
#         users = cursor.fetchall()
#         conn.close()
#
#         print(f"📋 Loaded {len(users)} users.")
#         return render_template('user_maintenance.html', users=users)
#
#     except Exception as e:
#         print("⚠️ user_maintenance error:", e)
#         flash("System error while loading users.", "danger")
#         # ✅ Add this redirect or fallback render:
#         return redirect(url_for('main_menu'))
#
#     # except Exception as e:
#     #     print("⚠️ user_maintenance error:", e)
#     #     # Log and show descriptive error
#     #     flash(f"⚠️ A system error occurred while loading users.<br><small>{e}</small>", "danger")
#     #     # ✅ Render the page with an empty user list (so it won't break)
#     #     return render_template('user_maintenance.html', users=[])

@app.route('/menu')
@login_required
def main_menu():
    db_status = "❌ Database Connection Failed"
    ad_status = "⚠️ AD Test Credentials Missing"
    try:
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

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM dbo.rooms WHERE status = 'Active'")
        room_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM dbo.reservations WHERE status = 'Pending'")
        pending_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM dbo.reservations WHERE status = 'Approved'")
        approved_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM dbo.reservations WHERE status = 'Cancelled'")
        cancelled_count = cursor.fetchone()[0]
        # chart data for menu.html
        cursor.execute("""
            SELECT CONVERT(VARCHAR(10), start_time, 120) AS date, status, COUNT(*) AS count
            FROM dbo.reservations
            WHERE start_time >= DATEADD(DAY, -6, CAST(GETDATE() AS date))
            GROUP BY CONVERT(VARCHAR(10), start_time, 120), status
            ORDER BY date ASC
        """)
        rows = cursor.fetchall()
        conn.close()
        # map to date buckets
        date_list = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
        date_map = {d: {'Approved': 0, 'Pending': 0} for d in date_list}
        for row in rows:
            d, status, c = row
            if d in date_map and status in date_map[d]:
                date_map[d][status] = c
        chart_labels = date_list
        chart_pending = [date_map[d]['Pending'] for d in date_list]
        chart_approved = [date_map[d]['Approved'] for d in date_list]
    except Exception as e:
        print("⚠️ Error loading dashboard data:", e)
        room_count = pending_count = approved_count = cancelled_count = 0
        chart_labels = []
        chart_pending = []
        chart_approved = []
    user_info = f"{current_user.display_name or current_user.username} ({current_user.role})"
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
        user_info=user_info
    )

# if __name__ == '__main__':
#     print("🧩 Initializing WebAXIS System...")
#     ensure_default_admin()
#     is_dev = os.getenv("FLASK_ENV", "development").lower() == "development"
#     print(f"💻 Running in {'Development' if is_dev else 'Production'} mode")
#     print("🚀 WebAXIS RoomSys available at http://127.0.0.1:5000/login")
#     if is_dev and os.environ.get("WERKZEUG_RUN_MAIN") == "true":
#         threading.Timer(1.5, lambda: webbrowser.open_new("http://127.0.0.1:5000/login")).start()
#     app.run(debug=is_dev, use_reloader=False)

if __name__ == '__main__':
    print("Initializing WebAXIS System...")
    ensure_default_admin()

    # True if running local dev, false if running inside docker
    is_dev = os.getenv("FLASK_ENV", "development").lower() == "development"
    print(f"Running in {'Development' if is_dev else 'Production'} mode")

    if is_dev:
        # Development mode → Local PC → 127.0.0.1 binding
        print("WebAXIS RoomSys available at http://127.0.0.1:5000/login")

        # Auto-open browser only during development
        if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
            threading.Timer(
                1.5,
                lambda: webbrowser.open_new("http://127.0.0.1:5000/login")
            ).start()

        app.run(
            host="127.0.0.1",
            port=5000,
            debug=True,
            use_reloader=True
        )

    else:
        # Production mode → Docker → must bind to 0.0.0.0
        print("WebAXIS RoomSys available at http://0.0.0.0:5000/login")

        app.run(
            host="0.0.0.0",
            port=5000,
            debug=False,
            use_reloader=False
        )

