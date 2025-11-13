# app.py (final)
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from dotenv import load_dotenv
import os
import pyodbc
from datetime import datetime, timedelta, timezone, date, time as datetime_time
import webbrowser
import threading
from dateutil import parser as dateparser  # pip install python-dateutil

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

def get_db_connection():
    driver = '{ODBC Driver 17 for SQL Server}'
    encrypt_option = 'yes' if str(DB_ENCRYPT).lower() == 'yes' else 'no'
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

def is_user_group_admin(username, group_code):
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM dbo.group_approvers WHERE group_code = ? AND approver_username = ?", (group_code, username))
        row = cur.fetchone(); conn.close()
        return (row[0] if row else 0) > 0
    except Exception as e:
        print("⚠️ is_user_group_admin error:", e)
        return False

@app.route('/approvals')
@login_required
def approvals():
    username = current_user.username
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT r.id, r.room_id, rm.name AS room_name, rm.location, r.reserved_by,
               r.start_time, r.end_time, r.remarks, r.status, r.approver_username
        FROM dbo.reservations r
        JOIN dbo.rooms rm ON rm.id = r.room_id
        WHERE r.status = 'Pending' AND r.approver_username = ?
        ORDER BY r.start_time
    """, (username,))
    rows = rows_to_dicts(cur)
    conn.close()
    return render_template('approvals.html', reservations=rows)

@app.route('/approvals/<int:res_id>/approve', methods=['POST'])
@login_required
def approve_reservation(res_id):
    username = current_user.username
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT approver_username, status FROM dbo.reservations WHERE id = ?", (res_id,))
    row = cur.fetchone()
    if not row:
        flash("Reservation not found.", "danger"); conn.close(); return redirect(url_for('approvals'))
    approver_username, status = row
    if approver_username != username:
        flash("Not authorized to approve.", "danger"); conn.close(); return redirect(url_for('approvals'))
    if status != 'Pending':
        flash("Reservation is not pending.", "warning"); conn.close(); return redirect(url_for('approvals'))
    cur.execute("UPDATE dbo.reservations SET status = 'Approved', approved_by = ?, approved_at = GETDATE() WHERE id = ?", (username, res_id))
    conn.commit(); conn.close()
    flash("✅ Reservation approved.", "success")
    return redirect(url_for('approvals'))

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
    username = current_user.username
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT approver_username, status FROM dbo.reservations WHERE id = ?", (res_id,))
    row = cur.fetchone()
    if not row:
        flash("Reservation not found.", "danger"); conn.close(); return redirect(url_for('approvals'))
    approver_username, status = row
    if approver_username != username:
        flash("Not authorized to deny.", "danger"); conn.close(); return redirect(url_for('approvals'))
    if status != 'Pending':
        flash("Reservation is not pending.", "warning"); conn.close(); return redirect(url_for('approvals'))
    cur.execute("UPDATE dbo.reservations SET status = 'Cancelled', approved_by = ?, approved_at = GETDATE() WHERE id = ?", (username, res_id))
    conn.commit(); conn.close()
    flash("✅ Reservation denied.", "info")
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
            ad_ok = authenticate_ldap(username, password)
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
    if not getattr(current_user, 'is_admin', lambda: False)():
        flash("Not authorized.", "danger"); return redirect(url_for('menu'))
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT r.*, (SELECT TOP 1 approver_username FROM dbo.group_approvers g WHERE g.group_code = r.group_code AND g.is_primary = 1) AS group_approver FROM dbo.rooms r WHERE r.status = 'Active' ORDER BY r.group_code, r.name")
    rooms = rows_to_dicts(cur)
    conn.close()
    return render_template('room_maintenance.html', rooms=rooms)

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

# --- ROOM LIST (FULL REPLACEMENT) --------------------------------------------
@app.route('/rooms', methods=['GET'])
@login_required
def room_list():
    from datetime import datetime, date, time, timedelta

    conn = get_db_connection()
    cursor = conn.cursor()

    # --- Normalize selected date from query or session
    date_str = request.args.get("date")
    if date_str:
        try:
            selected_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        except Exception:
            selected_date = datetime.now().date()
    else:
        sd = session.get("selected_date")
        if isinstance(sd, str):
            try:
                selected_date = datetime.strptime(sd, "%Y-%m-%d").date()
            except Exception:
                selected_date = datetime.now().date()
        elif isinstance(sd, date):
            selected_date = sd
        else:
            selected_date = datetime.now().date()

    session["selected_date"] = selected_date.strftime("%Y-%m-%d")

    # optional focus room highlight
    focus_room = request.args.get("focus")

    # --- Compute day window ---
    start_of_day = datetime.combine(selected_date, datetime.min.time())
    end_of_day = start_of_day + timedelta(days=1)

    # --- Fetch rooms ---
    cursor.execute("""
        SELECT id, name, capacity, location, description, group_code, is_combined
        FROM dbo.rooms
        WHERE status = 'Active'
        ORDER BY location, name
    """)
    raw_rooms = cursor.fetchall()

    rooms = []
    for r in raw_rooms:
        rooms.append({
            "id": getattr(r, "id", r[0]),
            "name": getattr(r, "name", r[1]),
            "capacity": getattr(r, "capacity", r[2]),
            "location": getattr(r, "location", r[3]) or "General",
            "description": getattr(r, "description", r[4]),
            "group_code": getattr(r, "group_code", r[5]),
            "is_combined": bool(getattr(r, "is_combined", r[6])),
        })

    # --- Fetch reservations for this day ---
    cursor.execute("""
        SELECT id, room_id, reserved_by, email, start_time, end_time, status, ISNULL(remarks,'') AS remarks
        FROM dbo.reservations
        WHERE status IN ('Pending','Approved','Blocked')
          AND start_time < ? AND end_time > ?
    """, (end_of_day, start_of_day))
    raw_res = cursor.fetchall()

    # --- Build availability dictionary ---
    availability = {}
    for room in rooms:
        rid = room["id"]
        availability[rid] = {}
        for hour in range(6, 20):
            for minute in (0, 30):
                label = f"{hour:02d}:{minute:02d}"
                availability[rid][label] = {
                    "status": "available",
                    "by": "",
                    "remarks": "",
                    "reserved_by": ""
                }

    # --- Mark slots based on reservations ---
    for rr in raw_res:
        res_id = getattr(rr, "id", rr[0])
        r_id = getattr(rr, "room_id", rr[1])
        reserved_by = getattr(rr, "reserved_by", rr[2]) or ""
        remarks = getattr(rr, "remarks", rr[7]) or ""
        status = getattr(rr, "status", rr[6])
        start_time = getattr(rr, "start_time", rr[4])
        end_time = getattr(rr, "end_time", rr[5])

        current = start_time
        while current < end_time:
            label = current.strftime("%H:%M")
            if r_id in availability and label in availability[r_id]:

                # Approved or Blocked → booked
                if status in ("Approved", "Blocked"):
                    availability[r_id][label]["status"] = "booked"

                elif status == "Pending":
                    # Only apply if not already booked
                    if availability[r_id][label]["status"] != "booked":
                        availability[r_id][label]["status"] = "pending"

                availability[r_id][label]["by"] = reserved_by
                availability[r_id][label]["remarks"] = remarks
                availability[r_id][label]["reserved_by"] = reserved_by
                availability[r_id][label + "_id"] = res_id

            current += timedelta(minutes=30)

    conn.close()

    return render_template(
        "index.html",
        rooms=rooms,
        availability=availability,
        selected_date=selected_date,
        focus_room=focus_room
    )


@app.route('/calendar_view', methods=['GET'])
@login_required
def calendar_view():
    from datetime import datetime

    # --- Selected Date ---
    date_str = request.args.get("date")
    if date_str:
        try:
            selected_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        except Exception:
            selected_date = datetime.now().date()
    else:
        selected_date = session.get("selected_date", datetime.now().date())

    session["selected_date"] = selected_date

    # --- Fetch Active Rooms ---
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, name, capacity, location, description, status
        FROM dbo.rooms
        WHERE status = 'Active'
        ORDER BY location, name
    """)
    rows = cursor.fetchall()
    conn.close()
    location_filter = request.args.get("location", "all")

    # --- SAFE conversion: pyodbc → serializable dict ---
    rooms = []
    for r in rows:
        rooms.append({
            "id": int(r.id),
            "name": str(r.name),
            "capacity": int(r.capacity) if r.capacity is not None else 0,
            "location": str(r.location) if r.location else "General",
            "description": str(r.description) if r.description else "",
            "status": str(r.status)
        })

    print("⚠️ Paramter", location_filter)

    return render_template(
        "calendar_view.html",
        selected_date=selected_date,
        rooms=rooms,
        location_filter=location_filter
    )


# @app.route('/rooms', methods=['GET'])
# @login_required
# def room_list():
#     # ensure selected_date is a date object
#     date_str = request.args.get("date")
#     if date_str:
#         try:
#             selected_date = datetime.strptime(date_str, "%Y-%m-%d").date()
#         except Exception:
#             selected_date = datetime.now().date()
#     else:
#         selected_date = session.get("selected_date", datetime.now().date())
#
#     if isinstance(selected_date, str):
#         try:
#             selected_date = datetime.strptime(selected_date, "%Y-%m-%d").date()
#         except Exception:
#             selected_date = datetime.now().date()
#
#     session["selected_date"] = selected_date
#
#     start_of_day = datetime.combine(selected_date, datetime.min.time())
#     end_of_day = start_of_day + timedelta(days=1)
#
#     conn = get_db_connection(); cursor = conn.cursor()
#     cursor.execute("""
#         SELECT id, name, capacity, location, description, group_code, is_combined
#         FROM dbo.rooms
#         WHERE status = 'Active'
#         ORDER BY location, name
#     """)
#     rooms = cursor.fetchall()
#
#     cursor.execute("""
#         SELECT id, room_id, start_time, end_time, status, reserved_by, remarks
#         FROM dbo.reservations
#         WHERE status IN ('Pending', 'Approved', 'Blocked')
#           AND start_time < ? AND end_time > ?
#     """, (end_of_day, start_of_day))
#     reservations = cursor.fetchall()
#
#     availability = {}
#     for room in rooms:
#         rid = room.id if hasattr(room, "id") else room[0]
#         availability[rid] = {}
#         for hour in range(6, 20):
#             for minute in [0, 30]:
#                 time_label = f"{hour:02d}:{minute:02d}"
#                 availability[rid][time_label] = "available"
#                 availability[rid][f"{time_label}_id"] = ""
#                 availability[rid][f"{time_label}_reserved_by"] = ""
#                 availability[rid][f"{time_label}_status"] = ""
#
#     # for res in reservations:
#     #     rid = res.room_id if hasattr(res, "room_id") else res[1]
#     #     start_time = res.start_time if hasattr(res, "start_time") else res[2]
#     #     end_time = res.end_time if hasattr(res, "end_time") else res[3]
#     #     status = res.status if hasattr(res, "status") else res[4]
#     #
#     #     reserved_by = res.reserved_by if hasattr(res, "reserved_by") else res[5]
#     #     res_id = res.id if hasattr(res, "id") else res[0]
#     #
#     #     # normalize datetimes to naive local (DB might be naive)
#     #     current = start_time
#     #     while current < end_time:
#     #         label = current.strftime("%H:%M")
#     #         if rid in availability and label in availability[rid]:
#     #             availability[rid][label] = "booked" if status in ("Approved", "Blocked") else "available"
#     #             availability[rid][f"{label}_id"] = res_id
#     #             availability[rid][f"{label}_reserved_by"] = reserved_by
#     #             availability[rid][f"{label}_status"] = status
#     #         current += timedelta(minutes=30)
#     # mark booked & pending slots
#     for res in reservations:
#         rid = res.room_id if hasattr(res, "room_id") else res[0]
#         start_time = res.start_time if hasattr(res, "start_time") else res[1]
#         end_time = res.end_time if hasattr(res, "end_time") else res[2]
#         status = res.status if hasattr(res, "status") else res[3]
#         reserved_by = res.reserved_by if hasattr(res, "reserved_by") else res[4]
#         remarks = res.remarks if hasattr(res, "remarks") else res[5]
#
#         if rid not in availability:
#             continue
#
#         current = start_time
#         while current < end_time:
#             label = current.strftime("%H:%M")
#             if label in availability[rid]:
#                 if status == "Approved" or status == "Blocked":
#                     availability[rid][label] = {
#                         "status": "booked",
#                         "by": reserved_by,
#                         "remarks": remarks
#                     }
#                 elif status == "Pending":
#                     availability[rid][label] = {
#                         "status": "pending",
#                         "by": reserved_by,
#                         "remarks": remarks
#                     }
#             current += timedelta(minutes=30)
#
#     conn.close()
#
#     # optional focus highlight param
#     focus_room = request.args.get('focus', None)
#     return render_template("index.html", rooms=rooms, availability=availability, selected_date=selected_date, focus_room=focus_room)
#


# ... (export_excel, api_reservations, helpers unchanged, keep them as in your existing file) ...
# We'll include reserve / reserve_post / api_check_slot / api_room_availability / api_booked_slots / room_schedule unchanged
# (but ensure they are present exactly as in your working copy). For brevity I keep the rest of your file intact.

def get_room_by_id(conn, room_id):
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, group_code, is_combined FROM dbo.rooms WHERE id = ?", (room_id,))
    row = cursor.fetchone()
    if row:
        return {"id": row[0], "name": row[1], "group_code": row[2], "is_combined": bool(row[3])}
    return None

def get_linked_rooms(conn, group_code, exclude_id=None):
    cursor = conn.cursor()
    if exclude_id:
        cursor.execute("SELECT id FROM dbo.rooms WHERE group_code = ? AND id <> ?", (group_code, exclude_id))
    else:
        cursor.execute("SELECT id FROM dbo.rooms WHERE group_code = ?", (group_code,))
    return [r[0] for r in cursor.fetchall()]

@app.route('/confirm')
@login_required
def confirm():
    return render_template('confirmation.html')


@app.route('/reserve_post/<int:room_id>', methods=['POST'])
@login_required
def reserve_post(room_id):
    from datetime import datetime, timedelta, timezone
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        room = get_room_by_id(conn, room_id)
        if not room:
            return jsonify({"success": False, "message": "Room not found."}), 404

        reserved_by = request.form.get('reserved_by')
        email = request.form.get('email', '')
        remarks = request.form.get('remarks', '')
        start_str = request.form.get('start_time')
        end_str = request.form.get('end_time')
        repeat_until_str = request.form.get('repeat_until')  # optional YYYY-MM-DD

        # parse times (from datetime-local e.g. 2025-11-12T09:30)
        try:
            start_dt = datetime.fromisoformat(start_str)
            end_dt = datetime.fromisoformat(end_str)
        except Exception:
            return jsonify({"success": False, "message": "Invalid date/time format."}), 400

        if end_dt <= start_dt:
            return jsonify({"success": False, "message": "End must be after start."}), 400

        # timezone normalization (GMT+8)
        tz = timezone(timedelta(hours=8))
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=tz)
        if end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=tz)

        # compute repeat range
        repeat_dates = [start_dt.date()]
        if repeat_until_str:
            try:
                repeat_until_date = datetime.strptime(repeat_until_str, "%Y-%m-%d").date()
            except Exception:
                return jsonify({"success": False, "message": "Invalid repeat_until date."}), 400
            if repeat_until_date < start_dt.date():
                return jsonify({"success": False, "message": "repeat_until must be >= start date."}), 400
            d = start_dt.date()
            while d <= repeat_until_date:
                if d != start_dt.date():
                    repeat_dates.append(d)
                d = d + timedelta(days=1)

        # prepare linked rooms if combined
        linked_room_ids = []
        if room.get("is_combined") and room.get("group_code"):
            linked_room_ids = get_linked_rooms(conn, room["group_code"], room_id)
        all_room_ids_template = [room_id] + linked_room_ids

        # Begin transaction (pyodbc default autocommit False)
        # For each date, build start/end datetimes with same time-of-day, check overlaps and insert
        inserted_ids = []
        for day in repeat_dates:
            # create day-specific start/end preserving time-of-day
            day_start = datetime.combine(day, start_dt.timetz()) if hasattr(start_dt, 'timetz') else datetime(day.year, day.month, day.day, start_dt.hour, start_dt.minute)
            day_end = datetime.combine(day, end_dt.timetz()) if hasattr(end_dt, 'timetz') else datetime(day.year, day.month, day.day, end_dt.hour, end_dt.minute)
            # ensure tz
            if day_start.tzinfo is None: day_start = day_start.replace(tzinfo=tz)
            if day_end.tzinfo is None: day_end = day_end.replace(tzinfo=tz)

            # overlap checks across all relevant room ids (Pending/Approved/Blocked)
            for rid in all_room_ids_template:
                cursor.execute("""
                    SELECT COUNT(*) FROM dbo.reservations
                    WHERE room_id = ? AND status IN ('Pending','Approved','Blocked')
                      AND NOT (end_time <= ? OR start_time >= ?)
                """, (rid, day_start, day_end))
                conflict_count = cursor.fetchone()[0]
                if conflict_count > 0:
                    conn.rollback()
                    return jsonify({
                        "success": False,
                        "message": f"Conflict found on {day.isoformat()} for room id {rid}."
                    }), 409

            # if no conflict: insert main reservation (Pending)
            cursor.execute("""
                INSERT INTO dbo.reservations (room_id, reserved_by, email, start_time, end_time, remarks, status, approver_username)
                VALUES (?, ?, ?, ?, ?, ?, 'Pending', ?)
            """, (room_id, reserved_by, email, day_start, day_end, remarks, get_group_approver(room.get("group_code")) if room.get("group_code") else None))

            # get inserted id (SQL Server SCOPE_IDENTITY)
            cursor.execute("SELECT CAST(SCOPE_IDENTITY() AS INT)")
            inserted_id_row = cursor.fetchone()
            inserted_id = inserted_id_row[0] if inserted_id_row else None
            if inserted_id:
                inserted_ids.append(inserted_id)

            # insert blocked entries for linked rooms
            for lid in linked_room_ids:
                cursor.execute("""
                    INSERT INTO dbo.reservations (room_id, reserved_by, email, start_time, end_time, remarks, status, approver_username)
                    VALUES (?, ?, ?, ?, ?, ?, 'Blocked', ?)
                """, (lid, f"[AUTO BLOCK] {reserved_by}", email, day_start, day_end, f"Blocked by combined booking of {room['name']}", get_group_approver(room.get("group_code")) if room.get("group_code") else None))

        # commit all inserts
        conn.commit()

        # build response
        return jsonify({
            "success": True,
            "message": f"Reservation submitted for {room['name']} and pending approval.",
            "room_id": room_id,
            "reservation_ids": inserted_ids,
            "start": start_dt.strftime("%H:%M"),
            "end": end_dt.strftime("%H:%M")
        })

    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        app.logger.exception("reserve_post error")
        return jsonify({"success": False, "message": f"System error: {e}"}), 500
    finally:
        try:
            conn.close()
        except:
            pass


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
   room = request.args.get('room', 'all')
   group = request.args.get('group', 'all')
   start = request.args.get('start')
   end = request.args.get('end')
   from datetime import datetime, timedelta, timezone
   from dateutil import parser as dateparser
   # --- Parse FullCalendar range
   try:
       start_dt = dateparser.isoparse(start)
       end_dt = dateparser.isoparse(end)
   except Exception as e:
       print("⚠️ Invalid date range:", e)
       return jsonify([])
   # --- Connect
   conn = get_db_connection()
   cursor = conn.cursor()
   # --- Base query
   query = """
       SELECT rm.id, rm.name, rm.location, r.reserved_by,
              r.start_time, r.end_time, ISNULL(r.remarks, '') AS remarks,
              r.status
       FROM dbo.reservations r
       INNER JOIN dbo.rooms rm ON rm.id = r.room_id
       WHERE r.status IN ('Approved', 'Pending')
         AND r.start_time >= ? AND r.start_time < ?
   """
   params = [start_dt, end_dt]
   # --- Apply filters dynamically
   if group and group.lower() != "all":
       query += " AND LOWER(LTRIM(RTRIM(rm.location))) = LOWER(?)"
       params.append(group.strip())
   if room and room.lower() != "all":
       query += " AND LOWER(LTRIM(RTRIM(rm.name))) = LOWER(?)"
       params.append(room.strip())
   query += " ORDER BY r.start_time"
   # print("🧠 SQL RUN:", query)
   print("🧩 Params:", params)
   cursor.execute(query, params)
   rows = cursor.fetchall()
   conn.close()
   # --- Force timezone +08:00 for display
   tz = timezone(timedelta(hours=8))
   events = []
   for rid, name, location, reserved_by, start_time, end_time, remarks, status in rows:
       start_local = start_time.replace(tzinfo=tz)
       end_local = end_time.replace(tzinfo=tz)
       color = "#0047AB" if status == "Approved" else "#FFA726"
       events.append({
           "id": rid,
           "title": f"{name} - {reserved_by}",
           "start": start_local.isoformat(),
           "end": end_local.isoformat(),
           "room": name,
           "location": location,
           "description": remarks,
           "status": status,
           "color": color
       })
   print(f"✅ Returned {len(events)} events for Group={group}, Room={room}")
   return jsonify(events)

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

# User maintenance (admin-only)
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

    except Exception as e:
        print("⚠️ user_maintenance error:", e)
        flash("System error while loading users.", "danger")
        # ✅ Add this redirect or fallback render:
        return redirect(url_for('main_menu'))

    # except Exception as e:
    #     print("⚠️ user_maintenance error:", e)
    #     # Log and show descriptive error
    #     flash(f"⚠️ A system error occurred while loading users.<br><small>{e}</small>", "danger")
    #     # ✅ Render the page with an empty user list (so it won't break)
    #     return render_template('user_maintenance.html', users=[])

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

if __name__ == '__main__':
    print("🧩 Initializing WebAXIS System...")
    ensure_default_admin()
    is_dev = os.getenv("FLASK_ENV", "development").lower() == "development"
    print(f"💻 Running in {'Development' if is_dev else 'Production'} mode")
    print("🚀 WebAXIS RoomSys available at http://127.0.0.1:5000/login")
    if is_dev and os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        threading.Timer(1.5, lambda: webbrowser.open_new("http://127.0.0.1:5000/login")).start()
    app.run(debug=is_dev, use_reloader=False)
