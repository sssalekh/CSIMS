import os
from functools import wraps
import threading
import time
from dataset.processor import process_dataset
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    jsonify
)

from flask_wtf.csrf import CSRFProtect

from storage.db import (
    initialize_database,
    administrator_exists,
    authenticate_user,
    get_active_user,
    get_users,
    set_user_role,
    create_user,
    delete_user,
    administrator_account_exists,
    create_initial_administrator,
    get_detection_rules,
    toggle_detection_rule,
    get_incidents_page,
    get_incidents_after_id,
    get_latest_incident_id,
    get_incident_detail,
    update_incident_status,
    update_incident_severity,
    add_incident_comment,
    get_dashboard_statistics,
    change_password,
    reset_user_password,
    set_user_active
)

from dataset.loader import DATASET_FILE
from detection.config import DETECTION_THRESHOLDS
from detection.rules import build_detection_rules
from pathlib import Path

app = Flask(__name__)

csrf = CSRFProtect(app)

app.secret_key = os.environ.get("CSIMS_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "CSIMS_SECRET_KEY environment variable is not configured."
    ) 

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # The Secure flag sends the session cookie only over HTTPS. It is off
    # for the local HTTP demonstration and enabled with CSIMS_HTTPS=1.
    SESSION_COOKIE_SECURE=os.environ.get("CSIMS_HTTPS") == "1"
)



dataset_thread = None
dataset_lock = threading.Lock()

# Logical rule codes (DOS-001, REC-001, ...) by rule name. The database
# identifies registered rules by their names, so the codes defined in
# detection/rules.py can be shown in the interface without a schema change.
RULE_CODES = {
    rule.name: rule.rule_id
    for rule in build_detection_rules(DETECTION_THRESHOLDS)
}


def add_rule_codes(rules):
    """Attach the logical rule code to each rule read from the database."""

    for rule in rules:
        rule["code"] = RULE_CODES.get(rule["name"])

    return rules

PROCESSING_STATE_FILE = (
    Path(__file__).resolve().parent / ".dataset_processed"
)


def run_dataset_processing(max_records=None):
    global dataset_thread

    try:
        process_dataset(
            max_records=max_records
        )
    except Exception:
        app.logger.exception("Background dataset processing failed")
    finally:
        with dataset_lock:
            dataset_thread = None


def start_dataset_processing(max_records=None):
    global dataset_thread

    with dataset_lock:
        if dataset_thread is not None and dataset_thread.is_alive():
            return False

        dataset_thread = threading.Thread(
            target=run_dataset_processing,
            args=(max_records,),
            daemon=True
        )
        dataset_thread.start()

        return True


def should_process_dataset():
    if not DATASET_FILE.exists():
        raise FileNotFoundError(
            f"Dataset file not found: {DATASET_FILE}"
        )

    dataset_stat = DATASET_FILE.stat()
    current_signature = (
        f"{dataset_stat.st_size}:{dataset_stat.st_mtime_ns}"
    )

    if not PROCESSING_STATE_FILE.exists():
        return True

    saved_signature = PROCESSING_STATE_FILE.read_text(
        encoding="utf-8"
    ).strip()

    return saved_signature != current_signature

# ============================================================
# LOGIN ATTEMPT LIMITING
# ============================================================

# After MAX_FAILED_LOGIN_ATTEMPTS consecutive failed logins for one
# username, logins for that username are blocked for
# LOGIN_LOCKOUT_SECONDS, even with the correct password. This slows down
# password guessing (brute-force attacks).
#
# The counters are kept in application memory, so they are reset when the
# application restarts. This is sufficient for a single-process deployment.
# Unknown usernames are counted in the same way, so the response does not
# reveal whether an account exists.
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 5 * 60
MAX_TRACKED_USERNAMES = 10000

failed_logins = {}
failed_logins_lock = threading.Lock()


def _forget_old_failed_logins(now):
    """Remove entries that are no longer locked and no longer recent."""

    for username in list(failed_logins):
        entry = failed_logins[username]
        if (
            entry["locked_until"] <= now
            and now - entry["last_failure"] >= LOGIN_LOCKOUT_SECONDS
        ):
            del failed_logins[username]


def login_lock_remaining(username):
    """Return the remaining lockout time in seconds (0 if not locked)."""

    now = time.monotonic()

    with failed_logins_lock:
        entry = failed_logins.get(username)

        if entry is None:
            return 0

        if entry["locked_until"] > now:
            return entry["locked_until"] - now

        return 0


def register_failed_login(username):
    """Count a failed login and lock the username after too many failures."""

    now = time.monotonic()

    with failed_logins_lock:
        if len(failed_logins) >= MAX_TRACKED_USERNAMES:
            _forget_old_failed_logins(now)

        entry = failed_logins.get(username)

        # Failures older than the lockout period are not counted.
        if (
            entry is None
            or now - entry["last_failure"] >= LOGIN_LOCKOUT_SECONDS
        ):
            entry = {"count": 0, "locked_until": 0.0, "last_failure": now}
            failed_logins[username] = entry

        entry["count"] += 1
        entry["last_failure"] = now

        if entry["count"] >= MAX_FAILED_LOGIN_ATTEMPTS:
            entry["count"] = 0
            entry["locked_until"] = now + LOGIN_LOCKOUT_SECONDS


def clear_failed_logins(username):
    """Reset the counter after a successful login or a password reset."""

    with failed_logins_lock:
        failed_logins.pop(username, None)


def lockout_message(seconds):
    minutes = max(1, int((seconds + 59) // 60))
    unit = "minute" if minutes == 1 else "minutes"

    return (
        "Too many failed login attempts. "
        f"Try again in {minutes} {unit}."
    )


# ============================================================
# ACCESS CONTROL
# ============================================================


def get_authenticated_user():
    """Return the current active user and refresh session data."""

    user_id = session.get("user_id")

    if user_id is None:
        return None

    user = get_active_user(user_id)

    if user is None:
        session.clear()
        return None

    # Synchronize session with the current database values.
    session["user"] = user["username"]
    session["role"] = user["role"]

    return user


# Pages that stay available while a user must replace a temporary password.
PASSWORD_CHANGE_ALLOWED_ENDPOINTS = {"change_password_page", "logout"}


def password_change_required(user):
    """Return True when the user must replace a temporary password first."""

    return (
        bool(user["must_change_password"])
        and request.endpoint not in PASSWORD_CHANGE_ALLOWED_ENDPOINTS
    )


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = get_authenticated_user()

        if user is None:
            return redirect(url_for("login"))

        if password_change_required(user):
            return redirect(url_for("change_password_page"))

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = get_authenticated_user()

        if user is None:
            return redirect(url_for("login"))

        if password_change_required(user):
            return redirect(url_for("change_password_page"))

        if user["role"] != "Administrator":
            abort(403)

        return function(*args, **kwargs)

    return wrapper

# ============================================================
# INITIAL ADMINISTRATOR SETUP
# ============================================================

@app.route("/setup", methods=["GET", "POST"])
def initial_setup():

    if administrator_account_exists():
        return redirect(url_for("login"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password:
            flash("Username and password are required.", "error")

        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")

        elif password != confirm_password:
            flash("Passwords do not match.", "error")

        else:
            try:
                create_initial_administrator(
                    username=username,
                    password=password
                )
                
                # Start dataset processing after the first administrator is created.
                try:
                    if should_process_dataset():
                        started = start_dataset_processing()

                        if started:
                            app.logger.info(
                                "Dataset processing started after administrator setup."
                            )
                        else:
                            app.logger.info(
                                "Dataset processing is already running."
                            )
                    else:
                        app.logger.info(
                            "Dataset has already been processed. "
                            "Automatic processing skipped."
                        )

                except Exception:
                    app.logger.exception(
                        "Could not start dataset processing after administrator setup."
                    )



                flash(
                    "Administrator account created. You can now log in.",
                    "success"
                )

                return redirect(url_for("login"))

            except ValueError as error:
                flash(str(error), "error")

    return render_template("setup.html")


# ============================================================
# LOGIN AND LOGOUT
# ============================================================

@app.route("/", methods=["GET", "POST"])
def login():

    # Until the first Administrator account is created, nobody can log in,
    # so the user is sent to the initial setup page (FR-17).
    if not administrator_account_exists():
        return redirect(url_for("initial_setup"))

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        remaining = login_lock_remaining(username)

        # While a username is locked, even the correct password is refused.
        if remaining:
            flash(lockout_message(remaining), "error")
            return render_template("login.html"), 429

        user = authenticate_user(username, password)

        if user:

            clear_failed_logins(username)

            session.clear()

            session["user_id"] = user["id"]
            session["user"] = user["username"]
            session["role"] = user["role"]



            return redirect(url_for("dashboard"))

        register_failed_login(username)

        remaining = login_lock_remaining(username)

        if remaining:
            flash(lockout_message(remaining), "error")
            return render_template("login.html"), 429

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():

    session.clear()

    return redirect(url_for("login"))


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password_page():
    """
    Let the current user replace their password.

    A user whose account was created or reset by an Administrator is sent
    here after logging in and cannot open other pages until the temporary
    password has been replaced.
    """

    user = get_authenticated_user()
    must_change = bool(user["must_change_password"])

    if request.method == "POST":

        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        try:
            if new_password != confirm_password:
                raise ValueError("New passwords do not match.")

            change_password(
                user_id=user["id"],
                current_password=current_password,
                new_password=new_password
            )

            flash("Password changed successfully.", "success")

            return redirect(url_for("dashboard"))

        except ValueError as error:
            flash(str(error), "error")

    return render_template(
        "change_password.html",
        must_change=must_change
    )


# ============================================================
# DASHBOARD
# ============================================================

# Filter options shown on the incidents page, in display order.
SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"]
STATUS_OPTIONS = ["New", "In Progress", "Resolved", "Closed"]
CATEGORY_OPTIONS = [
    "Dos / DDoS",
    "Exploitation",
    "Reconnaissance",
    "Other suspicious activity",
]

# Number of latest incidents shown on the dashboard overview.
RECENT_INCIDENTS_LIMIT = 10


@app.route("/dashboard")
@login_required
def dashboard():
    """Overview: incident statistics and the latest incidents."""

    statistics = get_dashboard_statistics()["incidents"]

    recent_incidents = get_incidents_page(
        limit=RECENT_INCIDENTS_LIMIT
    )["incidents"]

    return render_template(
        "dashboard.html",
        statistics=statistics,
        recent_incidents=recent_incidents,
        recent_limit=RECENT_INCIDENTS_LIMIT,
        latest_incident_id=get_latest_incident_id()
    )


@app.route("/incidents")
@login_required
def incidents():
    """Full incident list with search, filters and pagination."""

    query = request.args.get("q")
    severity = request.args.get("severity")
    status = request.args.get("status")
    category = request.args.get("category")

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1

    per_page = 20

    filters = {
        "search": query,
        "severity": severity,
        "status": status,
        "category": category,
    }

    result = get_incidents_page(
        **filters,
        limit=per_page,
        offset=(page - 1) * per_page
    )

    total_incidents = result["total"]
    total_pages = max(
        1,
        (total_incidents + per_page - 1) // per_page
    )

    if page > total_pages:
        page = total_pages

        result = get_incidents_page(
            **filters,
            limit=per_page,
            offset=(page - 1) * per_page
        )

    incident_list = result["incidents"]

    start_record = (page - 1) * per_page + 1 if total_incidents else 0
    end_record = (page - 1) * per_page + len(incident_list)

    return render_template(
        "incidents.html",
        incidents=incident_list,
        latest_incident_id=get_latest_incident_id(),
        page=page,
        per_page=per_page,
        total_incidents=total_incidents,
        total_pages=total_pages,
        start_record=start_record,
        end_record=end_record,
        severity_options=SEVERITY_OPTIONS,
        status_options=STATUS_OPTIONS,
        category_options=CATEGORY_OPTIONS
    )


@app.route("/api/dashboard-updates")
@login_required
def dashboard_updates():
    """Return incidents created since the browser's last update."""

    try:
        after_id = max(0, int(request.args.get("after_id", 0)))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid after_id."}), 400

    new_incidents = get_incidents_after_id(
        after_id=after_id,
        search=request.args.get("q"),
        severity=request.args.get("severity"),
        status=request.args.get("status"),
        category=request.args.get("category"),
        limit=500
    )

    statistics = get_dashboard_statistics()

    if len(new_incidents) >= 500:
        latest_id = new_incidents[-1]["id"]
    else:
        latest_id = get_latest_incident_id()

    return jsonify({
        "incidents": new_incidents,
        "latest_id": latest_id,
        "statistics": statistics["incidents"],
    })


# ============================================================
# INCIDENT MANAGEMENT
# ============================================================

@app.route("/incident/<int:id>")
@login_required
def incident_detail(id):

    result = get_incident_detail(id)

    if result is None:
        abort(404)

    return render_template(
        "incident_detail.html",
        incident=result["incident"],
        rules=add_rule_codes(result["rules"]),
        comments=result["comments"]
    )


@app.route("/update_status/<int:id>/<status>", methods=["POST"])
@login_required
def update_status(id, status):

    try:
        update_incident_status(id, status)


        flash("Incident status updated.", "success")

    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("incident_detail", id=id))


@app.route("/close/<int:id>", methods=["POST"])
@login_required
def close_incident(id):

    try:
        update_incident_status(id, "Closed")

        flash("Incident closed.", "success")

    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("incident_detail", id=id))


@app.route("/update_severity/<int:id>", methods=["POST"])
@login_required
def update_severity(id):

    severity = request.form.get("severity", "")

    try:
        update_incident_severity(id, severity)

        flash("Incident severity updated.", "success")

    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("incident_detail", id=id))


@app.route("/add_comment/<int:id>", methods=["POST"])
@login_required
def add_comment(id):

    comment = request.form.get("comment", "")

    try:
        add_incident_comment(
            incident_id=id,
            user_id=session["user_id"],
            comment=comment
        )


        flash("Comment added.", "success")

    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("incident_detail", id=id))


# ============================================================
# USER MANAGEMENT
# ============================================================

@app.route("/admin")
@admin_required
def admin_panel():

    users = get_users()

    return render_template(
        "admin.html",
        users=users
    )


@app.route("/add_user", methods=["POST"])
@admin_required
def add_user():

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "")

    try:
        create_user(
            username=username,
            password=password,
            role=role
        )

        flash(
            "User created successfully. The user must change the "
            "temporary password at the first login.",
            "success"
        )

    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("admin_panel"))


@app.route("/update_user_role/<int:id>", methods=["POST"])
@admin_required
def update_user_role(id):

    role = request.form.get("role", "")

    try:
        if id == session["user_id"] and role != "Administrator":
            raise ValueError(
                "You cannot change your own administrator role."
            )

        set_user_role(id, role)

        flash("User role updated successfully.", "success")

    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("admin_panel"))


@app.route("/reset_user_password/<int:id>", methods=["POST"])
@admin_required
def reset_user_password_route(id):

    if id == session["user_id"]:
        flash(
            "Use Change Password to change your own password.",
            "error"
        )
        return redirect(url_for("admin_panel"))

    temporary_password = request.form.get("temporary_password", "")

    try:
        user = get_active_user(id)

        reset_user_password(id, temporary_password)

        # A password reset also removes a login lockout for that user.
        if user is not None:
            clear_failed_logins(user["username"])

        flash(
            "Temporary password set. The user must change it "
            "at the next login.",
            "success"
        )

    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("admin_panel"))


@app.route("/set_user_active/<int:id>", methods=["POST"])
@admin_required
def set_user_active_route(id):

    activate = request.form.get("active") == "1"

    if id == session["user_id"] and not activate:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("admin_panel"))

    try:
        set_user_active(id, activate)

        if activate:
            flash("User account activated.", "success")
        else:
            flash(
                "User account deactivated. The user can no longer "
                "log in, and existing records are preserved.",
                "success"
            )

    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("admin_panel"))


@app.route("/delete_user/<int:id>", methods=["POST"])
@admin_required
def delete_user_route(id):

    if id == session["user_id"]:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin_panel"))

    try:
        result = delete_user(id)

        if result == "anonymized":
            flash(
                "User account anonymized and deactivated. "
                "Existing comments have been preserved.",
                "success"
            )
        else:
            flash("User deleted successfully.", "success")

    except ValueError as error:
        flash(str(error), "error")

    except Exception:
        # Unexpected errors are logged, but technical details are not shown.
        app.logger.exception("Could not delete user %s", id)
        flash("The user account could not be deleted.", "error")

    return redirect(url_for("admin_panel"))


# ============================================================
# DETECTION RULES
# ============================================================

@app.route("/rules")
@admin_required
def rules():

    detection_rules = add_rule_codes(get_detection_rules())

    return render_template(
        "rules.html",
        rules=detection_rules
    )


@app.route("/toggle_rule/<int:id>", methods=["POST"])
@admin_required
def toggle_rule(id):

    try:
        toggle_detection_rule(id)

        flash("Detection rule updated.", "success")

    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("rules"))


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(403)
def access_denied(error):
    return "Access denied", 403


@app.errorhandler(404)
def page_not_found(error):
    return "Page not found", 404


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    initialize_database()

    if administrator_exists() and should_process_dataset():
        started = start_dataset_processing()

        if started:
            app.logger.info("Automatic dataset processing started.")
    else:
        app.logger.info(
            "Automatic dataset processing skipped. "
            "Administrator setup is incomplete or dataset is already processed."
        )

    # The Flask debugger must never be enabled where other people can
    # reach the server. It is off by default and can be enabled only
    # explicitly for local development: set CSIMS_DEBUG=1.
    debug_mode = os.environ.get("CSIMS_DEBUG") == "1"

    app.run(debug=debug_mode, use_reloader=False)