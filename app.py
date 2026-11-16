import os
from functools import wraps
import threading
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
    get_dashboard_statistics
)

from dataset.loader import DATASET_FILE
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
    SESSION_COOKIE_SECURE=False
)



dataset_thread = None
dataset_lock = threading.Lock()

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


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = get_authenticated_user()

        if user is None:
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = get_authenticated_user()

        if user is None:
            return redirect(url_for("login"))

        if user["role"] != "Administrator":
            abort(403)

        return function(*args, **kwargs)

    return wrapper


def analyst_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = get_authenticated_user()

        if user is None:
            return redirect(url_for("login"))

        if user["role"] != "Security Analyst":
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
                user_id = create_initial_administrator(
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

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = authenticate_user(username, password)

        if user:

            session.clear()

            session["user_id"] = user["id"]
            session["user"] = user["username"]
            session["role"] = user["role"]



            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():

    session.clear()

    return redirect(url_for("login"))


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():
    severity = request.args.get("severity")
    query = request.args.get("q")

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1

    per_page = 20

    result = get_incidents_page(
        search=query,
        severity=severity,
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
            search=query,
            severity=severity,
            limit=per_page,
            offset=(page - 1) * per_page
        )

    incidents = result["incidents"]

    start_record = (page - 1) * per_page + 1 if total_incidents else 0
    end_record = (page - 1) * per_page + len(incidents)

    statistics = get_dashboard_statistics()
    incident_stats = statistics["incidents"]

    return render_template(
        "dashboard.html",
        incidents=incidents,
        statistics=statistics,
        latest_incident_id=get_latest_incident_id(),
        high=incident_stats["high"],
        medium=incident_stats["medium"],
        low=incident_stats["low"],
        critical=incident_stats["critical"],
        total=incident_stats["total"],
        page=page,
        per_page=per_page,
        total_incidents=total_incidents,
        total_pages=total_pages,
        start_record=start_record,
        end_record=end_record
    )


@app.route("/api/dashboard-updates")
@login_required
def dashboard_updates():
    """Return incidents created since the browser's last update."""

    try:
        after_id = max(0, int(request.args.get("after_id", 0)))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid after_id."}), 400

    severity = request.args.get("severity")
    query = request.args.get("q")

    incidents = get_incidents_after_id(
        after_id=after_id,
        search=query,
        severity=severity,
        limit=500
    )

    statistics = get_dashboard_statistics()

    if len(incidents) >= 500:
        latest_id = incidents[-1]["id"]
    else:
        latest_id = get_latest_incident_id()

    return jsonify({
        "incidents": incidents,
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
        rules=result["rules"],
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
        user_id = create_user(
            username=username,
            password=password,
            role=role
        )

        flash("User created successfully.", "success")

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

    except Exception as error:
        flash(str(error), "error")

    return redirect(url_for("admin_panel"))


# ============================================================
# DETECTION RULES
# ============================================================

@app.route("/rules")
@admin_required
def rules():

    detection_rules = get_detection_rules()

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

    app.run(debug=True, use_reloader=False)
