import sqlite3
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATABASE_PATH = PROJECT_ROOT / "csims_v2.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


VALID_ROLES = {
    "Administrator",
    "Security Analyst"
}

VALID_SEVERITIES = {
    "Low",
    "Medium",
    "High",
    "Critical"
}

# Initial severity is determined by the incident category (Thesis Table 4).
CATEGORY_INITIAL_SEVERITY = {
    "Reconnaissance": "Low",
    "Dos / DDoS": "High",
    "Exploitation": "Critical",
    "Other suspicious activity": "Medium"
}

VALID_CATEGORIES = set(CATEGORY_INITIAL_SEVERITY)

VALID_STATUSES = {
    "New",
    "In Progress",
    "Resolved",
    "Closed"
}


# ============================================================
# CONNECTION
# ============================================================

def get_connection():
    """Create a connection to the CSIMS database."""

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30
    )

    connection.execute("PRAGMA foreign_keys = ON")
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """Create database tables and migrate category columns."""

    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(
            f"Database schema not found: {SCHEMA_PATH}"
        )

    connection = get_connection()

    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as file:
            schema = file.read()

        connection.executescript(schema)

        # Migrate incidents.category.
        incident_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(incidents)"
            ).fetchall()
        }

        if "category" not in incident_columns:
            connection.execute(
                "ALTER TABLE incidents ADD COLUMN category TEXT"
            )

        # Migrate detection_rules.category.
        rule_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(detection_rules)"
            ).fetchall()
        }

        if "category" not in rule_columns:
            connection.execute(
                """
                ALTER TABLE detection_rules
                ADD COLUMN category TEXT
                CHECK (
                    category IS NULL
                    OR category IN (
                        'Reconnaissance',
                        'Dos / DDoS',
                        'Exploitation',
                        'Other suspicious activity'
                    )
                )
                """
            )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# ============================================================
# USER MANAGEMENT
# ============================================================


def authenticate_user(username, password):
    """Authenticate an active user."""

    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT
                user_id AS id,
                username,
                password_hash,
                role,
                is_active
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if not user or not user["is_active"]:
            return None

        if not check_password_hash(user["password_hash"], password):
            return None

        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }

    finally:
        connection.close()


def get_active_user(user_id):
    """Return the current data of an active user."""

    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT
                user_id AS id,
                username,
                role,
                is_active
            FROM users
            WHERE user_id = ?
            AND is_active = 1
            """,
            (user_id,)
        ).fetchone()

        if user is None:
            return None

        return dict(user)

    finally:
        connection.close()


def get_users():
    """Return all users without password hashes."""

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                user_id AS id,
                username,
                role,
                is_active,
                created_at
            FROM users
            ORDER BY user_id
            """
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def administrator_exists():
    """Check whether an active administrator already exists."""

    connection = get_connection()

    try:
        administrator = connection.execute(
            """
            SELECT user_id
            FROM users
            WHERE role = 'Administrator'
            AND is_active = 1
            LIMIT 1
            """
        ).fetchone()

        return administrator is not None

    finally:
        connection.close()
        

def administrator_account_exists():
    """Check whether any administrator account already exists."""

    connection = get_connection()

    try:
        administrator = connection.execute(
            """
            SELECT user_id
            FROM users
            WHERE role = 'Administrator'
            LIMIT 1
            """
        ).fetchone()

        return administrator is not None

    finally:
        connection.close()


def create_initial_administrator(username, password):
    """Atomically create the first administrator account."""

    username = username.strip()

    if not username or not password:
        raise ValueError("Username and password are required.")

    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")

    password_hash = generate_password_hash(password)
    connection = get_connection()

    try:
        connection.execute("BEGIN IMMEDIATE")

        administrator = connection.execute(
            """
            SELECT user_id
            FROM users
            WHERE role = 'Administrator'
            LIMIT 1
            """
        ).fetchone()

        if administrator is not None:
            raise ValueError("An administrator account already exists.")

        cursor = connection.execute(
            """
            INSERT INTO users (
                username,
                password_hash,
                role
            )
            VALUES (?, ?, ?)
            """,
            (username, password_hash, "Administrator")
        )

        connection.commit()
        return cursor.lastrowid

    except sqlite3.IntegrityError:
        connection.rollback()
        raise ValueError("Username already exists.")

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def create_user(username, password, role):
    """Create a user with a securely hashed password."""

    username = username.strip()

    if not username or not password:
        raise ValueError("Username and password are required.")
    
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")

    if role not in VALID_ROLES:
        raise ValueError("Invalid user role.")

    password_hash = generate_password_hash(password)
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO users (
                username,
                password_hash,
                role
            )
            VALUES (?, ?, ?)
            """,
            (username, password_hash, role)
        )

        connection.commit()
        return cursor.lastrowid

    except sqlite3.IntegrityError:
        connection.rollback()
        raise ValueError("Username already exists.")

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def set_user_active(user_id, is_active):
    """Activate or deactivate a user account."""

    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT user_id, role, is_active
            FROM users
            WHERE user_id = ?
            """,
            (user_id,)
        ).fetchone()

        if user is None:
            raise ValueError("User not found.")

        if (
            not is_active
            and user["role"] == "Administrator"
            and user["is_active"]
        ):
            active_admins = connection.execute(
                """
                SELECT COUNT(*)
                FROM users
                WHERE role = 'Administrator'
                AND is_active = 1
                """
            ).fetchone()[0]

            if active_admins <= 1:
                raise ValueError(
                    "Cannot deactivate the last active administrator."
                )

        connection.execute(
            """
            UPDATE users
            SET is_active = ?
            WHERE user_id = ?
            """,
            (int(bool(is_active)), user_id)
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def set_user_role(user_id, role):
    """Change a user's role."""

    if role not in VALID_ROLES:
        raise ValueError("Invalid user role.")

    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT user_id, role, is_active
            FROM users
            WHERE user_id = ?
            """,
            (user_id,)
        ).fetchone()

        if user is None:
            raise ValueError("User not found.")

        if (
            user["role"] == "Administrator"
            and role != "Administrator"
            and user["is_active"]
        ):
            active_admins = connection.execute(
                """
                SELECT COUNT(*)
                FROM users
                WHERE role = 'Administrator'
                AND is_active = 1
                """
            ).fetchone()[0]

            if active_admins <= 1:
                raise ValueError(
                    "Cannot change the role of the last active administrator."
                )

        connection.execute(
            """
            UPDATE users
            SET role = ?
            WHERE user_id = ?
            """,
            (role, user_id)
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def delete_user(user_id):
    """
    Delete a user account while preserving comment authorship.

    Users without comments are physically deleted.
    Users with comments are anonymized and deactivated.
    """

    connection = get_connection()

    try:
        # Keep the check and the following operation in one transaction.
        connection.execute("BEGIN IMMEDIATE")

        user = connection.execute(
            """
            SELECT user_id, role
            FROM users
            WHERE user_id = ?
            """,
            (user_id,)
        ).fetchone()

        if user is None:
            raise ValueError("User not found.")

        if user["role"] == "Administrator":
            admin_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM users
                WHERE role = 'Administrator'
                AND is_active = 1
                """
            ).fetchone()[0]

            if admin_count <= 1:
                raise ValueError(
                    "Cannot delete the last active administrator."
                )

        comment_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM incident_comments
            WHERE user_id = ?
            """,
            (user_id,)
        ).fetchone()[0]

        if comment_count > 0:
            connection.execute(
                """
                UPDATE users
                SET username = ?,
                    is_active = 0
                WHERE user_id = ?
                """,
                (f"deleted_user_{user_id}", user_id)
            )

            connection.commit()
            return "anonymized"

        connection.execute(
            """
            DELETE FROM users
            WHERE user_id = ?
            """,
            (user_id,)
        )

        connection.commit()
        return "deleted"

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# ============================================================
# DETECTION RULES
# ============================================================


def register_detection_rules(rules):
    """Register detection rules while preserving their enabled states."""

    connection = get_connection()

    try:
        for rule in rules:
            existing = connection.execute(
                """
                SELECT rule_id
                FROM detection_rules
                WHERE name = ?
                """,
                (rule.name,)
            ).fetchone()

            if existing is None:
                connection.execute(
                    """
                    INSERT INTO detection_rules (
                        name,
                        description,
                        category,
                        default_severity
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        rule.name,
                        rule.description,
                        rule.category,
                        rule.severity
                    )
                )
            else:
                connection.execute(
                    """
                    UPDATE detection_rules
                    SET description = ?,
                        category = ?,
                        default_severity = ?
                    WHERE rule_id = ?
                    """,
                    (
                        rule.description,
                        rule.category,
                        rule.severity,
                        existing["rule_id"]
                    )
                )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()



def get_enabled_rule_ids(rules, connection=None):
    """Return logical IDs of currently enabled detection rules."""

    owns_connection = connection is None

    if owns_connection:
        connection = get_connection()

    try:
        enabled_rule_ids = set()

        for rule in rules:
            row = connection.execute(
                """
                SELECT rule_id
                FROM detection_rules
                WHERE name = ?
                AND is_enabled = 1
                """,
                (rule.name,)
            ).fetchone()

            if row is not None:
                enabled_rule_ids.add(rule.rule_id)

        return enabled_rule_ids

    finally:
        if owns_connection:
            connection.close()


def get_detection_rules():
    """Return all registered detection rules."""

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                rule_id AS id,
                name,
                description,
                category,
                default_severity AS severity,
                is_enabled,
                created_at
            FROM detection_rules
            ORDER BY rule_id
            """
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def toggle_detection_rule(rule_id):
    """Toggle the enabled state of a detection rule."""

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            UPDATE detection_rules
            SET is_enabled = 1 - is_enabled
            WHERE rule_id = ?
            """,
            (rule_id,)
        )

        if cursor.rowcount == 0:
            raise ValueError("Detection rule not found.")

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()



# ============================================================
# DATASET PROCESSING
# ============================================================



def get_detection_rule_database_ids(rules):
    """Resolve database IDs for registered detection rules."""

    connection = get_connection()

    try:
        rule_database_ids = {}

        for rule in rules:
            row = connection.execute(
                """
                SELECT rule_id
                FROM detection_rules
                WHERE name = ?
                """,
                (rule.name,)
            ).fetchone()

            if row is None:
                raise ValueError(
                    f"Detection rule is not registered: {rule.name}"
                )

            rule_database_ids[rule.rule_id] = row["rule_id"]

        return rule_database_ids

    finally:
        connection.close()



# ============================================================
# INCIDENT STORAGE
# ============================================================


def save_detection_results(
    incidents,
    records,
    rules,
    rule_database_ids=None,
    connection=None
): # save detected incidents and their matched rules

    owns_connection = connection is None

    if owns_connection:
        connection = get_connection()

    inserted_incidents = 0

    try:
        connection.execute("BEGIN IMMEDIATE")

        # resolve database rule IDs if no mapping was happened 
        if rule_database_ids is None:
            rule_database_ids = {}

            for rule in rules:
                row = connection.execute(
                    """
                    SELECT rule_id
                    FROM detection_rules
                    WHERE name = ?
                    """,
                    (rule.name,)
                ).fetchone()

                if row is None:
                    raise ValueError(
                        f"Detection rule is not registered: {rule.rule_id}"
                    )

                rule_database_ids[rule.rule_id] = row["rule_id"]

        # validate the mapping
        missing_rule_ids = [
            rule.rule_id
            for rule in rules
            if rule.rule_id not in rule_database_ids
        ]

        if missing_rule_ids:
            raise ValueError(
                "Missing database IDs for detection rules: "
                + ", ".join(sorted(missing_rule_ids))
            )

        for _, incident in incidents.iterrows():

            source_record_id = int(
                incident["source_record_id"]
            )

            category = incident["category"]
            severity = incident["severity"]

            matched_rule_ids = set(
                incident["matched_rule_ids"]
            )

            if category not in VALID_CATEGORIES:
                raise ValueError(
                    f"Invalid incident category: {category}"
                )

            expected_severity = CATEGORY_INITIAL_SEVERITY[category]

            if severity != expected_severity:
                raise ValueError(
                    f"Category '{category}' requires initial severity "
                    f"'{expected_severity}', not '{severity}'."
                )

            unknown_rule_ids = (
                matched_rule_ids - set(rule_database_ids)
            )

            if unknown_rule_ids:
                raise ValueError(
                    "Unknown matched detection rules: "
                    + ", ".join(sorted(unknown_rule_ids))
                )

            matched_rules = [
                rule
                for rule in rules
                if rule.rule_id in matched_rule_ids
            ]
            
            # Recheck rule states inside the write transaction.
            # This prevents disabled rules from creating new incidents.
            active_matched_rules = []
            
            for rule in matched_rules:
                database_rule_id = rule_database_ids[rule.rule_id]
                
                rule_state = connection.execute(
                    """
                    SELECT is_enabled
                    FROM detection_rules
                    WHERE rule_id = ?
                    """,
                    (database_rule_id,)
                    ).fetchone()
                
                if rule_state is not None and rule_state["is_enabled"] == 1:
                    active_matched_rules.append(rule)
                    
                    # If all matched rules were disabled, do not create an incident.
            if not active_matched_rules:
                continue
            
            matched_rules = active_matched_rules
            
            # Recalculate category and severity using only currently enabled rules.
            severity_priority = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
            }

            highest_priority_rule = max(
            matched_rules,
            key=lambda rule: severity_priority[rule.severity]
            )

            category = highest_priority_rule.category
            severity = highest_priority_rule.severity

            if not matched_rules:
                raise ValueError(
                    f"Incident for source record {source_record_id} "
                    "has no matched detection rules."
                )

            # Check whether this source record already has an incident.
            existing_incident = connection.execute(
                """
                SELECT incident_id
                FROM incidents
                WHERE source_record_id = ?
                """,
                (source_record_id,)
            ).fetchone()

            # Preserve existing incidents and their history.
            if existing_incident is not None:
                continue

            if source_record_id not in records.index:
                raise ValueError(
                    f"Source record {source_record_id} "
                    "does not exist in the supplied batch."
                )

            # Build the incident description from matched rules.
            description = "; ".join(
                rule.description or ""
                for rule in matched_rules
            )

            # insert one incident
            cursor = connection.execute(
                """
                INSERT INTO incidents (
                    source_record_id,
                    category,
                    severity,
                    status,
                    description
                )
                VALUES (?, ?, ?, 'New', ?)
                """,
                (
                    source_record_id,
                    category,
                    severity,
                    description
                )
            )

            incident_id = cursor.lastrowid
            inserted_incidents += 1

            for rule in matched_rules:
                connection.execute(
                    """
                    INSERT INTO incident_rules (
                        incident_id,
                        rule_id
                    )
                    VALUES (?, ?)
                    """,
                    (
                        incident_id,
                        rule_database_ids[rule.rule_id]
                    )
                )

        connection.commit()
        return inserted_incidents

    except Exception:
        connection.rollback()
        raise

    finally:
        if owns_connection:
            connection.close()


def get_incidents_page(
    search=None,
    severity=None,
    status=None,
    limit=20,
    offset=0
):
    """Return one page of incidents and the total number of matching records."""

    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))

    connection = get_connection()

    try:
        where_clause = "WHERE 1 = 1"
        parameters = []

        if search and search.strip():
            pattern = f"%{search.strip()}%"
            where_clause += """
                AND (
                    CAST(incidents.incident_id AS TEXT) LIKE ?
                    OR incidents.category LIKE ?
                    OR incidents.description LIKE ?
                    OR CAST(incidents.source_record_id AS TEXT) LIKE ?
                )
            """
            parameters.extend([pattern] * 4)

        if severity in VALID_SEVERITIES:
            where_clause += " AND incidents.severity = ?"
            parameters.append(severity)

        if status in VALID_STATUSES:
            where_clause += " AND incidents.status = ?"
            parameters.append(status)

        total = connection.execute(
            f"""
                SELECT COUNT(*)
                FROM incidents
                {where_clause}
            """,
            parameters
        ).fetchone()[0]

        query = f"""
            SELECT
                incidents.incident_id AS id,
                incidents.source_record_id,
                incidents.category,
                incidents.severity,
                incidents.status,
                incidents.description,
                incidents.created_at AS detected_at,
                (
                    SELECT incident_comments.comment_text
                    FROM incident_comments
                    WHERE incident_comments.incident_id =
                        incidents.incident_id
                    ORDER BY incident_comments.comment_id DESC
                    LIMIT 1
                ) AS latest_comment
            FROM incidents
            {where_clause}
            ORDER BY incidents.created_at DESC,
                    incidents.incident_id DESC
            LIMIT ? OFFSET ?
        """

        query_parameters = parameters + [limit, offset]

        rows = connection.execute(
            query,
            query_parameters
        ).fetchall()

        return {
            "incidents": [dict(row) for row in rows],
            "total": total
        }

    finally:
        connection.close()


def get_incidents(
    search=None,
    severity=None,
    status=None,
    limit=500
):
    """Return incidents with their most recent comment."""

    limit = max(1, min(int(limit), 5000))
    connection = get_connection()

    try:
        query = """
            SELECT
                incidents.incident_id AS id,
                incidents.source_record_id,
                incidents.category,
                incidents.severity,
                incidents.status,
                incidents.description,
                incidents.created_at AS detected_at,
                (
                    SELECT incident_comments.comment_text
                    FROM incident_comments
                    WHERE incident_comments.incident_id =
                        incidents.incident_id
                    ORDER BY incident_comments.comment_id DESC
                    LIMIT 1
                ) AS latest_comment
            FROM incidents
            WHERE 1 = 1
        """

        parameters = []

        if search:
            pattern = f"%{search.strip()}%"
            query += """
                AND (
                    CAST(incidents.incident_id AS TEXT) LIKE ?
                    OR incidents.category LIKE ?
                    OR incidents.description LIKE ?
                    OR CAST(incidents.source_record_id AS TEXT) LIKE ?
                )
            """
            parameters.extend([pattern] * 4)

        if severity in VALID_SEVERITIES:
            query += " AND incidents.severity = ?"
            parameters.append(severity)

        if status in VALID_STATUSES:
            query += " AND incidents.status = ?"
            parameters.append(status)

        query += """
            ORDER BY incidents.created_at DESC,
                    incidents.incident_id DESC
            LIMIT ?
        """

        parameters.append(limit)

        rows = connection.execute(query, parameters).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_latest_incident_id():
    """Return the highest incident ID currently stored, or zero."""

    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT COALESCE(MAX(incident_id), 0) AS latest_id
            FROM incidents
            """
        ).fetchone()

        return int(row["latest_id"])

    finally:
        connection.close()



def get_incidents_after_id(
    after_id,
    search=None,
    severity=None,
    limit=500
):
    """Return newly created incidents after an ID, in ascending order."""

    after_id = max(0, int(after_id))
    limit = max(1, min(int(limit), 500))

    connection = get_connection()

    try:
        query = """
            SELECT
                incidents.incident_id AS id,
                incidents.source_record_id,
                incidents.category,
                incidents.severity,
                incidents.status,
                incidents.description,
                incidents.created_at AS detected_at,
                (
                    SELECT incident_comments.comment_text
                    FROM incident_comments
                    WHERE incident_comments.incident_id =
                        incidents.incident_id
                    ORDER BY incident_comments.comment_id DESC
                    LIMIT 1
                ) AS latest_comment
            FROM incidents
            WHERE incidents.incident_id > ?
        """

        parameters = [after_id]

        if search:
            pattern = f"%{search.strip()}%"
            query += """
                AND (
                    CAST(incidents.incident_id AS TEXT) LIKE ?
                    OR incidents.category LIKE ?
                    OR incidents.description LIKE ?
                    OR CAST(incidents.source_record_id AS TEXT) LIKE ?
                )
            """
            parameters.extend([pattern] * 4)

        if severity in VALID_SEVERITIES:
            query += " AND incidents.severity = ?"
            parameters.append(severity)

        query += """
            ORDER BY incidents.incident_id ASC
            LIMIT ?
        """

        parameters.append(limit)

        rows = connection.execute(query, parameters).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()



def get_incident_detail(incident_id):
    """Return incident details, matched rules and comments."""

    connection = get_connection()

    try:
        incident = connection.execute(
            """
            SELECT
                incident_id AS id,
                source_record_id,
                category,
                severity,
                status,
                description,
                created_at AS detected_at,
                created_at
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,)
        ).fetchone()

        if incident is None:
            return None

        rules = connection.execute(
            """
            SELECT
                detection_rules.rule_id,
                detection_rules.name,
                detection_rules.description,
                detection_rules.category,
                detection_rules.default_severity AS severity
            FROM incident_rules
            JOIN detection_rules
                ON detection_rules.rule_id = incident_rules.rule_id
            WHERE incident_rules.incident_id = ?
            ORDER BY detection_rules.rule_id
            """,
            (incident_id,)
        ).fetchall()

        comments = connection.execute(
            """
            SELECT
                incident_comments.comment_id AS id,
                incident_comments.comment_text AS comment,
                incident_comments.created_at,
                users.username,
                users.role
            FROM incident_comments
            JOIN users
                ON users.user_id = incident_comments.user_id
            WHERE incident_comments.incident_id = ?
            ORDER BY incident_comments.comment_id ASC
            """,
            (incident_id,)
        ).fetchall()

        return {
            "incident": dict(incident),
            "rules": [dict(row) for row in rules],
            "comments": [dict(row) for row in comments]
        }

    finally:
        connection.close()



def update_incident_status(incident_id, status):
    """
    Update incident status according to the defined lifecycle.

    Allowed transitions:
    New -> In Progress -> Resolved -> Closed

    Skipping stages and moving backwards are not allowed.
    """

    allowed_transitions = {
        "New": "In Progress",
        "In Progress": "Resolved",
        "Resolved": "Closed"
    }

    if status not in VALID_STATUSES:
        raise ValueError("Invalid incident status.")

    connection = get_connection()

    try:
        # Prevent concurrent status updates from bypassing the lifecycle validation.
        connection.execute("BEGIN IMMEDIATE")

        incident = connection.execute(
            """
            SELECT status
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,)
        ).fetchone()

        if incident is None:
            raise ValueError("Incident not found.")

        current_status = incident["status"]
        expected_next_status = allowed_transitions.get(current_status)

        if expected_next_status is None:
            raise ValueError(
                "The incident is already Closed and cannot be changed."
            )

        if status != expected_next_status:
            raise ValueError(
                f"Invalid status transition: "
                f"{current_status} -> {status}. "
                f"The next allowed status is "
                f"{expected_next_status}."
            )

        connection.execute(
            """
            UPDATE incidents
            SET status = ?
            WHERE incident_id = ?
            """,
            (status, incident_id)
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()



def update_incident_severity(incident_id, severity):
    """Update incident severity."""

    if severity not in VALID_SEVERITIES:
        raise ValueError("Invalid incident severity.")

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            UPDATE incidents
            SET severity = ?
            WHERE incident_id = ?
            """,
            (severity, incident_id)
        )

        if cursor.rowcount == 0:
            raise ValueError("Incident not found.")

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()



def add_incident_comment(incident_id, user_id, comment):
    """Add a comment to an incident."""

    comment = comment.strip()

    if not comment:
        raise ValueError("Comment cannot be empty.")

    connection = get_connection()

    try:
        incident = connection.execute(
            """
            SELECT incident_id
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,)
        ).fetchone()

        if incident is None:
            raise ValueError("Incident not found.")

        user = connection.execute(
            """
            SELECT user_id
            FROM users
            WHERE user_id = ?
            AND is_active = 1
            """,
            (user_id,)
        ).fetchone()

        if user is None:
            raise ValueError("Active user not found.")

        connection.execute(
            """
            INSERT INTO incident_comments (
                incident_id,
                user_id,
                comment_text
            )
            VALUES (?, ?, ?)
            """,
            (incident_id, user_id, comment)
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# ============================================================
# DASHBOARD STATISTICS
# ============================================================


def get_dashboard_statistics():
    """Return incident statistics for the dashboard."""

    connection = get_connection()

    try:
        incident_counts = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'New' THEN 1 ELSE 0 END)
                    AS new,
                SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END)
                    AS in_progress,
                SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END)
                    AS resolved,
                SUM(CASE WHEN status = 'Closed' THEN 1 ELSE 0 END)
                    AS closed,
                SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END)
                    AS critical,
                SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END)
                    AS high,
                SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END)
                    AS medium,
                SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END)
                    AS low
            FROM incidents
            """
        ).fetchone()

        return {
            "incidents": {
                key: incident_counts[key] or 0
                for key in incident_counts.keys()
            }
        }

    finally:
        connection.close()