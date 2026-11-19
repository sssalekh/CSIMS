"""Tests for rule codes in the interface and safe error messages."""

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as app_module
from app import app
import storage.db as database
from detection.config import DETECTION_THRESHOLDS
from detection.rules import build_detection_rules


class TestInterfaceDetails(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        database_path_patch = patch.object(
            database,
            "DATABASE_PATH",
            Path(self.temp_dir.name) / "test_csims.db"
        )
        database_path_patch.start()
        self.addCleanup(database_path_patch.stop)

        version_patch = patch(
            "flask.testing._get_werkzeug_version",
            return_value="3.1.9"
        )
        version_patch.start()
        self.addCleanup(version_patch.stop)

        database.initialize_database()
        database.register_detection_rules(
            build_detection_rules(DETECTION_THRESHOLDS)
        )
        self.admin_id = database.create_initial_administrator(
            username="admin", password="TestPassword123!"
        )

        app.config["TESTING"] = True
        self.client = app.test_client()

        with self.client.session_transaction() as session:
            session["user_id"] = self.admin_id
            session["user"] = "admin"
            session["role"] = "Administrator"

    def test_rules_page_shows_logical_rule_codes(self):
        html = self.client.get("/rules").get_data(as_text=True)

        for code in ("DOS-001", "REC-001", "EXP-001", "GEN-001", "CON-001"):
            self.assertIn(code, html)

    def test_incident_page_shows_rule_code(self):
        connection = database.get_connection()
        cursor = connection.execute(
            "INSERT INTO incidents (source_record_id, category, severity) "
            "VALUES (1, 'Exploitation', 'Critical')"
        )
        incident_id = cursor.lastrowid
        rule_id = connection.execute(
            "SELECT rule_id FROM detection_rules WHERE name = ?",
            ("Abnormal TCP handshake delay",)
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO incident_rules (incident_id, rule_id) VALUES (?, ?)",
            (incident_id, rule_id)
        )
        connection.commit()
        connection.close()

        html = self.client.get(f"/incident/{incident_id}").get_data(
            as_text=True
        )

        self.assertIn("Rule: EXP-001", html)

    def test_unexpected_delete_error_is_not_shown_to_user(self):
        user_id = database.create_user(
            "analyst", "TestPassword123!", "Security Analyst"
        )
        html = self.client.get("/admin").get_data(as_text=True)
        token = re.search(
            r'name="csrf_token"\s+value="([^"]+)"', html
        ).group(1)

        with patch.object(
            app_module, "delete_user",
            side_effect=RuntimeError("sqlite3 internal detail")
        ), patch.object(app.logger, "exception"):
            response = self.client.post(
                f"/delete_user/{user_id}",
                data={"csrf_token": token},
                follow_redirects=True
            )

        page = response.get_data(as_text=True)
        self.assertIn("The user account could not be deleted.", page)
        self.assertNotIn("sqlite3 internal detail", page)


if __name__ == "__main__":
    unittest.main()
