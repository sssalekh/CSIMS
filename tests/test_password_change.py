"""Tests for temporary passwords and password changes."""

import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app
import storage.db as database


PASSWORD = "TestPassword123!"
NEW_PASSWORD = "PersonalPassword456!"


class TestPasswordChange(unittest.TestCase):

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

        self.admin_id = database.create_initial_administrator(
            username="admin",
            password=PASSWORD
        )
        self.analyst_id = database.create_user(
            username="analyst",
            password=PASSWORD,
            role="Security Analyst"
        )

        app.config["TESTING"] = True
        self.client = app.test_client()

    # ---------- helpers ----------

    def flag(self, user_id):
        connection = database.get_connection()
        try:
            return connection.execute(
                "SELECT must_change_password FROM users WHERE user_id = ?",
                (user_id,)
            ).fetchone()[0]
        finally:
            connection.close()

    def csrf_token(self, path):
        html = self.client.get(path).get_data(as_text=True)
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        self.assertIsNotNone(match)
        return match.group(1)

    def log_in(self, username, password):
        token = self.csrf_token("/")
        return self.client.post("/", data={
            "csrf_token": token,
            "username": username,
            "password": password,
        })

    # ---------- database layer ----------

    def test_created_user_must_change_password(self):
        self.assertEqual(self.flag(self.analyst_id), 1)

    def test_initial_administrator_does_not_need_to_change_password(self):
        self.assertEqual(self.flag(self.admin_id), 0)

    def test_change_password_clears_flag_and_replaces_password(self):
        database.change_password(self.analyst_id, PASSWORD, NEW_PASSWORD)

        self.assertEqual(self.flag(self.analyst_id), 0)
        self.assertIsNone(database.authenticate_user("analyst", PASSWORD))
        self.assertIsNotNone(
            database.authenticate_user("analyst", NEW_PASSWORD)
        )

    def test_change_password_rejects_wrong_current_password(self):
        with self.assertRaises(ValueError):
            database.change_password(
                self.analyst_id, "WrongPassword!", NEW_PASSWORD
            )

    def test_change_password_rejects_short_or_same_password(self):
        with self.assertRaises(ValueError):
            database.change_password(self.analyst_id, PASSWORD, "short")
        with self.assertRaises(ValueError):
            database.change_password(self.analyst_id, PASSWORD, PASSWORD)

    def test_reset_password_sets_temporary_password(self):
        database.change_password(self.analyst_id, PASSWORD, NEW_PASSWORD)
        database.reset_user_password(self.analyst_id, "Temporary789!")

        self.assertEqual(self.flag(self.analyst_id), 1)
        self.assertIsNotNone(
            database.authenticate_user("analyst", "Temporary789!")
        )

    def test_password_hash_is_not_plaintext(self):
        database.change_password(self.analyst_id, PASSWORD, NEW_PASSWORD)
        connection = database.get_connection()
        try:
            stored = connection.execute(
                "SELECT password_hash FROM users WHERE user_id = ?",
                (self.analyst_id,)
            ).fetchone()[0]
        finally:
            connection.close()

        self.assertNotEqual(stored, NEW_PASSWORD)

    def test_migration_adds_column_to_existing_database(self):
        old_path = Path(self.temp_dir.name) / "old.db"
        connection = sqlite3.connect(old_path)
        connection.execute(
            """
            CREATE TABLE users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.commit()
        connection.close()

        with patch.object(database, "DATABASE_PATH", old_path):
            database.initialize_database()
            connection = database.get_connection()
            try:
                columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(users)")
                }
            finally:
                connection.close()

        self.assertIn("must_change_password", columns)

    # ---------- web layer ----------

    def test_user_with_temporary_password_is_sent_to_change_page(self):
        response = self.log_in("analyst", PASSWORD)
        self.assertEqual(response.status_code, 302)

        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response.headers["Location"].endswith("/change_password")
        )

    def test_user_can_continue_after_changing_password(self):
        self.log_in("analyst", PASSWORD)
        token = self.csrf_token("/change_password")

        response = self.client.post("/change_password", data={
            "csrf_token": token,
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
        })
        self.assertEqual(response.status_code, 302)

        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_mismatched_confirmation_is_rejected(self):
        self.log_in("analyst", PASSWORD)
        token = self.csrf_token("/change_password")

        self.client.post("/change_password", data={
            "csrf_token": token,
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirm_password": "Different123!",
        })

        self.assertEqual(self.flag(self.analyst_id), 1)

    def test_user_with_temporary_password_can_log_out(self):
        self.log_in("analyst", PASSWORD)
        token = self.csrf_token("/change_password")

        response = self.client.post("/logout", data={"csrf_token": token})
        self.assertEqual(response.status_code, 302)

        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_administrator_can_reset_password(self):
        database.change_password(self.analyst_id, PASSWORD, NEW_PASSWORD)
        self.log_in("admin", PASSWORD)
        token = self.csrf_token("/admin")

        self.client.post(
            f"/reset_user_password/{self.analyst_id}",
            data={
                "csrf_token": token,
                "temporary_password": "Temporary789!",
            }
        )

        self.assertEqual(self.flag(self.analyst_id), 1)

    def test_analyst_cannot_reset_password(self):
        database.change_password(self.analyst_id, PASSWORD, NEW_PASSWORD)
        self.log_in("analyst", NEW_PASSWORD)
        token = self.csrf_token("/dashboard")

        response = self.client.post(
            f"/reset_user_password/{self.admin_id}",
            data={
                "csrf_token": token,
                "temporary_password": "Temporary789!",
            }
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.flag(self.admin_id), 0)


if __name__ == "__main__":
    unittest.main()
