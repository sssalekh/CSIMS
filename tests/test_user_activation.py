"""Tests for activating and deactivating user accounts."""

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app
import storage.db as database


PASSWORD = "TestPassword123!"


class TestUserActivation(unittest.TestCase):

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
            username="admin", password=PASSWORD
        )
        self.analyst_id = database.create_user(
            "analyst", PASSWORD, "Security Analyst"
        )

        app.config["TESTING"] = True
        self.client = app.test_client()

    def is_active(self, user_id):
        connection = database.get_connection()
        try:
            return connection.execute(
                "SELECT is_active FROM users WHERE user_id = ?",
                (user_id,)
            ).fetchone()[0]
        finally:
            connection.close()

    def act_as_admin(self):
        with self.client.session_transaction() as session:
            session["user_id"] = self.admin_id
            session["user"] = "admin"
            session["role"] = "Administrator"

        html = self.client.get("/admin").get_data(as_text=True)
        return re.search(
            r'name="csrf_token"\s+value="([^"]+)"', html
        ).group(1)

    # ---------- database layer ----------

    def test_deactivated_user_cannot_log_in(self):
        database.set_user_active(self.analyst_id, False)

        self.assertIsNone(database.authenticate_user("analyst", PASSWORD))

    def test_activated_user_can_log_in_again(self):
        database.set_user_active(self.analyst_id, False)
        database.set_user_active(self.analyst_id, True)

        self.assertIsNotNone(
            database.authenticate_user("analyst", PASSWORD)
        )

    def test_last_active_administrator_cannot_be_deactivated(self):
        with self.assertRaises(ValueError):
            database.set_user_active(self.admin_id, False)

        self.assertEqual(self.is_active(self.admin_id), 1)

    def test_deleted_account_cannot_be_activated(self):
        connection = database.get_connection()
        connection.execute(
            "INSERT INTO incidents (source_record_id, category, severity) "
            "VALUES (1, 'Reconnaissance', 'Low')"
        )
        connection.commit()
        connection.close()
        database.add_incident_comment(1, self.analyst_id, "note")
        self.assertEqual(database.delete_user(self.analyst_id), "anonymized")

        with self.assertRaises(ValueError):
            database.set_user_active(self.analyst_id, True)

        users = {user["id"]: user for user in database.get_users()}
        self.assertEqual(users[self.analyst_id]["is_deleted"], 1)
        self.assertEqual(users[self.admin_id]["is_deleted"], 0)

    # ---------- web layer ----------

    def test_administrator_can_deactivate_and_activate_user(self):
        token = self.act_as_admin()

        self.client.post(
            f"/set_user_active/{self.analyst_id}",
            data={"csrf_token": token, "active": "0"}
        )
        self.assertEqual(self.is_active(self.analyst_id), 0)

        self.client.post(
            f"/set_user_active/{self.analyst_id}",
            data={"csrf_token": token, "active": "1"}
        )
        self.assertEqual(self.is_active(self.analyst_id), 1)

    def test_administrator_cannot_deactivate_own_account(self):
        database.create_user("admin2", PASSWORD, "Administrator")
        token = self.act_as_admin()

        self.client.post(
            f"/set_user_active/{self.admin_id}",
            data={"csrf_token": token, "active": "0"}
        )

        self.assertEqual(self.is_active(self.admin_id), 1)

    def test_deactivated_user_is_signed_out(self):
        database.change_password(self.analyst_id, PASSWORD, "NewPassword456!")

        with self.client.session_transaction() as session:
            session["user_id"] = self.analyst_id
            session["user"] = "analyst"
            session["role"] = "Security Analyst"

        self.assertEqual(self.client.get("/dashboard").status_code, 200)

        database.set_user_active(self.analyst_id, False)

        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)

    def test_analyst_cannot_change_account_status(self):
        database.change_password(self.analyst_id, PASSWORD, "NewPassword456!")
        other_id = database.create_user("other", PASSWORD, "Security Analyst")

        with self.client.session_transaction() as session:
            session["user_id"] = self.analyst_id
            session["user"] = "analyst"
            session["role"] = "Security Analyst"

        html = self.client.get("/dashboard").get_data(as_text=True)
        token = re.search(
            r'name="csrf_token"\s+value="([^"]+)"', html
        ).group(1)

        response = self.client.post(
            f"/set_user_active/{other_id}",
            data={"csrf_token": token, "active": "0"}
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.is_active(other_id), 1)


if __name__ == "__main__":
    unittest.main()
