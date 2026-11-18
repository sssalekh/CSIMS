"""Tests for limiting failed login attempts."""

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as app_module
from app import app
import storage.db as database


PASSWORD = "TestPassword123!"


class TestLoginLockout(unittest.TestCase):

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

        # A controllable clock for the lockout period.
        self.now = 1000.0
        clock_patch = patch.object(
            app_module.time, "monotonic", side_effect=lambda: self.now
        )
        clock_patch.start()
        self.addCleanup(clock_patch.stop)

        app_module.failed_logins.clear()
        self.addCleanup(app_module.failed_logins.clear)

        database.initialize_database()
        self.admin_id = database.create_initial_administrator(
            username="admin",
            password=PASSWORD
        )

        app.config["TESTING"] = True
        self.client = app.test_client()

    def log_in(self, username, password):
        html = self.client.get("/").get_data(as_text=True)
        token = re.search(
            r'name="csrf_token"\s+value="([^"]+)"', html
        ).group(1)

        return self.client.post("/", data={
            "csrf_token": token,
            "username": username,
            "password": password,
        })

    def fail(self, times, username="admin"):
        for _ in range(times):
            self.log_in(username, "WrongPassword!")

    def test_four_failures_do_not_lock_the_account(self):
        self.fail(4)

        response = self.log_in("admin", PASSWORD)

        self.assertEqual(response.status_code, 302)

    def test_fifth_failure_locks_the_account(self):
        self.fail(4)
        response = self.log_in("admin", "WrongPassword!")

        self.assertEqual(response.status_code, 429)
        self.assertIn(
            "Too many failed login attempts",
            response.get_data(as_text=True)
        )

    def test_correct_password_is_refused_while_locked(self):
        self.fail(5)

        response = self.log_in("admin", PASSWORD)

        self.assertEqual(response.status_code, 429)
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_login_is_possible_after_lockout_period(self):
        self.fail(5)
        self.now += app_module.LOGIN_LOCKOUT_SECONDS + 1

        response = self.log_in("admin", PASSWORD)

        self.assertEqual(response.status_code, 302)

    def test_successful_login_resets_the_counter(self):
        self.fail(4)
        self.log_in("admin", PASSWORD)
        with self.client.session_transaction() as session:
            session.clear()

        self.fail(4)
        response = self.log_in("admin", PASSWORD)

        self.assertEqual(response.status_code, 302)

    def test_old_failures_are_forgotten(self):
        self.fail(4)
        self.now += app_module.LOGIN_LOCKOUT_SECONDS + 1
        self.fail(1)

        response = self.log_in("admin", PASSWORD)

        self.assertEqual(response.status_code, 302)

    def test_lockout_applies_only_to_that_username(self):
        database.create_user("analyst", PASSWORD, "Security Analyst")
        self.fail(5, username="admin")

        response = self.log_in("analyst", PASSWORD)

        self.assertEqual(response.status_code, 302)

    def test_unknown_username_gets_the_same_lockout(self):
        self.fail(5, username="nobody")

        response = self.log_in("nobody", "WrongPassword!")

        self.assertEqual(response.status_code, 429)

    def test_password_reset_removes_lockout(self):
        analyst_id = database.create_user(
            "analyst", PASSWORD, "Security Analyst"
        )
        self.fail(5, username="analyst")

        with self.client.session_transaction() as session:
            session["user_id"] = self.admin_id
            session["user"] = "admin"
            session["role"] = "Administrator"

        html = self.client.get("/admin").get_data(as_text=True)
        token = re.search(
            r'name="csrf_token"\s+value="([^"]+)"', html
        ).group(1)
        self.client.post(
            f"/reset_user_password/{analyst_id}",
            data={"csrf_token": token, "temporary_password": "Temporary789!"}
        )

        with self.client.session_transaction() as session:
            session.clear()

        response = self.log_in("analyst", "Temporary789!")

        self.assertEqual(response.status_code, 302)


if __name__ == "__main__":
    unittest.main()
