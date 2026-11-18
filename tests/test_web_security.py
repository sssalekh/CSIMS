import tempfile
import unittest
import re
from pathlib import Path
from unittest.mock import patch

from app import app
import storage.db as database


class TestWebSecurity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()

        cls.database_path_patch = patch.object(
            database,
            "DATABASE_PATH",
            Path(cls.temp_dir.name) / "test_csims.db"
        )
        cls.database_path_patch.start()

        database.initialize_database()

    @classmethod
    def tearDownClass(cls):
        cls.database_path_patch.stop()
        cls.temp_dir.cleanup()

    def setUp(self):
        self.version_patch = patch(
            "flask.testing._get_werkzeug_version",
            return_value="3.1.9"
        )
        self.version_patch.start()
        self.addCleanup(self.version_patch.stop)

        app.config["TESTING"] = True
        self.client = app.test_client()

        # Create real users in the temporary test database.
        self.analyst_id = database.create_user(
            username=f"analyst_{id(self)}",
            password="TestPassword123!",
            role="Security Analyst"
        )

        self.admin_id = database.create_user(
            username=f"admin_{id(self)}",
            password="TestPassword123!",
            role="Administrator"
        )

        # A second administrator allows role-demotion tests
        # without violating the last-administrator protection.
        self.second_admin_id = database.create_user(
            username=f"admin2_{id(self)}",
            password="TestPassword123!",
            role="Administrator"
        )

        # These tests check access control, not temporary passwords, so the
        # users are treated as having already chosen personal passwords.
        connection = database.get_connection()
        try:
            connection.execute(
                "UPDATE users SET must_change_password = 0"
            )
            connection.commit()
        finally:
            connection.close()

    def set_session(self, user_id, role):
        with self.client.session_transaction() as session:
            session["user_id"] = user_id
            session["user"] = "test_user"
            session["role"] = role
    
    def get_csrf_token(self):
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)

        html = response.get_data(as_text=True)

        match = re.search(
            r'name="csrf_token"\s+value="([^"]+)"',
            html
        )

        self.assertIsNotNone(
            match,
            "CSRF token was not found in the page."
        )

        return match.group(1)

    def test_login_page_is_accessible_without_authentication(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)

    def test_dashboard_redirects_unauthenticated_user(self):
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/", response.headers["Location"])

    def test_admin_panel_redirects_unauthenticated_user(self):
        response = self.client.get("/admin")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/", response.headers["Location"])

    def test_security_analyst_cannot_access_admin_panel(self):
        self.set_session(
            user_id=self.analyst_id,
            role="Security Analyst"
        )

        response = self.client.get("/admin")

        self.assertEqual(response.status_code, 403)

    def test_administrator_can_pass_admin_access_check(self):
        self.set_session(
            user_id=self.admin_id,
            role="Administrator"
        )

        response = self.client.get("/admin")

        self.assertNotEqual(response.status_code, 403)
        self.assertNotEqual(response.status_code, 302)

    def test_role_change_is_reflected_in_existing_session(self):
        self.set_session(
            user_id=self.analyst_id,
            role="Security Analyst"
        )

        # Promote the user in the database.
        database.set_user_role(
            self.analyst_id,
            "Administrator"
        )

        response = self.client.get("/admin")

        self.assertNotEqual(response.status_code, 403)
        self.assertNotEqual(response.status_code, 302)

        with self.client.session_transaction() as session:
            self.assertEqual(session["role"], "Administrator")

    def test_role_demotion_is_reflected_in_existing_session(self):
        self.set_session(
            user_id=self.admin_id,
            role="Administrator"
        )

        # Demote the user while another active administrator exists.
        database.set_user_role(
            self.admin_id,
            "Security Analyst"
        )

        response = self.client.get("/admin")

        self.assertEqual(response.status_code, 403)

        with self.client.session_transaction() as session:
            self.assertEqual(session["role"], "Security Analyst")

    def test_deactivated_user_cannot_use_existing_session(self):
        self.set_session(
            user_id=self.analyst_id,
            role="Security Analyst"
        )

        database.set_user_active(
            self.analyst_id,
            False
        )

        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 302)

        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)
            self.assertNotIn("role", session)

    
    def test_logout_uses_post_method(self):
        rules = [
            rule
            for rule in app.url_map.iter_rules()
            if rule.endpoint == "logout"
        ]

        self.assertEqual(len(rules), 1)
        self.assertIn("POST", rules[0].methods)
        self.assertNotIn("GET", rules[0].methods)
        
    
    def test_post_request_without_csrf_token_is_rejected(self):
        self.set_session(
            user_id=self.analyst_id,
            role="Security Analyst"
        )

        response = self.client.post("/logout")

        self.assertEqual(response.status_code, 400)

    def test_post_request_with_valid_csrf_token_is_accepted(self):
        self.set_session(
            user_id=self.analyst_id,
            role="Security Analyst"
        )

        csrf_token = self.get_csrf_token()

        response = self.client.post(
            "/logout",
            data={"csrf_token": csrf_token}
        )

        self.assertEqual(response.status_code, 302)

    def test_logout_clears_authenticated_session(self):
        self.set_session(
            user_id=self.analyst_id,
            role="Security Analyst"
        )

        csrf_token = self.get_csrf_token()

        response = self.client.post(
            "/logout",
            data={"csrf_token": csrf_token}
        )

        self.assertEqual(response.status_code, 302)

        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)
            self.assertNotIn("role", session)


if __name__ == "__main__":
    unittest.main()
