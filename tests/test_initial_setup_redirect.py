"""Tests for redirection between the login and initial setup pages."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app
import storage.db as database


class TestInitialSetupRedirect(unittest.TestCase):

    def setUp(self):
        # Every test starts with a new, empty database.
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

        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_login_redirects_to_setup_without_administrator(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/setup"))

    def test_protected_page_leads_to_setup_without_administrator(self):
        response = self.client.get("/dashboard", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request.path, "/setup")

    def test_setup_page_is_shown_without_administrator(self):
        response = self.client.get("/setup")

        self.assertEqual(response.status_code, 200)

    def test_login_page_is_shown_after_administrator_exists(self):
        database.create_initial_administrator(
            username="first_admin",
            password="TestPassword123!"
        )

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)

    def test_setup_redirects_to_login_after_administrator_exists(self):
        database.create_initial_administrator(
            username="first_admin",
            password="TestPassword123!"
        )

        response = self.client.get("/setup")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/"))


if __name__ == "__main__":
    unittest.main()
