"""Tests for the dashboard overview and the incidents page."""

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app
import storage.db as database


class TestDashboardPages(unittest.TestCase):

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
            username="admin", password="TestPassword123!"
        )

        rows = [
            (1, "Exploitation", "Critical", "New"),
            (2, "Reconnaissance", "Low", "In Progress"),
            (3, "Dos / DDoS", "High", "Resolved"),
            (4, "Other suspicious activity", "Medium", "Closed"),
            (5, "Exploitation", "Critical", "New"),
        ]
        connection = database.get_connection()
        connection.executemany(
            "INSERT INTO incidents "
            "(source_record_id, category, severity, status, description) "
            "VALUES (?, ?, ?, ?, 'test incident')",
            rows
        )
        connection.commit()
        connection.close()

        app.config["TESTING"] = True
        self.client = app.test_client()

        with self.client.session_transaction() as session:
            session["user_id"] = self.admin_id
            session["user"] = "admin"
            session["role"] = "Administrator"

    def page(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def incident_ids(self, html):
        return {
            int(value)
            for value in re.findall(r'data-incident-id="(\d+)"', html)
        }

    # ---------- statistics ----------

    def test_statistics_include_status_and_category_counts(self):
        stats = database.get_dashboard_statistics()["incidents"]

        self.assertEqual(stats["total"], 5)
        self.assertEqual(stats["new"], 2)
        self.assertEqual(stats["in_progress"], 1)
        self.assertEqual(stats["resolved"], 1)
        self.assertEqual(stats["closed"], 1)
        self.assertEqual(stats["category_exploitation"], 2)
        self.assertEqual(stats["category_reconnaissance"], 1)
        self.assertEqual(stats["category_dos"], 1)
        self.assertEqual(stats["category_other"], 1)

    # ---------- dashboard ----------

    def test_dashboard_shows_overview_and_recent_incidents(self):
        html = self.page("/dashboard")

        self.assertIn("Incidents by Status", html)
        self.assertIn("Incidents by Category", html)
        self.assertIn("Recent Incidents", html)
        self.assertEqual(self.incident_ids(html), {1, 2, 3, 4, 5})

    def test_dashboard_shows_at_most_ten_recent_incidents(self):
        connection = database.get_connection()
        connection.executemany(
            "INSERT INTO incidents (source_record_id, category, severity) "
            "VALUES (?, 'Reconnaissance', 'Low')",
            [(number,) for number in range(100, 120)]
        )
        connection.commit()
        connection.close()

        html = self.page("/dashboard")

        self.assertEqual(len(self.incident_ids(html)), 10)

    # ---------- incidents page ----------

    def test_incidents_page_lists_all_incidents(self):
        html = self.page("/incidents")

        self.assertIn("All Incidents", html)
        self.assertEqual(self.incident_ids(html), {1, 2, 3, 4, 5})

    def test_incidents_page_filters_by_status(self):
        html = self.page("/incidents?status=New")

        self.assertEqual(self.incident_ids(html), {1, 5})

    def test_incidents_page_filters_by_category(self):
        html = self.page("/incidents?category=Dos+%2F+DDoS")

        self.assertEqual(self.incident_ids(html), {3})

    def test_incidents_page_combines_filters(self):
        html = self.page("/incidents?severity=Critical&status=New")

        self.assertEqual(self.incident_ids(html), {1, 5})

    def test_invalid_filter_values_are_ignored(self):
        html = self.page("/incidents?status=Unknown&category=Nothing")

        self.assertEqual(self.incident_ids(html), {1, 2, 3, 4, 5})

    def test_live_updates_respect_status_filter(self):
        response = self.client.get(
            "/api/dashboard-updates?after_id=0&status=Closed"
        )
        data = response.get_json()

        self.assertEqual([item["id"] for item in data["incidents"]], [4])
        self.assertEqual(data["statistics"]["total"], 5)

    def test_incidents_page_requires_login(self):
        with self.client.session_transaction() as session:
            session.clear()

        response = self.client.get("/incidents")

        self.assertEqual(response.status_code, 302)


if __name__ == "__main__":
    unittest.main()
