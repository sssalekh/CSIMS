
"""Database tests for the current five-entity CSIMS schema."""

import sqlite3
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

import pandas as pd

import storage.db as database
from detection.engine import DetectionRule


class TestDatabase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._temporary_directory = tempfile.TemporaryDirectory(
            prefix="csims_test_"
        )

        cls.test_database_path = (
            Path(cls._temporary_directory.name) / "csims_test.db"
        )

        cls._database_path_patch = patch.object(
            database,
            "DATABASE_PATH",
            cls.test_database_path
        )
        cls._database_path_patch.start()

        database.initialize_database()

    @classmethod
    def tearDownClass(cls):
        cls._database_path_patch.stop()
        cls._temporary_directory.cleanup()

    def setUp(self):
        self.connection = database.get_connection()

    def tearDown(self):
        self.connection.close()

    def create_user(self, username="test_user"):
        return database.create_user(
            username=username,
            password="TestPassword123!",
            role="Security Analyst"
        )

    def create_incident(self, source_record_id=1001):
        cursor = self.connection.execute(
            """
            INSERT INTO incidents (
                source_record_id,
                category,
                severity,
                status,
                description
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                source_record_id,
                "Reconnaissance",
                "Low",
                "New",
                "Test incident"
            )
        )
        self.connection.commit()
        return cursor.lastrowid

    def test_database_file_exists(self):
        self.assertTrue(self.test_database_path.exists())

    def test_only_five_erd_entities_exist(self):
        rows = self.connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()

        existing_tables = {row["name"] for row in rows}

        expected_tables = {
            "users",
            "incidents",
            "detection_rules",
            "incident_comments",
            "incident_rules",
        }

        self.assertEqual(existing_tables, expected_tables)

    def test_foreign_keys_are_enabled(self):
        result = self.connection.execute(
            "PRAGMA foreign_keys"
        ).fetchone()

        self.assertEqual(result[0], 1)

    def test_database_initialization_is_idempotent(self):
        self.create_user("idempotency_test_user")

        database.initialize_database()

        row = self.connection.execute(
            """
            SELECT username
            FROM users
            WHERE username = ?
            """,
            ("idempotency_test_user",)
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(
            row["username"],
            "idempotency_test_user"
        )

    def test_invalid_incident_severity_is_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO incidents (
                    source_record_id,
                    category,
                    severity
                )
                VALUES (?, ?, ?)
                """,
                (2001, "Reconnaissance", "Unknown")
            )

        self.connection.rollback()

    def test_invalid_user_role_is_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    role
                )
                VALUES (?, ?, ?)
                """,
                (
                    "invalid_role_user",
                    "test-hash",
                    "Superuser"
                )
            )

        self.connection.rollback()

    def test_source_record_id_must_be_unique(self):
        self.create_incident(3001)

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO incidents (
                    source_record_id,
                    category,
                    severity
                )
                VALUES (?, ?, ?)
                """,
                (3001, "Reconnaissance", "Low")
            )

        self.connection.rollback()

    def test_incident_rule_relationship_uses_composite_key(self):
        incident_id = self.create_incident(4001)

        self.connection.execute(
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
                "Test rule",
                "Rule for database testing",
                "Reconnaissance",
                "Low"
            )
        )
        self.connection.commit()

        rule = self.connection.execute(
            """
            SELECT rule_id
            FROM detection_rules
            WHERE name = ?
            """,
            ("Test rule",)
        ).fetchone()

        rule_id = rule["rule_id"]

        self.connection.execute(
            """
            INSERT INTO incident_rules (incident_id, rule_id)
            VALUES (?, ?)
            """,
            (incident_id, rule_id)
        )
        self.connection.commit()

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO incident_rules (incident_id, rule_id)
                VALUES (?, ?)
                """,
                (incident_id, rule_id)
            )

        self.connection.rollback()

    def test_comment_requires_existing_incident_and_user(self):
        incident_id = self.create_incident(5001)
        user_id = self.create_user("comment_test_user")

        database.add_incident_comment(
            incident_id,
            user_id,
            "Investigation started."
        )

        comment = self.connection.execute(
            """
            SELECT comment_text, user_id
            FROM incident_comments
            WHERE incident_id = ?
            """,
            (incident_id,)
        ).fetchone()

        self.assertIsNotNone(comment)
        self.assertEqual(
            comment["comment_text"],
            "Investigation started."
        )
        self.assertEqual(comment["user_id"], user_id)

    def test_incident_status_follows_defined_lifecycle(self):
        incident_id = self.create_incident(6001)

        database.update_incident_status(
            incident_id,
            "In Progress"
        )
        database.update_incident_status(
            incident_id,
            "Resolved"
        )
        database.update_incident_status(
            incident_id,
            "Closed"
        )

        status = self.connection.execute(
            """
            SELECT status
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,)
        ).fetchone()["status"]

        self.assertEqual(status, "Closed")

    def test_incident_status_cannot_skip_lifecycle_stages(self):
        incident_id = self.create_incident(6002)

        with self.assertRaises(ValueError):
            database.update_incident_status(
                incident_id,
                "Closed"
            )

        status = self.connection.execute(
            """
            SELECT status
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,)
        ).fetchone()["status"]

        self.assertEqual(status, "New")

    def test_disabled_rule_cannot_create_new_incident(self):
        """A disabled rule must not create an incident using stale results."""

        rule = DetectionRule(
            rule_id="TEST-DISABLED-001",
            name="Test disabled rule",
            description="Rule for disabled-rule testing.",
            severity="High",
            condition=lambda df: df["sbytes"] > 1000,
            required_features=("sbytes",),
            enabled=True,
            category="Dos / DDoS"
        )

        # Register the rule in the test database.
        database.register_detection_rules([rule])

        # Resolve its actual SQLite primary key.
        rule_database_ids = database.get_detection_rule_database_ids(
            [rule]
        )

        database_rule_id = rule_database_ids[rule.rule_id]

        # Disable the rule as an administrator would.
        database.toggle_detection_rule(database_rule_id)

        # The Detection Engine may still hold an old enabled=True object.
        # Simulate a result produced from that stale state.
        records = pd.DataFrame(
            {"sbytes": [5000]},
            index=[7001]
        )

        incidents = pd.DataFrame([
            {
                "source_record_id": 7001,
                "category": "Dos / DDoS",
                "severity": "High",
                "matched_rule_ids": [rule.rule_id]
            }
        ])

        inserted = database.save_detection_results(
            incidents=incidents,
            records=records,
            rules=[rule],
            rule_database_ids=rule_database_ids,
            connection=self.connection
        )

        # No incident should be created from the disabled rule.
        self.assertEqual(inserted, 0)

        saved_incident = self.connection.execute(
            """
            SELECT incident_id
            FROM incidents
            WHERE source_record_id = ?
            """,
            (7001,)
        ).fetchone()

        self.assertIsNone(saved_incident)


if __name__ == "__main__":
    unittest.main()
