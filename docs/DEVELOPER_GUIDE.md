# Developer Guide

## Architecture

The application is divided into the following layers:

- Flask web layer (`app.py`): routes, session authentication, role checks, dashboard update endpoint, and background processing startup.
- Dataset layer (`dataset/`): reads the UNSW-NB15 CSV data and passes feature records to the Detection Engine one record at a time.
- Detection layer (`detection/`): defines rule metadata and evaluates records without passing ground-truth label columns to the engine.
- Storage layer (`storage/`): persists users, dataset runs, detection rules, incidents, rule matches, comments, and evaluation data in SQLite.

## Detection flow

1. The dataset loader reads CSV input in chunks.
2. The processor evaluates each source record individually.
3. The Detection Engine applies enabled rules to the record's feature columns.
4. At most one incident is produced for a source record, with all matching rule identifiers retained.
5. A detected incident and its rule associations are committed to SQLite immediately.
6. The dashboard update endpoint exposes newly persisted incidents to an open browser session.

Dataset ground-truth fields are reserved for evaluation and must not be passed to the Detection Engine.

## Database

The authoritative schema is `storage/schema.sql`. `storage/db.py` initializes the schema and provides parameterized database operations. The distributable project includes a clean database; user accounts and incident data are created locally when the application is used.

## Security controls

- Passwords are stored using Werkzeug password hashing.
- User roles are checked before administrative routes are accessed.
- POST requests are protected by session-backed CSRF tokens.
- Session cookies are configured as HttpOnly and SameSite=Lax.
- The Secure cookie flag can be enabled with `CSIMS_HTTPS=1`.
- A persistent secret should be supplied through `CSIMS_SECRET_KEY`.
- Flask debug mode is disabled by default.

## Tests

Run:

```powershell
python -m unittest discover -s tests -v
```

The suite covers detection behavior, database integrity, duplicate prevention, incident lifecycle transitions, password-length validation, CSRF handling, and the logout HTTP method.

## Important implementation constraints

- Preserve sequential per-record detection and immediate persistence of detected incidents.
- Do not use dataset ground-truth labels as detection inputs.
- Do not create more than one incident for the same source record.
- Preserve existing incidents when processing is repeated.
- Keep status transitions sequential.
- Rule deactivation must not remove historical incidents.
