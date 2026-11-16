# Cybersecurity Incident Management System (CSIMS)

A Flask-based web application for processing the UNSW-NB15 network-flow dataset, detecting suspicious records with configurable rules, and managing the resulting incidents.

## Requirements

- Python 3.10 or newer
- Packages listed in `requirements.txt`
- The included UNSW-NB15 dataset files in `data/`

## Installation (Windows)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## First launch

1. From the project root, set a persistent secret key in the current PowerShell session:

   ```powershell
   $env:dce6d4c97ee4511a8b836280b42d0fa92c16f257178dcbf0361b412159140fb5= python -c "import secrets; print(secrets.token_hex(32))"
   ```

2. Start the application:

   ```powershell
   python app.py
   ```

3. Open `http://127.0.0.1:5000/setup` and create the first Administrator account.
4. Sign in with that account.

The included SQLite database is intentionally clean. The application creates the initial database schema automatically. Dataset processing starts automatically on application startup after Administrator setup has been completed, unless the dataset has already been fully processed.

For a production HTTPS deployment, set `CSIMS_HTTPS=1`, configure a persistent `CSIMS_SECRET_KEY`, and run the application behind a production WSGI server and HTTPS reverse proxy. The built-in Flask development server is intended for local development only.

## Tests

Run the automated tests from the project root:

```powershell
python -m unittest discover -s tests -v
```

## Project layout

- `app.py` — Flask routes, authentication, access control, dashboard endpoints.
- `detection/` — detection rules, thresholds, and rule evaluation engine.
- `dataset/` — UNSW-NB15 loading, sequential record processing, and evaluation scripts.
- `storage/` — SQLite schema and database operations.
- `templates/` — server-rendered HTML pages.
- `static/` — CSS.
- `tests/` — unit and web-security regression tests.
- `docs/` — user and developer guides.

See `docs/USER_GUIDE.md` and `docs/DEVELOPER_GUIDE.md` for further information.
