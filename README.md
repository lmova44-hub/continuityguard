# ContinuityGuard

ContinuityGuard is an educational incident and risk management web application built with Flask and SQLite.

## Features
- Dashboard for risk and incident overview
- Risk register with likelihood × impact scoring
- Incident tracking and status updates
- Recovery Lab for backup creation, SHA-256 checksums, synthetic outage simulation, and restore verification
- Basic RTO/RPO estimates after recovery
- Audit log for important actions
- CSRF protection on forms
- Optional administrator login using environment variables
- Health endpoint at `/health`

## Run locally (Windows PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

To enable login locally, set environment variables before starting the app:

```powershell
$env:SECRET_KEY="replace-with-a-long-random-secret"
$env:ADMIN_USERNAME="admin"
$env:ADMIN_PASSWORD="replace-with-a-strong-password"
python app.py
```

If `ADMIN_PASSWORD` is empty, login is disabled for convenient local development. Set it on any public deployment.

## Recovery Lab demo
1. Open `/recovery`.
2. Click **Create verified backup**.
3. Click **Simulate synthetic outage**. Only the local synthetic `service.db` test data is cleared.
4. Click **Restore from latest backup**.
5. Confirm that the service is operational and the sample records are restored.
6. Open `/audit` to see the recorded actions.

Do not use this demo to test recovery against real systems or real data.

## Deploy to Render
- Create a Python Web Service connected to the GitHub repository.
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`
- Health check path: `/health`
- Set environment variables `SECRET_KEY`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD`.
- The app uses SQLite by default. Files on Render's default filesystem can be ephemeral. For a lasting demo database and backup files, configure a persistent disk on a plan that supports it and mount it at `/opt/render/project/src/instance`. Otherwise, data may be lost after a restart or redeploy.

## Limitations
This is a portfolio/academic prototype, not a production disaster recovery system. It does not provide multi-user roles, enterprise identity integration, immutable off-site backups, alerting, or production-grade recovery orchestration. RTO/RPO values are simplified demo measurements.
