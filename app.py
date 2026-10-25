import os
import json
import hmac
import hashlib
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__, instance_relative_config=True)
Path(app.instance_path).mkdir(parents=True, exist_ok=True)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "local-development-key-change-before-deploy"),
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + str(Path(app.instance_path) / "continuityguard.db")
    ).replace("postgres://", "postgresql://", 1),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    ADMIN_USERNAME=os.environ.get("ADMIN_USERNAME", "admin"),
    ADMIN_PASSWORD=os.environ.get("ADMIN_PASSWORD", ""),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

SERVICE_DB = str(Path(app.instance_path) / "service.db")
BACKUP_DIR = Path(app.instance_path) / "backups"
OUTAGE_FILE = Path(app.instance_path) / "service_outage.json"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def score_risk(likelihood, impact):
    return int(likelihood) * int(impact)


def risk_level(score):
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


class Risk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    asset = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, default="")
    likelihood = db.Column(db.Integer, nullable=False, default=3)
    impact = db.Column(db.Integer, nullable=False, default=3)
    mitigation = db.Column(db.Text, default="")
    owner = db.Column(db.String(120), default="Unassigned")
    status = db.Column(db.String(30), default="Open")
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)

    @property
    def score(self):
        return score_risk(self.likelihood, self.impact)

    @property
    def level(self):
        return risk_level(self.score)


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    category = db.Column(db.String(80), nullable=False, default="Other")
    severity = db.Column(db.String(30), nullable=False, default="Medium")
    status = db.Column(db.String(30), nullable=False, default="Open")
    description = db.Column(db.Text, default="")
    assigned_to = db.Column(db.String(120), default="Unassigned")
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    resolved_at = db.Column(db.DateTime, nullable=True)


class RecoveryTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(30), nullable=False)
    result = db.Column(db.String(30), nullable=False)
    backup_name = db.Column(db.String(200), default="")
    details = db.Column(db.Text, default="")
    rto_seconds = db.Column(db.Float, nullable=True)
    rpo_seconds = db.Column(db.Float, nullable=True)
    checksum = db.Column(db.String(64), default="")
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)


def audit(action, details=""):
    db.session.add(AuditEvent(action=action, details=details))
    db.session.commit()


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def init_test_service():
    with sqlite3.connect(SERVICE_DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS service_records (
                id INTEGER PRIMARY KEY,
                record_name TEXT NOT NULL,
                record_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        count = conn.execute("SELECT COUNT(*) FROM service_records").fetchone()[0]
        if count == 0 and not OUTAGE_FILE.exists():
            now = utc_now().isoformat(timespec="seconds")
            rows = [
                ("Payment API", "Operational", now),
                ("Customer portal", "Operational", now),
                ("Notification queue", "Operational", now),
            ]
            conn.executemany(
                "INSERT INTO service_records (record_name, record_value, updated_at) VALUES (?, ?, ?)",
                rows,
            )
            conn.commit()


def verify_service_database(path):
    if not os.path.exists(path):
        return False, "Database file does not exist."
    try:
        with sqlite3.connect(path) as conn:
            result = conn.execute("PRAGMA integrity_check").fetchone()[0]
            conn.execute("SELECT id, record_name, record_value, updated_at FROM service_records LIMIT 1").fetchall()
        if result == "ok":
            return True, "Integrity check passed."
        return False, f"Integrity check failed: {result}"
    except sqlite3.Error as exc:
        return False, str(exc)


def latest_backup():
    backups = sorted(BACKUP_DIR.glob("service-backup-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in backups:
        ok, _ = verify_service_database(str(path))
        if ok:
            return path
    return None


def service_record_count():
    try:
        with sqlite3.connect(SERVICE_DB) as conn:
            return conn.execute("SELECT COUNT(*) FROM service_records").fetchone()[0]
    except sqlite3.Error:
        return 0


def service_status():
    if OUTAGE_FILE.exists():
        return "Outage"
    ok, _ = verify_service_database(SERVICE_DB)
    return "Operational" if ok else "Unavailable"


def get_backup_inventory():
    inventory = []
    for path in sorted(BACKUP_DIR.glob("service-backup-*.db"), key=lambda p: p.stat().st_mtime, reverse=True):
        ok, message = verify_service_database(str(path))
        inventory.append({
            "name": path.name,
            "size": round(path.stat().st_size / 1024, 1),
            "checksum": file_sha256(str(path)),
            "verified": ok,
            "message": message,
            "created": datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return inventory


@app.context_processor
def inject_globals():
    return {
        "current_year": datetime.now().year,
        "admin_auth_enabled": bool(app.config["ADMIN_PASSWORD"]),
        "service_status": service_status,
    }


@app.before_request
def enforce_login():
    if not app.config["ADMIN_PASSWORD"]:
        return None
    if request.endpoint in {"login", "health", "static"}:
        return None
    if not session.get("authenticated"):
        return redirect(url_for("login", next=request.path))
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if not app.config["ADMIN_PASSWORD"]:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        valid_user = hmac.compare_digest(username, app.config["ADMIN_USERNAME"])
        valid_password = hmac.compare_digest(password, app.config["ADMIN_PASSWORD"])
        if valid_user and valid_password:
            session.clear()
            session["authenticated"] = True
            flash("Welcome back. You are signed in.", "success")
            destination = request.args.get("next", "")
            if not destination.startswith("/") or destination.startswith("//"):
                destination = url_for("dashboard")
            return redirect(destination)
        flash("Incorrect username or password.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login") if app.config["ADMIN_PASSWORD"] else url_for("dashboard"))


@app.get("/health")
def health():
    return {"status": "ok", "application": "ContinuityGuard"}, 200


@app.get("/")
def dashboard():
    risks = Risk.query.order_by(Risk.created_at.desc()).all()
    incidents = Incident.query.order_by(Incident.created_at.desc()).limit(5).all()
    open_incidents = Incident.query.filter(Incident.status != "Resolved").count()
    high_risks = sum(1 for risk in risks if risk.level in {"High", "Critical"})
    recent_audit = AuditEvent.query.order_by(AuditEvent.created_at.desc()).limit(6).all()
    return render_template(
        "dashboard.html",
        risks=risks[:5],
        incidents=incidents,
        open_incidents=open_incidents,
        high_risks=high_risks,
        risk_count=len(risks),
        incident_count=Incident.query.count(),
        recovery_count=RecoveryTest.query.count(),
        recent_audit=recent_audit,
    )


@app.route("/risks", methods=["GET", "POST"])
def risks_page():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        asset = request.form.get("asset", "").strip()
        description = request.form.get("description", "").strip()
        mitigation = request.form.get("mitigation", "").strip()
        owner = request.form.get("owner", "").strip() or "Unassigned"
        try:
            likelihood = int(request.form.get("likelihood", "3"))
            impact = int(request.form.get("impact", "3"))
        except ValueError:
            flash("Likelihood and impact must be numbers from 1 to 5.", "error")
            return redirect(url_for("risks_page"))
        if not title or not asset:
            flash("Risk title and affected asset are required.", "error")
            return redirect(url_for("risks_page"))
        if likelihood not in range(1, 6) or impact not in range(1, 6):
            flash("Likelihood and impact must be between 1 and 5.", "error")
            return redirect(url_for("risks_page"))
        risk = Risk(
            title=title, asset=asset, description=description,
            likelihood=likelihood, impact=impact,
            mitigation=mitigation, owner=owner,
        )
        db.session.add(risk)
        db.session.commit()
        audit("RISK_CREATED", f"Risk #{risk.id}: {risk.title}")
        flash("Risk added to the register.", "success")
        return redirect(url_for("risks_page"))

    risks = Risk.query.order_by(Risk.created_at.desc()).all()
    return render_template("risks.html", risks=risks)


@app.post("/risks/<int:risk_id>/status")
def update_risk_status(risk_id):
    risk = db.session.get(Risk, risk_id)
    if risk is None:
        abort(404)
    new_status = request.form.get("status", "Open")
    if new_status not in {"Open", "Mitigating", "Accepted", "Closed"}:
        abort(400)
    risk.status = new_status
    db.session.commit()
    audit("RISK_STATUS_CHANGED", f"Risk #{risk.id} status changed to {risk.status}")
    flash("Risk status updated.", "success")
    return redirect(url_for("risks_page"))


@app.route("/incidents", methods=["GET", "POST"])
def incidents_page():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "Other")
        severity = request.form.get("severity", "Medium")
        description = request.form.get("description", "").strip()
        assigned_to = request.form.get("assigned_to", "").strip() or "Unassigned"
        if not title:
            flash("Incident title is required.", "error")
            return redirect(url_for("incidents_page"))
        if category not in {"Security", "Availability", "Data", "Network", "Other"}:
            category = "Other"
        if severity not in {"Low", "Medium", "High", "Critical"}:
            severity = "Medium"
        incident = Incident(
            title=title, category=category, severity=severity,
            description=description, assigned_to=assigned_to,
        )
        db.session.add(incident)
        db.session.commit()
        audit("INCIDENT_CREATED", f"Incident #{incident.id}: {incident.title}")
        flash("Incident recorded.", "success")
        return redirect(url_for("incidents_page"))

    incidents = Incident.query.order_by(Incident.created_at.desc()).all()
    return render_template("incidents.html", incidents=incidents)


@app.post("/incidents/<int:incident_id>/status")
def update_incident_status(incident_id):
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        abort(404)
    new_status = request.form.get("status", "Open")
    if new_status not in {"Open", "Investigating", "Contained", "Resolved"}:
        abort(400)
    incident.status = new_status
    incident.resolved_at = utc_now() if new_status == "Resolved" else None
    db.session.commit()
    audit("INCIDENT_STATUS_CHANGED", f"Incident #{incident.id} status changed to {incident.status}")
    flash("Incident status updated.", "success")
    return redirect(url_for("incidents_page"))


@app.route("/recovery", methods=["GET", "POST"])
def recovery_page():
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "backup":
            ok, message = verify_service_database(SERVICE_DB)
            if not ok:
                flash(f"Cannot create backup: {message}", "error")
                return redirect(url_for("recovery_page"))
            backup_name = f"service-backup-{utc_now().strftime('%Y%m%d-%H%M%S-%f')}.db"
            backup_path = BACKUP_DIR / backup_name
            try:
                with sqlite3.connect(SERVICE_DB) as source, sqlite3.connect(str(backup_path)) as target:
                    source.backup(target)
                backup_ok, backup_message = verify_service_database(str(backup_path))
                checksum = file_sha256(str(backup_path))
                result = "Success" if backup_ok else "Failed"
                details = f"{backup_message} SHA-256: {checksum}"
                db.session.add(RecoveryTest(
                    action="Backup", result=result, backup_name=backup_name,
                    details=details, checksum=checksum,
                ))
                db.session.commit()
                audit("BACKUP_CREATED", f"{backup_name}; verified={backup_ok}; SHA-256={checksum}")
                flash("Backup created and verified." if backup_ok else "Backup created but verification failed.", "success" if backup_ok else "error")
            except (sqlite3.Error, OSError) as exc:
                db.session.add(RecoveryTest(action="Backup", result="Failed", details=str(exc)))
                db.session.commit()
                audit("BACKUP_FAILED", str(exc))
                flash(f"Backup failed: {exc}", "error")
            return redirect(url_for("recovery_page"))

        if action == "simulate_outage":
            if OUTAGE_FILE.exists():
                flash("An outage is already active. Recover the service first.", "error")
                return redirect(url_for("recovery_page"))
            if latest_backup() is None:
                flash("Create and verify a backup before simulating an outage.", "error")
                return redirect(url_for("recovery_page"))
            outage_started = utc_now()
            OUTAGE_FILE.write_text(json.dumps({"started_at": outage_started.isoformat()}), encoding="utf-8")
            try:
                # Only the isolated synthetic test database is affected.
                with sqlite3.connect(SERVICE_DB) as conn:
                    conn.execute("DELETE FROM service_records")
                    conn.commit()
                db.session.add(RecoveryTest(
                    action="Outage", result="Simulated",
                    details="Synthetic service records were cleared to test backup restoration.",
                ))
                db.session.commit()
                audit("OUTAGE_SIMULATED", "Synthetic test service set to outage; no real systems affected.")
                flash("Synthetic outage simulated. The test service is now unavailable.", "success")
            except sqlite3.Error as exc:
                OUTAGE_FILE.unlink(missing_ok=True)
                audit("OUTAGE_SIMULATION_FAILED", str(exc))
                flash(f"Could not simulate outage: {exc}", "error")
            return redirect(url_for("recovery_page"))

        if action == "recover":
            if not OUTAGE_FILE.exists():
                flash("No active outage. Simulate an outage first.", "error")
                return redirect(url_for("recovery_page"))
            backup = latest_backup()
            if backup is None:
                flash("No verified backup is available.", "error")
                return redirect(url_for("recovery_page"))
            try:
                outage_data = json.loads(OUTAGE_FILE.read_text(encoding="utf-8"))
                outage_started = datetime.fromisoformat(outage_data["started_at"])
                ok, verify_message = verify_service_database(str(backup))
                if not ok:
                    raise RuntimeError(f"Backup verification failed: {verify_message}")

                restored_path = str(Path(app.instance_path) / "service.restore.tmp")
                Path(restored_path).unlink(missing_ok=True)
                with sqlite3.connect(str(backup)) as source, sqlite3.connect(restored_path) as target:
                    source.backup(target)
                restore_ok, restore_message = verify_service_database(restored_path)
                if not restore_ok:
                    raise RuntimeError(f"Restored database failed validation: {restore_message}")
                shutil.move(restored_path, SERVICE_DB)
                final_ok, final_message = verify_service_database(SERVICE_DB)
                if not final_ok:
                    raise RuntimeError(f"Final validation failed: {final_message}")

                rto = max(0.0, (utc_now() - outage_started).total_seconds())
                rpo = None
                try:
                    with sqlite3.connect(SERVICE_DB) as conn:
                        latest = conn.execute("SELECT MAX(updated_at) FROM service_records").fetchone()[0]
                    if latest:
                        latest_time = datetime.fromisoformat(latest)
                        rpo = max(0.0, (outage_started - latest_time).total_seconds())
                except (sqlite3.Error, ValueError):
                    pass

                OUTAGE_FILE.unlink(missing_ok=True)
                checksum = file_sha256(SERVICE_DB)
                db.session.add(RecoveryTest(
                    action="Recovery", result="Success", backup_name=backup.name,
                    details=f"Restore verified. {final_message}",
                    rto_seconds=rto, rpo_seconds=rpo, checksum=checksum,
                ))
                db.session.commit()
                audit("SERVICE_RECOVERED", f"Restored from {backup.name}; RTO={rto:.2f}s; RPO={rpo if rpo is not None else 'N/A'}")
                flash(f"Recovery successful. Restored {service_record_count()} synthetic records; RTO {rto:.2f} seconds.", "success")
            except (OSError, sqlite3.Error, ValueError, KeyError, RuntimeError, shutil.Error) as exc:
                db.session.add(RecoveryTest(action="Recovery", result="Failed", backup_name=backup.name, details=str(exc)))
                db.session.commit()
                audit("RECOVERY_FAILED", str(exc))
                flash(f"Recovery failed: {exc}", "error")
            return redirect(url_for("recovery_page"))

        flash("Unknown recovery action.", "error")
        return redirect(url_for("recovery_page"))

    history = RecoveryTest.query.order_by(RecoveryTest.created_at.desc()).limit(15).all()
    return render_template(
        "recovery.html",
        history=history,
        backups=get_backup_inventory(),
        record_count=service_record_count(),
        status=service_status(),
        latest_backup=latest_backup(),
    )


@app.get("/audit")
def audit_page():
    events = AuditEvent.query.order_by(AuditEvent.created_at.desc()).limit(100).all()
    return render_template("audit.html", events=events)


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The page you requested could not be found."), 404


@app.errorhandler(500)
def server_error(_error):
    db.session.rollback()
    return render_template("error.html", code=500, message="Something went wrong. Check the application logs."), 500


def seed_demo_data():
    if Risk.query.count() == 0:
        db.session.add_all([
            Risk(
                title="Insufficient backup validation",
                asset="Customer records database",
                description="Backups may exist but have not been regularly tested.",
                likelihood=3, impact=5,
                mitigation="Schedule restore tests and retain integrity-check evidence.",
                owner="IT Operations", status="Mitigating",
            ),
            Risk(
                title="Privileged account compromise",
                asset="Administrator account",
                description="A compromised privileged account could affect critical services.",
                likelihood=3, impact=5,
                mitigation="Use MFA, unique credentials, and least privilege.",
                owner="Security Team", status="Open",
            ),
            Risk(
                title="Unmonitored service interruption",
                asset="Customer portal",
                description="Detection may be delayed without service health monitoring.",
                likelihood=2, impact=4,
                mitigation="Add uptime monitoring and define escalation thresholds.",
                owner="Infrastructure", status="Open",
            ),
        ])
    if Incident.query.count() == 0:
        db.session.add_all([
            Incident(
                title="Repeated authentication failures",
                category="Security", severity="High",
                status="Investigating",
                description="Synthetic example: several failed sign-in attempts were detected.",
                assigned_to="Security Team",
            ),
            Incident(
                title="Customer portal response delay",
                category="Availability", severity="Medium",
                status="Open",
                description="Synthetic example: response time exceeded the internal threshold.",
                assigned_to="IT Operations",
            ),
        ])
    db.session.commit()


with app.app_context():
    db.create_all()
    seed_demo_data()
    init_test_service()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
