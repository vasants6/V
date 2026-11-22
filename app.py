import os, secrets, hashlib, json
from datetime import datetime, timedelta, timezone
from io import BytesIO
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
import qrcode
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")
db_url = os.environ.get("DATABASE_URL", "sqlite:///diagnostics.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
db = SQLAlchemy(app)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "24"))

class DiagnosticSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    label = db.Column(db.String(120), default="Diagnostic session")
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    revoked = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    consent_summary = db.Column(db.Text, nullable=True)
    results_json = db.Column(db.Text, nullable=True)
    client_submitted_at = db.Column(db.String(80), nullable=True)

def utcnow():
    return datetime.now(timezone.utc)

def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def public_url(path):
    base = PUBLIC_BASE_URL or request.url_root.rstrip("/")
    return base + path

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(self), geolocation=(self), accelerometer=(self), gyroscope=(self)"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/")
def home():
    if session.get("admin_authenticated"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if not ADMIN_PASSWORD_HASH:
            flash("Admin password is not configured. Set ADMIN_PASSWORD_HASH in environment variables.", "error")
        elif secrets.compare_digest(username, ADMIN_USERNAME) and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session.clear()
            session["admin_authenticated"] = True
            session["admin_username"] = username
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid login details.", "error")
    return render_template("login.html")

@app.get("/admin/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/admin")
@admin_required
def dashboard():
    records = DiagnosticSession.query.order_by(DiagnosticSession.created_at.desc()).limit(100).all()
    now = utcnow()
    for item in records:
        expiry = item.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        item.is_expired = expiry < now
    return render_template("dashboard.html", records=records)

@app.post("/admin/create")
@admin_required
def create_session():
    label = (request.form.get("label") or "Diagnostic session").strip()[:120]
    hours = request.form.get("hours", "24")
    try:
        hours = max(1, min(int(hours), 168))
    except ValueError:
        hours = 24
    token = secrets.token_urlsafe(32)
    record = DiagnosticSession(
        token_hash=token_digest(token),
        label=label,
        expires_at=utcnow() + timedelta(hours=hours)
    )
    db.session.add(record)
    db.session.commit()
    link = public_url(url_for("user_portal", token=token))
    return render_template("created.html", link=link, qr_data=qr_data_uri(link), record=record)

def qr_data_uri(value):
    img = qrcode.make(value)
    buff = BytesIO()
    img.save(buff, format="PNG")
    import base64
    return "data:image/png;base64," + base64.b64encode(buff.getvalue()).decode("ascii")

def find_public_session(token):
    if not token or len(token) > 200:
        return None
    record = DiagnosticSession.query.filter_by(token_hash=token_digest(token)).first()
    if not record or record.revoked or record.expires_at < utcnow():
        return None
    return record

@app.get("/d/<token>")
def user_portal(token):
    record = find_public_session(token)
    if not record:
        return render_template("unavailable.html"), 404
    return render_template("user.html", token=token, label=record.label, expires=record.expires_at.isoformat())

@app.post("/api/submit/<token>")
def submit_results(token):
    record = find_public_session(token)
    if not record:
        return jsonify({"ok": False, "error": "This session is expired or revoked."}), 404
    payload = request.get_json(silent=True) or {}
    if payload.get("consent") is not True:
        return jsonify({"ok": False, "error": "Explicit consent is required."}), 400
    results = payload.get("results", {})
    if not isinstance(results, dict):
        return jsonify({"ok": False, "error": "Invalid report format."}), 400
    # Allowlist fields and enforce a conservative payload size.
    allowed = {"phone", "network", "battery", "geolocation", "camera", "microphone", "sound", "sensors", "browser", "connection"}
    safe_results = {k: v for k, v in results.items() if k in allowed}
    safe_json = json.dumps(safe_results, ensure_ascii=False)
    if len(safe_json) > 30000:
        return jsonify({"ok": False, "error": "Report is too large."}), 413
    record.results_json = safe_json
    record.consent_summary = "User confirmed consent before submitting selected diagnostic results."
    record.client_submitted_at = str(payload.get("clientSubmittedAt", ""))[:80]
    record.completed_at = utcnow()
    db.session.commit()
    return jsonify({"ok": True, "message": "Report securely submitted."})

@app.get("/admin/report/<int:record_id>")
@admin_required
def report(record_id):
    record = db.session.get(DiagnosticSession, record_id)
    if not record:
        abort(404)
    results = json.loads(record.results_json or "{}")
    return render_template("report.html", record=record, results=results)

@app.post("/admin/revoke/<int:record_id>")
@admin_required
def revoke(record_id):
    record = db.session.get(DiagnosticSession, record_id)
    if record:
        record.revoked = True
        db.session.commit()
    return redirect(url_for("dashboard"))

@app.get("/admin/pdf/<int:record_id>")
@admin_required
def pdf_report(record_id):
    record = db.session.get(DiagnosticSession, record_id)
    if not record:
        abort(404)
    results = json.loads(record.results_json or "{}")
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm)
    styles = getSampleStyleSheet()
    story = [Paragraph("GEO-DIAGNOSTIC PRO — Diagnostic Report", styles["Title"]), Spacer(1, 8)]
    story.append(Paragraph(f"Session: {record.label}", styles["Heading2"]))
    story.append(Paragraph(f"Created: {record.created_at.isoformat() if record.created_at else '—'}", styles["BodyText"]))
    story.append(Paragraph(f"Completed: {record.completed_at.isoformat() if record.completed_at else 'Not completed'}", styles["BodyText"]))
    story.append(Paragraph(f"Consent: {record.consent_summary or 'Not submitted'}", styles["BodyText"]))
    story.append(Spacer(1, 10))
    rows = [["Diagnostic", "Result"]]
    for key, value in results.items():
        val = json.dumps(value, ensure_ascii=False)
        if len(val) > 1500:
            val = val[:1500] + "…"
        rows.append([key.replace("_", " ").title(), val])
    if len(rows) == 1:
        rows.append(["No results", "No diagnostic results submitted"])
    table = Table(rows, colWidths=[42*mm, 125*mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#102b48")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.35, colors.HexColor("#b7c7d8")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(table)
    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"diagnostic-{record.id}.pdf", mimetype="application/pdf")

@app.get("/ping")
def ping():
    return "ok", 200, {"Content-Type": "text/plain"}

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
