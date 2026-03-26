import os
from datetime import datetime, date

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import (Flask, flash, redirect, render_template,
                   request, send_from_directory, abort, make_response)
from flask_login import (LoginManager, UserMixin, login_user,
                         logout_user, login_required, current_user)
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-schimba-asta!")

# ── Debug OFF in productie
app.config["DEBUG"] = os.environ.get("FLASK_ENV") == "development"

# ── Mail
app.config["MAIL_SERVER"]         = "smtp.gmail.com"
app.config["MAIL_PORT"]           = 587
app.config["MAIL_USE_TLS"]        = True
app.config["MAIL_USERNAME"]       = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"]       = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME")
mail = Mail(app)

# ── Upload folder (local dev); pe Render foloseste un bucket cloud
UPLOAD_FOLDER      = os.path.join(os.path.dirname(__file__), "uploads")
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "doc", "docx"}
MAX_FILE_MB        = 10
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── Flask-Login
login_manager = LoginManager(app)
login_manager.login_view    = "login"
login_manager.login_message = "error|Trebuie sa fii autentificat."


# ══════════════════════════════════════════════
# DATABASE HELPER  (replaces cs50.SQL)
# ══════════════════════════════════════════════

def get_db():
    """Open a new DB connection per request."""
    database_url = os.environ.get("DATABASE_URL", "")
    # Render gives postgres:// but psycopg2 needs postgresql://
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    conn = psycopg2.connect(database_url, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def db_execute(query, *args):
    """
    Run a SQL query.
    SELECT  → returns list of dicts
    INSERT/UPDATE/DELETE → returns None
    Converts %s placeholders; also accepts ? for compatibility.
    """
    query = query.replace("?", "%s")
    conn = get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, args if args else None)
                if query.strip().upper().startswith("SELECT"):
                    return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return None


# ══════════════════════════════════════════════
# USER MODEL
# ══════════════════════════════════════════════

class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id       = id
        self.username = username
        self.email    = email
        self.role     = role

@login_manager.user_loader
def load_user(user_id):
    rows = db_execute("SELECT * FROM users WHERE id = %s", int(user_id))
    if not rows:
        return None
    u = rows[0]
    return User(u["id"], u["username"], u["email"], u["role"])


# ── Helpers
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def send_email(to, subject, body):
    try:
        if app.config.get("MAIL_USERNAME"):
            msg = Message(subject, recipients=[to], body=body)
            mail.send(msg)
    except Exception:
        pass

@app.context_processor
def inject_globals():
    return {"now": datetime.now(), "request": request}


# ══════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect("/")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("error|Completeaza toate campurile.")
            return redirect("/login")
        rows = db_execute("SELECT * FROM users WHERE username = %s", username)
        if not rows or not check_password_hash(rows[0]["password_hash"], password):
            flash("error|Username sau parola gresita.")
            return redirect("/login")
        u = rows[0]
        login_user(User(u["id"], u["username"], u["email"], u["role"]),
                   remember=request.form.get("remember") == "on")
        flash(f"success|Bun venit, {u['username']}!")
        return redirect(request.args.get("next") or "/")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("success|Ai fost deconectat.")
    return redirect("/login")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "change_password":
            old_pw  = request.form.get("old_password", "")
            new_pw  = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            rows = db_execute("SELECT password_hash FROM users WHERE id = %s", current_user.id)
            if not check_password_hash(rows[0]["password_hash"], old_pw):
                flash("error|Parola actuala este gresita.")
                return redirect("/settings")
            if len(new_pw) < 6:
                flash("error|Parola noua trebuie sa aiba minim 6 caractere.")
                return redirect("/settings")
            if new_pw != confirm:
                flash("error|Parolele nu se potrivesc.")
                return redirect("/settings")
            db_execute("UPDATE users SET password_hash = %s WHERE id = %s",
                       generate_password_hash(new_pw), current_user.id)
            flash("success|Parola schimbata!")
            return redirect("/settings")

        if action == "add_user":
            uname  = request.form.get("new_username", "").strip()
            uemail = request.form.get("new_email", "").strip()
            upw    = request.form.get("new_user_password", "")
            if not uname or not uemail or not upw:
                flash("error|Completeaza toate campurile.")
                return redirect("/settings")
            existing = db_execute("SELECT id FROM users WHERE username = %s OR email = %s", uname, uemail)
            if existing:
                flash("error|Username sau email deja folosit.")
                return redirect("/settings")
            db_execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                       uname, uemail, generate_password_hash(upw))
            flash(f"success|Utilizatorul {uname} creat.")
            return redirect("/settings")

    users_list = db_execute("SELECT id, username, email, role, created_at FROM users")
    return render_template("settings.html", users_list=users_list)


# ══════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════

@app.route("/")
@login_required
def index():
    apartments = db_execute("""
        SELECT a.id, a.number, a.address, a.status,
               t.first_name, t.last_name, t.id AS tenant_id
        FROM apartments a
        LEFT JOIN tenants t ON a.id = t.apartment_id
    """)
    total    = len(apartments)
    occupied = sum(1 for a in apartments if a["status"] == "Rented")
    vacant   = total - occupied

    open_tickets = db_execute("SELECT COUNT(*) AS cnt FROM maintenance WHERE status = 'Open'")[0]["cnt"]
    unpaid_bills = db_execute("SELECT COUNT(*) AS cnt FROM facturi WHERE status = 'Unpaid'")[0]["cnt"]

    this_month = date.today().strftime("%Y-%m")
    revenue = db_execute(
        "SELECT COALESCE(SUM(amount), 0) AS total FROM facturi WHERE status='Paid' AND paid_at::text LIKE %s",
        f"{this_month}%"
    )[0]["total"]

    recent = db_execute("""
        SELECT f.amount, f.status, f.due_date, t.first_name, t.last_name
        FROM facturi f JOIN tenants t ON f.tenant_id = t.id
        ORDER BY f.id DESC LIMIT 5
    """)

    return render_template("index.html",
        apartments=apartments, total=total, occupied=occupied,
        vacant=vacant, open_tickets=open_tickets, unpaid_bills=unpaid_bills,
        revenue=revenue, recent=recent
    )


# ══════════════════════════════════════════════
# TENANTS
# ══════════════════════════════════════════════

@app.route("/tenants")
@login_required
def tenants():
    search = request.args.get("q", "").strip()
    base = """
        SELECT t.id, t.first_name, t.last_name, t.email, t.phone,
               a.number, a.address, a.id AS apartment_id,
               (SELECT COUNT(*) FROM facturi f WHERE f.tenant_id = t.id AND f.status = 'Unpaid') AS unpaid,
               (SELECT COUNT(*) FROM acte ac WHERE ac.tenant_id = t.id) AS nr_acte
        FROM tenants t JOIN apartments a ON t.apartment_id = a.id
    """
    if search:
        like = f"%{search}%"
        all_tenants = db_execute(
            base + " WHERE t.first_name ILIKE %s OR t.last_name ILIKE %s OR t.email ILIKE %s OR a.number ILIKE %s ORDER BY t.last_name",
            like, like, like, like
        )
    else:
        all_tenants = db_execute(base + " ORDER BY t.last_name")
    return render_template("tenants.html", tenants=all_tenants, search=search)


@app.route("/add_tenant", methods=["GET", "POST"])
@login_required
def add_tenant():
    if request.method == "POST":
        fname  = request.form.get("first_name", "").strip()
        lname  = request.form.get("last_name", "").strip()
        email  = request.form.get("email", "").strip()
        phone  = request.form.get("phone", "").strip()
        apt_id = request.form.get("apartment_id")
        if not fname or not lname or not email or not apt_id:
            flash("error|Completeaza toate campurile obligatorii.")
            return redirect("/add_tenant")
        db_execute(
            "INSERT INTO tenants (first_name, last_name, email, phone, apartment_id) VALUES (%s, %s, %s, %s, %s)",
            fname, lname, email, phone, apt_id
        )
        db_execute("UPDATE apartments SET status = 'Rented' WHERE id = %s", apt_id)
        apt = db_execute("SELECT number, address FROM apartments WHERE id = %s", apt_id)[0]
        send_email(email, "Bun venit la RentManager!",
            f"Buna ziua {fname},\n\nContractul tau pentru Unitatea {apt['number']} ({apt['address']}) a fost activat.\n\nEchipa RentManager")
        flash(f"success|Chiriasul {fname} {lname} a fost adaugat!")
        return redirect("/tenants")
    available_apts = db_execute("SELECT * FROM apartments WHERE status = 'Available'")
    return render_template("add_tenant.html", available_apts=available_apts)


@app.route("/delete_tenant", methods=["POST"])
@login_required
def delete_tenant():
    tenant_id = request.form.get("tenant_id")
    rows = db_execute("SELECT * FROM tenants WHERE id = %s", tenant_id)
    if not rows:
        flash("error|Chiriasul nu a fost gasit.")
        return redirect("/tenants")
    t      = rows[0]
    apt_id = t["apartment_id"]
    name   = f"{t['first_name']} {t['last_name']}"
    acte_rows = db_execute("SELECT filename FROM acte WHERE tenant_id = %s", tenant_id)
    for a in acte_rows:
        fpath = os.path.join(UPLOAD_FOLDER, a["filename"])
        if os.path.exists(fpath):
            os.remove(fpath)
    db_execute("DELETE FROM acte WHERE tenant_id = %s", tenant_id)
    db_execute("DELETE FROM facturi WHERE tenant_id = %s", tenant_id)
    db_execute("DELETE FROM tenants WHERE id = %s", tenant_id)
    db_execute("UPDATE apartments SET status = 'Available' WHERE id = %s", apt_id)
    flash(f"success|{name} eliminat. Apartamentul este disponibil.")
    return redirect("/tenants")


# ══════════════════════════════════════════════
# ACTE
# ══════════════════════════════════════════════

@app.route("/acte/<int:tenant_id>")
@login_required
def acte(tenant_id):
    tenant = db_execute("""
        SELECT t.id, t.first_name, t.last_name, a.number
        FROM tenants t JOIN apartments a ON t.apartment_id = a.id
        WHERE t.id = %s
    """, tenant_id)
    if not tenant:
        flash("error|Chiriasul nu a fost gasit.")
        return redirect("/tenants")
    docs = db_execute("SELECT * FROM acte WHERE tenant_id = %s ORDER BY uploaded_at DESC", tenant_id)
    return render_template("acte.html", tenant=tenant[0], docs=docs)


@app.route("/acte/upload/<int:tenant_id>", methods=["POST"])
@login_required
def upload_act(tenant_id):
    doc_type = request.form.get("doc_type", "Altele").strip()
    notes    = request.form.get("notes", "").strip()
    if "file" not in request.files or request.files["file"].filename == "":
        flash("error|Niciun fisier selectat.")
        return redirect(f"/acte/{tenant_id}")
    file = request.files["file"]
    if not allowed_file(file.filename):
        flash("error|Tip de fisier nepermis. Acceptam: PDF, JPG, PNG, DOC, DOCX.")
        return redirect(f"/acte/{tenant_id}")
    # Check file size
    file.seek(0, 2)
    size_mb = file.tell() / (1024 * 1024)
    file.seek(0)
    if size_mb > MAX_FILE_MB:
        flash(f"error|Fisierul este prea mare. Maxim {MAX_FILE_MB}MB.")
        return redirect(f"/acte/{tenant_id}")
    safe     = secure_filename(f"{tenant_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
    filepath = os.path.join(UPLOAD_FOLDER, safe)
    file.save(filepath)
    db_execute("INSERT INTO acte (tenant_id, doc_type, filename, original_name, notes) VALUES (%s, %s, %s, %s, %s)",
               tenant_id, doc_type, safe, file.filename, notes)
    flash("success|Documentul a fost incarcat!")
    return redirect(f"/acte/{tenant_id}")


@app.route("/acte/download/<int:doc_id>")
@login_required
def download_act(doc_id):
    doc = db_execute("SELECT * FROM acte WHERE id = %s", doc_id)
    if not doc:
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, doc[0]["filename"],
                               as_attachment=True, download_name=doc[0]["original_name"])


@app.route("/acte/delete/<int:doc_id>", methods=["POST"])
@login_required
def delete_act(doc_id):
    doc = db_execute("SELECT * FROM acte WHERE id = %s", doc_id)
    if not doc:
        flash("error|Documentul nu a fost gasit.")
        return redirect("/tenants")
    tenant_id = doc[0]["tenant_id"]
    fpath = os.path.join(UPLOAD_FOLDER, doc[0]["filename"])
    if os.path.exists(fpath):
        os.remove(fpath)
    db_execute("DELETE FROM acte WHERE id = %s", doc_id)
    flash("success|Documentul a fost sters.")
    return redirect(f"/acte/{tenant_id}")


# ══════════════════════════════════════════════
# FACTURI
# ══════════════════════════════════════════════

@app.route("/facturi", methods=["GET", "POST"])
@login_required
def facturi():
    if request.method == "POST":
        action = request.form.get("action", "create")
        if action == "pay":
            bill_id = request.form.get("bill_id")
            db_execute("UPDATE facturi SET status='Paid', paid_at=%s WHERE id=%s",
                       date.today().isoformat(), bill_id)
            flash("success|Factura marcata ca platita.")
            return redirect("/facturi")
        if action == "delete":
            bill_id = request.form.get("bill_id")
            db_execute("DELETE FROM facturi WHERE id = %s", bill_id)
            flash("success|Factura stearsa.")
            return redirect("/facturi")
        tenant_id   = request.form.get("tenant_id")
        amount      = request.form.get("amount")
        description = request.form.get("description", "Chirie lunara").strip()
        due_date    = request.form.get("due_date")
        if not tenant_id or not amount or not due_date:
            flash("error|Completeaza toate campurile obligatorii.")
            return redirect("/facturi")
        db_execute("INSERT INTO facturi (tenant_id, amount, description, due_date, status) VALUES (%s, %s, %s, %s, 'Unpaid')",
                   tenant_id, amount, description, due_date)
        t = db_execute("""
            SELECT t.email, t.first_name, a.number FROM tenants t
            JOIN apartments a ON t.apartment_id = a.id WHERE t.id = %s
        """, tenant_id)
        if t:
            send_email(t[0]["email"], f"Factura noua — {description}",
                f"Buna ziua {t[0]['first_name']},\n\nAi o factura noua de {amount} RON.\nData scadenta: {due_date}.\n\nRentManager")
        flash("success|Factura creata!")
        return redirect("/facturi")

    bills = db_execute("""
        SELECT f.id, f.amount, f.description, f.due_date, f.status, f.paid_at,
               t.id AS tenant_id, t.first_name, t.last_name, a.number
        FROM facturi f JOIN tenants t ON f.tenant_id = t.id
        JOIN apartments a ON t.apartment_id = a.id
        ORDER BY f.status ASC, f.due_date ASC
    """)
    tenants_list = db_execute("""
        SELECT t.id, t.first_name, t.last_name, a.number
        FROM tenants t JOIN apartments a ON t.apartment_id = a.id
    """)
    today        = date.today().isoformat()
    total_unpaid = sum(b["amount"] for b in bills if b["status"] == "Unpaid")
    total_paid   = sum(b["amount"] for b in bills if b["status"] == "Paid")
    return render_template("facturi.html",
        bills=bills, tenants=tenants_list,
        today=today, total_unpaid=total_unpaid, total_paid=total_paid,
        pdf_available=PDF_AVAILABLE)


@app.route("/facturi/pdf/<int:bill_id>")
@login_required
def export_factura_pdf(bill_id):
    if not PDF_AVAILABLE:
        flash("error|ReportLab nu este instalat.")
        return redirect("/facturi")
    bill = db_execute("""
        SELECT f.*, t.first_name, t.last_name, t.email, t.phone, a.number, a.address
        FROM facturi f JOIN tenants t ON f.tenant_id = t.id
        JOIN apartments a ON t.apartment_id = a.id WHERE f.id = %s
    """, bill_id)
    if not bill:
        abort(404)
    b = bill[0]
    from io import BytesIO
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=60, bottomMargin=50)
    styles = getSampleStyleSheet()
    story  = [Paragraph("FACTURA", styles["Title"]), Spacer(1, 20)]
    data = [
        ["Nr. Factura:",   f"#{b['id']:04d}"],
        ["Data emitere:",  str(b["created_at"])],
        ["Data scadenta:", str(b["due_date"])],
        ["Chirias:",       f"{b['first_name']} {b['last_name']}"],
        ["Email:",         b["email"] or "—"],
        ["Telefon:",       b["phone"] or "—"],
        ["Unitate:",       f"Nr. {b['number']} — {b['address']}"],
        ["Descriere:",     b["description"]],
        ["Suma:",          f"{b['amount']:.2f} RON"],
        ["Status:",        "PLATIT" if b["status"] == "Paid" else "NEPLATIT"],
    ]
    tbl = Table(data, colWidths=[150, 330])
    tbl.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",  (0, 0), (-1, -1), 11),
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.whitesmoke, colors.white]),
        ("GRID",      (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("FONTSIZE",  (1, 8), (1, 8), 14),
        ("FONTNAME",  (1, 8), (1, 8), "Helvetica-Bold"),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 30))
    story.append(Paragraph("<i>Generat automat de RentManager</i>", styles["Normal"]))
    doc.build(story)
    buf.seek(0)
    response = make_response(buf.read())
    response.headers["Content-Type"]        = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=factura_{bill_id:04d}.pdf"
    return response


# ══════════════════════════════════════════════
# MAINTENANCE
# ══════════════════════════════════════════════

@app.route("/maintenance", methods=["GET", "POST"])
@login_required
def maintenance():
    if request.method == "POST":
        action = request.form.get("action", "create")
        if action == "resolve":
            ticket_id = request.form.get("ticket_id")
            db_execute("UPDATE maintenance SET status='Resolved' WHERE id=%s", ticket_id)
            flash("success|Tichetul a fost rezolvat.")
            return redirect("/maintenance")
        apt_id   = request.form.get("apartment_id")
        desc     = request.form.get("description", "").strip()
        priority = request.form.get("priority", "Medium")
        if not apt_id or not desc:
            flash("error|Completeaza toate campurile.")
            return redirect("/maintenance")
        db_execute("INSERT INTO maintenance (apartment_id, description, priority, status) VALUES (%s, %s, %s, 'Open')",
                   apt_id, desc, priority)
        flash("success|Tichetul a fost trimis.")
        return redirect("/maintenance")
    tickets    = db_execute("""
        SELECT m.id, a.number, m.description, m.priority, m.status, m.created_at
        FROM maintenance m JOIN apartments a ON m.apartment_id = a.id
        ORDER BY CASE m.priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, m.id DESC
    """)
    apartments = db_execute("SELECT id, number FROM apartments")
    return render_template("maintenance.html", tickets=tickets, apartments=apartments)
