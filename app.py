# =============================================================================
# app.py — RentManager: Aplicatie web pentru gestionarea chiriilor
# Stack: Flask + PostgreSQL (psycopg2) + Flask-Login + Flask-Mail
# Fiecare ruta logeaza actiunile in tabelul activity_log (audit trail)
# =============================================================================

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

# ReportLab — librarie pt generare PDF; optional
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

load_dotenv()

# ── Initializare aplicatie Flask ──
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-schimba-asta!")

# Debug OFF in productie (se activeaza doar cu FLASK_ENV=development)
app.config["DEBUG"] = os.environ.get("FLASK_ENV") == "development"

# ── Configurare email (SMTP Gmail) ──
app.config["MAIL_SERVER"]         = "smtp.gmail.com"
app.config["MAIL_PORT"]           = 587
app.config["MAIL_USE_TLS"]        = True
app.config["MAIL_USERNAME"]       = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"]       = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME")
mail = Mail(app)

# ── Upload fisiere (acte, contracte) ──
UPLOAD_FOLDER      = os.path.join(os.path.dirname(__file__), "uploads")
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "doc", "docx"}
MAX_FILE_MB        = 10
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── Flask-Login: gestioneaza sesiunile utilizatorilor ──
login_manager = LoginManager(app)
login_manager.login_view    = "login"
login_manager.login_message = "error|Trebuie sa fii autentificat."


# =============================================================================
# CONEXIUNE BAZA DE DATE (PostgreSQL)
# =============================================================================

def get_db():
    """Deschide o conexiune noua la baza de date."""
    database_url = os.environ.get("DATABASE_URL", "")
    # Render.com da postgres:// dar psycopg2 cere postgresql://
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    conn = psycopg2.connect(database_url, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def db_execute(query, *args):
    """
    Executa un query SQL.
    SELECT  -> returneaza lista de dict-uri
    INSERT/UPDATE/DELETE -> returneaza None
    """
    query = query.replace("?", "%s")
    conn = get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, args if args else None)
                upper_query = query.strip().upper()
                if upper_query.startswith("SELECT") or " RETURNING " in upper_query:
                    return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return None


_schema_checked = False

def ensure_schema():
    """Aplica migratii mici necesare pentru instalari deja existente."""
    db_execute("ALTER TABLE IF EXISTS tenants ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE")
    db_execute("ALTER TABLE IF EXISTS tenants ADD COLUMN IF NOT EXISTS contract_start DATE")
    db_execute("ALTER TABLE IF EXISTS tenants ADD COLUMN IF NOT EXISTS contract_end DATE")
    db_execute("ALTER TABLE IF EXISTS tenants ADD COLUMN IF NOT EXISTS rent_amount REAL")
    db_execute("ALTER TABLE IF EXISTS maintenance ADD COLUMN IF NOT EXISTS cost REAL DEFAULT 0")
    db_execute("ALTER TABLE IF EXISTS facturi ADD COLUMN IF NOT EXISTS invoice_number TEXT")
    db_execute("ALTER TABLE IF EXISTS facturi ADD COLUMN IF NOT EXISTS apartment_id INTEGER REFERENCES apartments(id)")
    db_execute("""
        UPDATE facturi f
        SET apartment_id = t.apartment_id
        FROM tenants t
        WHERE f.tenant_id = t.id AND f.apartment_id IS NULL
    """)
    db_execute("CREATE INDEX IF NOT EXISTS idx_facturi_apartment_id ON facturi(apartment_id)")
    db_execute("CREATE INDEX IF NOT EXISTS idx_tenants_apartment_id ON tenants(apartment_id)")
    db_execute("CREATE INDEX IF NOT EXISTS idx_maintenance_apartment_id ON maintenance(apartment_id)")


@app.before_request
def run_schema_check():
    global _schema_checked
    if _schema_checked:
        return
    try:
        ensure_schema()
        _schema_checked = True
    except Exception as exc:
        app.logger.warning("Schema migration skipped: %s", exc)


# =============================================================================
# MODELUL USER (Flask-Login)
# =============================================================================

class User(UserMixin):
    """Clasa User — Flask-Login o foloseste pt sesiuni."""
    def __init__(self, id, username, email, role):
        self.id       = id
        self.username = username
        self.email    = email
        self.role     = role

@login_manager.user_loader
def load_user(user_id):
    """Callback Flask-Login: incarca userul din DB dupa ID-ul din sesiune."""
    rows = db_execute("SELECT * FROM users WHERE id = %s", int(user_id))
    if not rows:
        return None
    u = rows[0]
    return User(u["id"], u["username"], u["email"], u["role"])


# =============================================================================
# FUNCTII HELPER
# =============================================================================

def allowed_file(filename):
    """Verifica daca extensia fisierului e permisa."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def send_email(to, subject, body):
    """Trimite email prin Flask-Mail; esueaza silentios daca nu e configurat."""
    try:
        if app.config.get("MAIL_USERNAME"):
            msg = Message(subject, recipients=[to], body=body)
            mail.send(msg)
    except Exception:
        pass

def log_activity(action, category, details, target_type=None, target_id=None):
    """
    Inregistreaza o actiune in jurnalul de activitate (audit trail).
    Parametri:
        action      — tipul actiunii (create, update, delete, login, etc.)
        category    — grupa: auth, tenant, factura, maintenance, document, user
        details     — descriere in romana (ex: "A adaugat chirasul Ion Pop")
        target_type — entitatea afectata (tenant, factura, etc.)
        target_id   — ID-ul entitatii afectate
    """
    user_id = current_user.id if current_user.is_authenticated else None
    username = current_user.username if current_user.is_authenticated else "system"
    ip = request.remote_addr
    db_execute(
        """INSERT INTO activity_log
           (user_id, username, action, category, target_type, target_id, details, ip_address)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        user_id, username, action, category, target_type, target_id, details, ip
    )

@app.context_processor
def inject_globals():
    """Injecteaza variabile globale in toate template-urile."""
    return {"now": datetime.now(), "request": request}


# =============================================================================
# AUTENTIFICARE (Login / Logout)
# =============================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    """Pagina de login — autentificare cu username + parola."""
    if current_user.is_authenticated:
        return redirect("/")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("error|Completeaza toate campurile.")
            return redirect("/login")

        # Cauta userul in DB si verifica parola hash-uita
        rows = db_execute("SELECT * FROM users WHERE username = %s", username)
        if not rows or not check_password_hash(rows[0]["password_hash"], password):
            flash("error|Username sau parola gresita.")
            return redirect("/login")

        u = rows[0]
        login_user(User(u["id"], u["username"], u["email"], u["role"]),
                   remember=request.form.get("remember") == "on")

        # Logare actiune: login reusit
        log_activity("login", "auth", f"S-a autentificat in sistem")
        flash(f"success|Bun venit, {u['username']}!")
        return redirect(request.args.get("next") or "/")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Deconecteaza utilizatorul curent."""
    log_activity("logout", "auth", "S-a deconectat din sistem")
    logout_user()
    flash("success|Ai fost deconectat.")
    return redirect("/login")


# =============================================================================
# SETARI CONT (Schimbare parola + Creare utilizatori noi)
# =============================================================================

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Pagina setari: schimbare parola si adaugare utilizatori noi."""
    if request.method == "POST":
        action = request.form.get("action")

        # ── Schimbare parola ──
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
            log_activity("change_password", "user", "Si-a schimbat parola")
            flash("success|Parola schimbata!")
            return redirect("/settings")

        # ── Creare utilizator nou ──
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
            log_activity("create", "user", f"A creat contul {uname}", "user")
            flash(f"success|Utilizatorul {uname} creat.")
            return redirect("/settings")

    users_list = db_execute("SELECT id, username, email, role, created_at FROM users")
    return render_template("settings.html", users_list=users_list)


# =============================================================================
# DASHBOARD (Pagina principala)
# =============================================================================

@app.route("/")
@login_required
def index():
    """Dashboard-ul principal — statistici, grafic, alerte, unitati."""
    # Interogare complexa: apartamente + chirias activ + restante/tichete pe unitate
    apartments = db_execute("""
        SELECT a.id, a.number, a.address, a.status,
               t.first_name, t.last_name, t.id AS tenant_id,
               t.contract_end,
               (SELECT COUNT(*) FROM facturi f WHERE f.apartment_id = a.id AND f.status = 'Unpaid') AS unpaid_count,
               (SELECT COALESCE(SUM(f2.amount), 0) FROM facturi f2 WHERE f2.apartment_id = a.id AND f2.status = 'Unpaid') AS unpaid_amount,
               (SELECT COUNT(*) FROM maintenance m WHERE m.apartment_id = a.id AND m.status != 'Resolved') AS open_maint
        FROM apartments a
        LEFT JOIN tenants t ON a.id = t.apartment_id AND t.is_active = TRUE
        ORDER BY a.number
    """)
    total    = len(apartments)
    occupied = sum(1 for a in apartments if a["status"] == "Rented")
    vacant   = total - occupied

    # Statistici globale
    open_tickets = db_execute("SELECT COUNT(*) AS cnt FROM maintenance WHERE status != 'Resolved'")[0]["cnt"]
    unpaid_data  = db_execute("SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total_ron FROM facturi WHERE status = 'Unpaid'")[0]
    unpaid_bills = unpaid_data["cnt"]
    unpaid_ron   = unpaid_data["total_ron"]

    # Venit luna curenta (facturi platite)
    this_month = date.today().strftime("%Y-%m")
    revenue = db_execute(
        "SELECT COALESCE(SUM(amount), 0) AS total FROM facturi WHERE status='Paid' AND paid_at::text LIKE %s",
        f"{this_month}%"
    )[0]["total"]

    # Ultimele 5 facturi (pt lista activitate recenta)
    recent = db_execute("""
        SELECT f.amount, f.status, f.due_date, t.first_name, t.last_name
        FROM facturi f JOIN tenants t ON f.tenant_id = t.id
        ORDER BY f.id DESC LIMIT 5
    """)

    # Alerte contracte care expira in 30 zile
    expiring = db_execute("""
        SELECT t.first_name, t.last_name, t.contract_end, a.number
        FROM tenants t JOIN apartments a ON t.apartment_id = a.id
        WHERE t.is_active = TRUE AND t.contract_end IS NOT NULL
          AND t.contract_end BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '30 days'
        ORDER BY t.contract_end
    """)

    # Date grafic: venit vs cheltuieli ultimele 6 luni
    chart_data = db_execute("""
        SELECT months.m AS month,
               COALESCE((SELECT SUM(f.amount) FROM facturi f WHERE f.status='Paid'
                         AND TO_CHAR(f.paid_at, 'YYYY-MM') = months.m), 0) AS income,
               COALESCE((SELECT SUM(m.cost) FROM maintenance m WHERE m.status='Resolved'
                         AND TO_CHAR(m.created_at, 'YYYY-MM') = months.m), 0) AS expenses
        FROM (
            SELECT TO_CHAR(CURRENT_DATE - (n || ' months')::interval, 'YYYY-MM') AS m
            FROM generate_series(5, 0, -1) AS n
        ) months
        ORDER BY months.m
    """)
    chart_labels = [r["month"] for r in chart_data]
    chart_income = [float(r["income"]) for r in chart_data]
    chart_expenses = [float(r["expenses"]) for r in chart_data]

    # Profit = venit - cheltuieli mentenanta luna curenta
    maint_costs = db_execute(
        "SELECT COALESCE(SUM(cost), 0) AS total FROM maintenance WHERE status='Resolved' AND TO_CHAR(created_at, 'YYYY-MM') = %s",
        this_month
    )[0]["total"]
    profit = float(revenue) - float(maint_costs)

    return render_template("index.html",
        apartments=apartments, total=total, occupied=occupied,
        vacant=vacant, open_tickets=open_tickets, unpaid_bills=unpaid_bills,
        unpaid_ron=unpaid_ron, revenue=revenue, recent=recent,
        expiring=expiring, chart_labels=chart_labels,
        chart_income=chart_income, chart_expenses=chart_expenses,
        profit=profit
    )


# =============================================================================
# APARTAMENTE (Detalii + Adaugare unitati)
# =============================================================================

@app.route("/apartments/add", methods=["GET", "POST"])
@login_required
def add_apartment():
    """Formular adaugare apartament nou din aplicatie."""
    if request.method == "POST":
        number = request.form.get("number", "").strip()
        address = request.form.get("address", "").strip()
        if not number or not address:
            flash("error|Completeaza numarul unitatii si adresa.")
            return redirect("/apartments/add")

        existing = db_execute("""
            SELECT id FROM apartments
            WHERE LOWER(number) = LOWER(%s) AND LOWER(address) = LOWER(%s)
            LIMIT 1
        """, number, address)
        if existing:
            flash("error|Exista deja un apartament cu acest numar la adresa introdusa.")
            return redirect("/apartments/add")

        inserted = db_execute("""
            INSERT INTO apartments (number, address, status)
            VALUES (%s, %s, 'Available')
            RETURNING id
        """, number, address)
        apt_id = inserted[0]["id"] if inserted else None
        log_activity("create", "apartment", f"A adaugat Unitatea {number} - {address}", "apartment", apt_id)
        flash(f"success|Apartamentul {number} a fost adaugat.")
        return redirect(f"/apartments/{apt_id}" if apt_id else "/")

    return render_template("add_apartment.html")


@app.route("/apartments/<int:apt_id>")
@login_required
def apartment_detail(apt_id):
    """Pagina detalii apartament: chiriasi, facturi si tichete istorice."""
    rows = db_execute("SELECT * FROM apartments WHERE id = %s", apt_id)
    if not rows:
        flash("error|Apartamentul nu a fost gasit.")
        return redirect("/")
    apartment = rows[0]

    tenants_history = db_execute("""
        SELECT DISTINCT t.id, t.first_name, t.last_name, t.email, t.phone,
               t.is_active, t.contract_start, t.contract_end, t.rent_amount, t.created_at
        FROM tenants t
        LEFT JOIN facturi f ON f.tenant_id = t.id
        WHERE t.apartment_id = %s OR f.apartment_id = %s
        ORDER BY t.is_active DESC, t.created_at DESC, t.id DESC
    """, apt_id, apt_id)

    bills = db_execute("""
        SELECT f.id, f.amount, f.description, f.due_date, f.status, f.paid_at,
               f.created_at, f.invoice_number,
               t.id AS tenant_id, t.first_name, t.last_name, t.is_active
        FROM facturi f
        LEFT JOIN tenants t ON f.tenant_id = t.id
        WHERE f.apartment_id = %s
        ORDER BY f.status ASC, f.due_date DESC, f.id DESC
    """, apt_id)

    tickets = db_execute("""
        SELECT id, description, priority, status, created_at, cost
        FROM maintenance
        WHERE apartment_id = %s
        ORDER BY CASE status WHEN 'Open' THEN 1 WHEN 'In Progress' THEN 2 ELSE 3 END,
                 created_at DESC, id DESC
    """, apt_id)

    active_tenant = next((t for t in tenants_history if t["is_active"]), None)
    total_unpaid = sum(float(b["amount"] or 0) for b in bills if b["status"] == "Unpaid")
    total_paid = sum(float(b["amount"] or 0) for b in bills if b["status"] == "Paid")
    open_tickets = sum(1 for t in tickets if t["status"] != "Resolved")
    maintenance_cost = sum(float(t["cost"] or 0) for t in tickets if t["status"] == "Resolved")

    return render_template("apartment_detail.html",
        apartment=apartment,
        active_tenant=active_tenant,
        tenants_history=tenants_history,
        bills=bills,
        tickets=tickets,
        total_unpaid=total_unpaid,
        total_paid=total_paid,
        open_tickets=open_tickets,
        maintenance_cost=maintenance_cost
    )


# =============================================================================
# GENERARE FACTURI IN MASA (Bulk Invoice)
# =============================================================================

@app.route("/bulk_invoice", methods=["POST"])
@login_required
def bulk_invoice():
    """Genereaza facturi automat pt toti chiriasii activi cu chiria setata."""
    tenants_with_rent = db_execute("""
        SELECT t.id, t.first_name, t.last_name, t.rent_amount, t.email, t.apartment_id, a.number
        FROM tenants t JOIN apartments a ON t.apartment_id = a.id
        WHERE t.is_active = TRUE AND t.rent_amount IS NOT NULL AND t.rent_amount > 0
    """)
    if not tenants_with_rent:
        flash("error|Niciun chirias nu are chiria lunara setata. Editeaza chiriasii mai intai.")
        return redirect("/")
    count = 0
    month_name = date.today().strftime("%B %Y")
    year = date.today().year
    for t in tenants_with_rent:
        # Verifica daca factura exista deja luna asta pt acest chirias
        existing = db_execute(
            "SELECT id FROM facturi WHERE tenant_id = %s AND TO_CHAR(created_at, 'YYYY-MM') = %s",
            t["id"], date.today().strftime("%Y-%m")
        )
        if existing:
            continue
        last = db_execute("SELECT COUNT(*) AS cnt FROM facturi WHERE EXTRACT(YEAR FROM created_at) = %s", year)[0]["cnt"]
        invoice_number = f"RM-{year}-{last + 1:03d}"
        due_date = date.today().replace(day=28).isoformat() if date.today().day <= 28 else date.today().isoformat()
        db_execute(
            "INSERT INTO facturi (tenant_id, apartment_id, amount, description, due_date, status, invoice_number) VALUES (%s, %s, %s, %s, %s, 'Unpaid', %s)",
            t["id"], t["apartment_id"], t["rent_amount"], f"Chirie lunara - {month_name}", due_date, invoice_number
        )
        send_email(t["email"], f"Factura noua {invoice_number}",
            f"Buna ziua {t['first_name']},\n\nAi o factura noua ({invoice_number}) de {t['rent_amount']} RON.\nData scadenta: {due_date}.\n\nRentManager")
        count += 1

    if count > 0:
        log_activity("bulk_create", "factura", f"A generat {count} facturi automat pentru {month_name}")
        flash(f"success|{count} facturi generate automat pentru luna curenta!")
    else:
        flash("error|Toate facturile pe luna asta au fost deja generate.")
    return redirect("/")


# =============================================================================
# CHIRIASI (CRUD)
# =============================================================================

@app.route("/tenants")
@login_required
def tenants():
    """Lista chiriasi — cu cautare si filtru activi/inactivi."""
    search = request.args.get("q", "").strip()
    show_inactive = request.args.get("show_inactive") == "1"

    # Query dinamic cu filtre optionale
    base = """
        SELECT t.id, t.first_name, t.last_name, t.email, t.phone,
               t.is_active, t.contract_end, t.rent_amount,
               a.number, a.address, a.id AS apartment_id,
               (SELECT COUNT(*) FROM facturi f WHERE f.tenant_id = t.id AND f.status = 'Unpaid') AS unpaid,
               (SELECT COUNT(*) FROM acte ac WHERE ac.tenant_id = t.id) AS nr_acte
        FROM tenants t JOIN apartments a ON t.apartment_id = a.id
    """
    where_clauses = []
    params = []
    if not show_inactive:
        where_clauses.append("t.is_active = TRUE")
    if search:
        like = f"%{search}%"
        where_clauses.append("(t.first_name ILIKE %s OR t.last_name ILIKE %s OR t.email ILIKE %s OR a.number ILIKE %s)")
        params.extend([like, like, like, like])
    if where_clauses:
        base += " WHERE " + " AND ".join(where_clauses)
    base += " ORDER BY t.is_active DESC, t.last_name"
    all_tenants = db_execute(base, *params)
    return render_template("tenants.html", tenants=all_tenants, search=search, show_inactive=show_inactive)


@app.route("/add_tenant", methods=["GET", "POST"])
@login_required
def add_tenant():
    """Formular adaugare chirias nou + alocare apartament."""
    if request.method == "POST":
        fname  = request.form.get("first_name", "").strip()
        lname  = request.form.get("last_name", "").strip()
        email  = request.form.get("email", "").strip()
        phone  = request.form.get("phone", "").strip()
        apt_id = request.form.get("apartment_id")
        contract_start = request.form.get("contract_start") or None
        contract_end   = request.form.get("contract_end") or None
        rent_amount    = request.form.get("rent_amount") or None
        if not fname or not lname or not email or not apt_id:
            flash("error|Completeaza toate campurile obligatorii.")
            return redirect("/add_tenant")

        # Verifica daca apartamentul e liber
        apt_check = db_execute("SELECT status FROM apartments WHERE id = %s", apt_id)
        if apt_check and apt_check[0]["status"] != "Available":
            flash("error|Aceasta unitate este deja ocupata.")
            return redirect("/add_tenant")

        result = db_execute(
            "INSERT INTO tenants (first_name, last_name, email, phone, apartment_id, contract_start, contract_end, rent_amount) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            fname, lname, email, phone, apt_id, contract_start, contract_end, rent_amount
        )
        # Marcheaza apartamentul ca inchiriat
        db_execute("UPDATE apartments SET status = 'Rented' WHERE id = %s", apt_id)
        apt = db_execute("SELECT number, address FROM apartments WHERE id = %s", apt_id)[0]

        # Trimite email de bun venit
        send_email(email, "Bun venit la RentManager!",
            f"Buna ziua {fname},\n\nContractul tau pentru Unitatea {apt['number']} ({apt['address']}) a fost activat.\n\nEchipa RentManager")

        # Ia ID-ul noului chirias pt redirect si log
        new_t = db_execute("SELECT id FROM tenants WHERE first_name=%s AND last_name=%s AND apartment_id=%s ORDER BY id DESC LIMIT 1", fname, lname, apt_id)
        new_id = new_t[0]["id"] if new_t else None
        log_activity("create", "tenant", f"A adaugat chirasul {fname} {lname} in Unitatea {apt['number']}", "tenant", new_id)

        flash(f"success|Chiriasul {fname} {lname} a fost adaugat! Incarca actele de contract.")
        if new_t:
            return redirect(f"/acte/{new_t[0]['id']}")
        return redirect("/tenants")

    preselect = request.args.get("apt")
    available_apts = db_execute("SELECT * FROM apartments WHERE status = 'Available'")
    return render_template("add_tenant.html", available_apts=available_apts, preselect=preselect)


@app.route("/delete_tenant", methods=["POST"])
@login_required
def delete_tenant():
    """Dezactiveaza chirias (soft delete) — pastreaza istoricul."""
    tenant_id = request.form.get("tenant_id")
    rows = db_execute("SELECT * FROM tenants WHERE id = %s", tenant_id)
    if not rows:
        flash("error|Chiriasul nu a fost gasit.")
        return redirect("/tenants")
    t      = rows[0]
    apt_id = t["apartment_id"]
    name   = f"{t['first_name']} {t['last_name']}"

    # Nu poti dezactiva daca are facturi neplatite
    unpaid = db_execute("SELECT COUNT(*) as cnt FROM facturi WHERE tenant_id = %s AND status = 'Unpaid'", tenant_id)[0]["cnt"]
    if unpaid > 0:
        flash("error|Nu poți dezactiva un chiriaș cu facturi neplătite. Șterge sau marchează-le ca plătite mai întâi.")
        return redirect("/tenants")

    # Soft delete + elibereaza apartamentul
    db_execute("UPDATE tenants SET is_active = FALSE WHERE id = %s", tenant_id)
    db_execute("UPDATE apartments SET status = 'Available' WHERE id = %s", apt_id)
    log_activity("deactivate", "tenant", f"A dezactivat chirasul {name}", "tenant", int(tenant_id))
    flash(f"success|{name} dezactivat. Apartamentul este disponibil. Istoricul a fost pastrat.")
    return redirect("/tenants")


@app.route("/edit_tenant/<int:tenant_id>", methods=["GET", "POST"])
@login_required
def edit_tenant(tenant_id):
    """Formular editare chirias — date personale + mutare apartament."""
    tenant = db_execute("""
        SELECT t.*, a.number, a.address FROM tenants t
        JOIN apartments a ON t.apartment_id = a.id WHERE t.id = %s
    """, tenant_id)
    if not tenant:
        flash("error|Chiriasul nu a fost gasit.")
        return redirect("/tenants")
    t = tenant[0]
    if request.method == "POST":
        fname  = request.form.get("first_name", "").strip()
        lname  = request.form.get("last_name", "").strip()
        email  = request.form.get("email", "").strip()
        phone  = request.form.get("phone", "").strip()
        contract_start = request.form.get("contract_start") or None
        contract_end   = request.form.get("contract_end") or None
        rent_amount    = request.form.get("rent_amount") or None
        new_apt_id     = request.form.get("apartment_id")
        if not fname or not lname or not email:
            flash("error|Completeaza toate campurile obligatorii.")
            return redirect(f"/edit_tenant/{tenant_id}")

        # Gestionare mutare apartament
        if new_apt_id and int(new_apt_id) != t["apartment_id"]:
            db_execute("UPDATE apartments SET status = 'Available' WHERE id = %s", t["apartment_id"])
            db_execute("UPDATE apartments SET status = 'Rented' WHERE id = %s", new_apt_id)
        else:
            new_apt_id = t["apartment_id"]

        db_execute("""
            UPDATE tenants SET first_name=%s, last_name=%s, email=%s, phone=%s,
                apartment_id=%s, contract_start=%s, contract_end=%s, rent_amount=%s
            WHERE id = %s
        """, fname, lname, email, phone, new_apt_id, contract_start, contract_end, rent_amount, tenant_id)
        log_activity("update", "tenant", f"A editat chirasul {fname} {lname}", "tenant", tenant_id)
        flash(f"success|Chiriasul {fname} {lname} a fost actualizat!")
        return redirect("/tenants")

    available_apts = db_execute("SELECT * FROM apartments WHERE status = 'Available' OR id = %s", t["apartment_id"])
    return render_template("edit_tenant.html", tenant=t, available_apts=available_apts)


@app.route("/edit_factura/<int:bill_id>", methods=["GET", "POST"])
@login_required
def edit_factura(bill_id):
    """Formular editare factura — suma, descriere, data scadenta."""
    bill = db_execute("""
        SELECT f.*, t.first_name, t.last_name, a.number
        FROM facturi f JOIN tenants t ON f.tenant_id = t.id
        LEFT JOIN apartments a ON f.apartment_id = a.id WHERE f.id = %s
    """, bill_id)
    if not bill:
        flash("error|Factura nu a fost gasita.")
        return redirect("/facturi")
    b = bill[0]
    if request.method == "POST":
        amount      = request.form.get("amount")
        description = request.form.get("description", "").strip()
        due_date    = request.form.get("due_date")
        if not amount or not due_date:
            flash("error|Completeaza toate campurile obligatorii.")
            return redirect(f"/edit_factura/{bill_id}")
        if float(amount) < 0:
            flash("error|Suma nu poate fi negativa.")
            return redirect(f"/edit_factura/{bill_id}")
        db_execute("UPDATE facturi SET amount=%s, description=%s, due_date=%s WHERE id=%s",
                   amount, description, due_date, bill_id)
        log_activity("update", "factura", f"A editat factura #{bill_id} ({amount} RON)", "factura", bill_id)
        flash("success|Factura actualizata!")
        return redirect("/facturi")
    return render_template("edit_factura.html", bill=b)


# =============================================================================
# ACTE / DOCUMENTE (Upload, Download, Stergere)
# =============================================================================

@app.route("/acte/<int:tenant_id>")
@login_required
def acte(tenant_id):
    """Lista documente (acte) pt un chirias."""
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
    """Incarca un document (contract, act, etc.) pt un chirias."""
    doc_type = request.form.get("doc_type", "Altele").strip()
    notes    = request.form.get("notes", "").strip()
    if "file" not in request.files or request.files["file"].filename == "":
        flash("error|Niciun fisier selectat.")
        return redirect(f"/acte/{tenant_id}")
    file = request.files["file"]
    if not allowed_file(file.filename):
        flash("error|Tip de fisier nepermis. Acceptam: PDF, JPG, PNG, DOC, DOCX.")
        return redirect(f"/acte/{tenant_id}")

    # Verificare dimensiune fisier
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

    # Logare: cine a incarcat ce document
    t_info = db_execute("SELECT first_name, last_name FROM tenants WHERE id = %s", tenant_id)
    t_name = f"{t_info[0]['first_name']} {t_info[0]['last_name']}" if t_info else f"#{tenant_id}"
    log_activity("upload", "document", f"A incarcat '{file.filename}' ({doc_type}) pt {t_name}", "document", tenant_id)
    flash("success|Documentul a fost incarcat!")
    return redirect(f"/acte/{tenant_id}")


@app.route("/acte/download/<int:doc_id>")
@login_required
def download_act(doc_id):
    """Descarca un document — logeaza descarcarea in audit trail."""
    doc = db_execute("SELECT * FROM acte WHERE id = %s", doc_id)
    if not doc:
        abort(404)
    d = doc[0]
    # Logare: cine a descarcat documentul
    t_info = db_execute("SELECT first_name, last_name FROM tenants WHERE id = %s", d["tenant_id"])
    t_name = f"{t_info[0]['first_name']} {t_info[0]['last_name']}" if t_info else f"#{d['tenant_id']}"
    log_activity("download", "document", f"A descarcat '{d['original_name']}' al lui {t_name}", "document", doc_id)
    return send_from_directory(UPLOAD_FOLDER, d["filename"],
                               as_attachment=True, download_name=d["original_name"])


@app.route("/acte/delete/<int:doc_id>", methods=["POST"])
@login_required
def delete_act(doc_id):
    """Sterge un document — din DB si de pe disc."""
    doc = db_execute("SELECT * FROM acte WHERE id = %s", doc_id)
    if not doc:
        flash("error|Documentul nu a fost gasit.")
        return redirect("/tenants")
    d = doc[0]
    tenant_id = d["tenant_id"]

    # Logare inainte de stergere (sa avem datele inca)
    t_info = db_execute("SELECT first_name, last_name FROM tenants WHERE id = %s", tenant_id)
    t_name = f"{t_info[0]['first_name']} {t_info[0]['last_name']}" if t_info else f"#{tenant_id}"
    log_activity("delete", "document", f"A sters documentul '{d['original_name']}' al lui {t_name}", "document", doc_id)

    fpath = os.path.join(UPLOAD_FOLDER, d["filename"])
    if os.path.exists(fpath):
        os.remove(fpath)
    db_execute("DELETE FROM acte WHERE id = %s", doc_id)
    flash("success|Documentul a fost sters.")
    return redirect(f"/acte/{tenant_id}")


# =============================================================================
# FACTURI (Creare, Plata, Stergere, Export PDF)
# =============================================================================

@app.route("/facturi", methods=["GET", "POST"])
@login_required
def facturi():
    """Gestionare facturi: creare, marcare platita, stergere, filtrare."""
    if request.method == "POST":
        action = request.form.get("action", "create")
        return_to = request.form.get("return_to") or "/facturi"

        # ── Marcare factura ca platita ──
        if action == "pay":
            bill_id = request.form.get("bill_id")
            db_execute("UPDATE facturi SET status='Paid', paid_at=%s WHERE id=%s",
                       date.today().isoformat(), bill_id)
            log_activity("pay", "factura", f"A marcat factura #{bill_id} ca platita", "factura", int(bill_id))
            flash("success|Factura marcata ca platita.")
            return redirect(return_to)

        # ── Stergere factura ──
        if action == "delete":
            bill_id = request.form.get("bill_id")
            log_activity("delete", "factura", f"A sters factura #{bill_id}", "factura", int(bill_id))
            db_execute("DELETE FROM facturi WHERE id = %s", bill_id)
            flash("success|Factura stearsa.")
            return redirect(return_to)

        # ── Creare factura noua ──
        tenant_id   = request.form.get("tenant_id")
        amount      = request.form.get("amount")
        description = request.form.get("description", "Chirie lunara").strip()
        due_date    = request.form.get("due_date")
        if not tenant_id or not amount or not due_date:
            flash("error|Completeaza toate campurile obligatorii.")
            return redirect(return_to)
        if float(amount) < 0:
            flash("error|Suma nu poate fi negativa.")
            return redirect(return_to)
        if due_date < date.today().isoformat():
            flash("error|Data scadentă nu poate fi în trecut.")
            return redirect(return_to)

        # Generare numar factura secvential (RM-2026-001)
        year = date.today().year
        last = db_execute("SELECT COUNT(*) AS cnt FROM facturi WHERE EXTRACT(YEAR FROM created_at) = %s", year)[0]["cnt"]
        invoice_number = f"RM-{year}-{last + 1:03d}"
        t = db_execute("""
            SELECT t.email, t.first_name, t.apartment_id, a.number FROM tenants t
            JOIN apartments a ON t.apartment_id = a.id WHERE t.id = %s
        """, tenant_id)
        if not t:
            flash("error|Chiriasul selectat nu a fost gasit.")
            return redirect(return_to)

        db_execute("INSERT INTO facturi (tenant_id, apartment_id, amount, description, due_date, status, invoice_number) VALUES (%s, %s, %s, %s, %s, 'Unpaid', %s)",
                   tenant_id, t[0]["apartment_id"], amount, description, due_date, invoice_number)

        # Trimite email chiriasuluinotificare
        send_email(t[0]["email"], f"Factura noua {invoice_number} - {description}",
            f"Buna ziua {t[0]['first_name']},\n\nAi o factura noua ({invoice_number}) de {amount} RON.\nData scadenta: {due_date}.\n\nRentManager")

        log_activity("create", "factura", f"A creat factura {invoice_number} de {amount} RON", "factura")
        flash(f"success|Factura {invoice_number} creata!")
        return redirect(return_to)

    # GET — lista facturi cu filtre
    status_filter = request.args.get("status", "all")
    preselect_tenant = request.args.get("tenant")
    base_query = """
        SELECT f.id, f.amount, f.description, f.due_date, f.status, f.paid_at, f.invoice_number,
               t.id AS tenant_id, t.first_name, t.last_name, a.number
        FROM facturi f JOIN tenants t ON f.tenant_id = t.id
        LEFT JOIN apartments a ON f.apartment_id = a.id
    """
    if status_filter == "unpaid":
        base_query += " WHERE f.status = 'Unpaid'"
    elif status_filter == "paid":
        base_query += " WHERE f.status = 'Paid'"
    base_query += " ORDER BY f.status ASC, f.due_date ASC"
    bills = db_execute(base_query)

    tenants_list = db_execute("""
        SELECT t.id, t.first_name, t.last_name, a.number
        FROM tenants t JOIN apartments a ON t.apartment_id = a.id
        WHERE t.is_active = TRUE
    """)
    today        = date.today().isoformat()
    total_unpaid = db_execute("SELECT COALESCE(SUM(amount), 0) AS t FROM facturi WHERE status = 'Unpaid'")[0]["t"]
    total_paid   = db_execute("SELECT COALESCE(SUM(amount), 0) AS t FROM facturi WHERE status = 'Paid'")[0]["t"]
    return render_template("facturi.html",
        bills=bills, tenants=tenants_list,
        today=today, total_unpaid=total_unpaid, total_paid=total_paid,
        pdf_available=PDF_AVAILABLE, status_filter=status_filter,
        preselect_tenant=preselect_tenant)


@app.route("/facturi/pdf/<int:bill_id>")
@login_required
def export_factura_pdf(bill_id):
    """Genereaza PDF pt o factura — logeaza descarcarea."""
    if not PDF_AVAILABLE:
        flash("error|ReportLab nu este instalat.")
        return redirect("/facturi")
    bill = db_execute("""
        SELECT f.*, t.first_name, t.last_name, t.email, t.phone, a.number, a.address
        FROM facturi f JOIN tenants t ON f.tenant_id = t.id
        LEFT JOIN apartments a ON f.apartment_id = a.id WHERE f.id = %s
    """, bill_id)
    if not bill:
        abort(404)
    b = bill[0]

    # Logare descarcare PDF factura
    log_activity("download", "factura",
                 f"A descarcat PDF factura #{bill_id} ({b['first_name']} {b['last_name']}, {b['amount']} RON)",
                 "factura", bill_id)

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


# =============================================================================
# MENTENANTA (Tichete de reparatii)
# =============================================================================

@app.route("/maintenance", methods=["GET", "POST"])
@login_required
def maintenance():
    """Gestionare tichete mentenanta: creare, preluare, rezolvare."""
    if request.method == "POST":
        action = request.form.get("action", "create")
        return_to = request.form.get("return_to") or "/maintenance"

        # ── Rezolvare tichet ──
        if action == "resolve":
            ticket_id = request.form.get("ticket_id")
            cost = request.form.get("cost", 0)
            db_execute("UPDATE maintenance SET status='Resolved', cost=%s WHERE id=%s", cost or 0, ticket_id)
            log_activity("resolve", "maintenance", f"A rezolvat tichetul #{ticket_id} (cost: {cost} RON)", "maintenance", int(ticket_id))
            flash("success|Tichetul a fost rezolvat.")
            return redirect(return_to)

        # ── Preluare tichet (In Progress) ──
        if action == "in_progress":
            ticket_id = request.form.get("ticket_id")
            db_execute("UPDATE maintenance SET status='In Progress' WHERE id=%s", ticket_id)
            log_activity("in_progress", "maintenance", f"A preluat tichetul #{ticket_id}", "maintenance", int(ticket_id))
            flash("success|Tichetul a fost preluat.")
            return redirect(return_to)

        # ── Actualizare cost ──
        if action == "update_cost":
            ticket_id = request.form.get("ticket_id")
            cost = request.form.get("cost", 0)
            db_execute("UPDATE maintenance SET cost=%s WHERE id=%s", cost or 0, ticket_id)
            log_activity("update_cost", "maintenance", f"A actualizat costul tichetului #{ticket_id} la {cost} RON", "maintenance", int(ticket_id))
            flash("success|Costul a fost actualizat cu succes.")
            return redirect(return_to)

        # ── Creare tichet nou ──
        apt_id   = request.form.get("apartment_id")
        desc     = request.form.get("description", "").strip()
        priority = request.form.get("priority", "Medium")
        if not apt_id or not desc:
            flash("error|Completeaza toate campurile.")
            return redirect(return_to)
        db_execute("INSERT INTO maintenance (apartment_id, description, priority, status) VALUES (%s, %s, %s, 'Open')",
                   apt_id, desc, priority)
        apt = db_execute("SELECT number FROM apartments WHERE id = %s", apt_id)
        apt_nr = apt[0]["number"] if apt else apt_id
        log_activity("create", "maintenance", f"A creat tichet mentenanta pt Unitatea {apt_nr}: {desc[:60]}", "maintenance")
        flash("success|Tichetul a fost trimis.")
        return redirect(return_to)

    # GET — lista tichete sortate: Open > In Progress > Resolved, apoi dupa prioritate
    tickets    = db_execute("""
        SELECT m.id, a.number, m.description, m.priority, m.status, m.created_at, m.cost
        FROM maintenance m JOIN apartments a ON m.apartment_id = a.id
        ORDER BY CASE m.status WHEN 'Open' THEN 1 WHEN 'In Progress' THEN 2 ELSE 3 END,
                 CASE m.priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, m.id DESC
    """)
    apartments = db_execute("SELECT id, number FROM apartments")
    preselect = request.args.get("apt")
    return render_template("maintenance.html", tickets=tickets, apartments=apartments, preselect=preselect)


# =============================================================================
# JURNAL ACTIVITATE / AUDIT TRAIL
# =============================================================================

@app.route("/activity-log")
@login_required
def activity_log():
    """Pagina Audit Trail — jurnal complet cu filtre si paginare."""
    category = request.args.get("category", "all")
    search   = request.args.get("q", "").strip()
    page     = max(1, int(request.args.get("page", 1)))
    per_page = 25

    # Construire query dinamic cu filtre
    base = "SELECT * FROM activity_log"
    where_clauses = []
    params = []

    if category != "all":
        where_clauses.append("category = %s")
        params.append(category)
    if search:
        where_clauses.append("(details ILIKE %s OR username ILIKE %s)")
        like = f"%{search}%"
        params.extend([like, like])

    if where_clauses:
        base += " WHERE " + " AND ".join(where_clauses)

    # Total pt paginare
    count_q = base.replace("SELECT *", "SELECT COUNT(*) AS cnt", 1)
    total = db_execute(count_q, *params)[0]["cnt"]

    # Query paginat, ordonat descrescator
    base += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
    params.extend([per_page, (page - 1) * per_page])
    logs = db_execute(base, *params)

    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template("activity_log.html",
        logs=logs, category=category, search=search,
        page=page, total_pages=total_pages, total=total)
