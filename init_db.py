"""
init_db.py — Script de initializare a bazei de date PostgreSQL
Ruleaza o singura data dupa ce ai setat DATABASE_URL in .env:
    python init_db.py
Creeaza toate tabelele necesare si un cont admin default.
"""
import os
import psycopg2
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL", "")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if not DATABASE_URL:
    print("❌ DATABASE_URL nu este setat in .env!")
    exit(1)

conn = psycopg2.connect(DATABASE_URL)
conn.autocommit = True
c = conn.cursor()

print("Creez tabelele...")

# Tabelul users — conturile de admin ale aplicatiei
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    created_at    DATE DEFAULT CURRENT_DATE
);
""")

# Tabelul apartments — unitatile imobiliare gestionate
c.execute("""
CREATE TABLE IF NOT EXISTS apartments (
    id      SERIAL PRIMARY KEY,
    number  TEXT NOT NULL,
    address TEXT NOT NULL,
    status  TEXT NOT NULL DEFAULT 'Available'
);
""")

# Tabelul tenants — chiriasii (legati de un apartament prin FK)
c.execute("""
CREATE TABLE IF NOT EXISTS tenants (
    id           SERIAL PRIMARY KEY,
    first_name   TEXT NOT NULL,
    last_name    TEXT NOT NULL,
    email        TEXT NOT NULL,
    phone        TEXT,
    apartment_id INTEGER NOT NULL REFERENCES apartments(id),
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    contract_start DATE,
    contract_end DATE,
    rent_amount  REAL,
    created_at   DATE DEFAULT CURRENT_DATE
);
""")

# Tabelul maintenance — tichete de mentenanta/reparatii
c.execute("""
CREATE TABLE IF NOT EXISTS maintenance (
    id           SERIAL PRIMARY KEY,
    apartment_id INTEGER NOT NULL REFERENCES apartments(id),
    description  TEXT NOT NULL,
    priority     TEXT NOT NULL DEFAULT 'Medium',
    status       TEXT NOT NULL DEFAULT 'Open',
    cost         REAL DEFAULT 0,
    created_at   DATE DEFAULT CURRENT_DATE
);
""")

# Tabelul acte — documente incarcate (contracte, acte, etc.)
c.execute("""
CREATE TABLE IF NOT EXISTS acte (
    id            SERIAL PRIMARY KEY,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id),
    doc_type      TEXT NOT NULL DEFAULT 'Altele',
    filename      TEXT NOT NULL,
    original_name TEXT NOT NULL,
    notes         TEXT,
    uploaded_at   DATE DEFAULT CURRENT_DATE
);
""")

# Tabelul facturi — facturile emise catre chiriasi
c.execute("""
CREATE TABLE IF NOT EXISTS facturi (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
    apartment_id INTEGER REFERENCES apartments(id),
    amount      REAL NOT NULL,
    description TEXT NOT NULL DEFAULT 'Chirie lunara',
    due_date    DATE NOT NULL,
    status      TEXT NOT NULL DEFAULT 'Unpaid',
    paid_at     DATE,
    invoice_number TEXT,
    created_at  DATE DEFAULT CURRENT_DATE
);
""")

# Migratii mici pentru baze existente create cu versiuni mai vechi
c.execute("ALTER TABLE IF EXISTS tenants ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;")
c.execute("ALTER TABLE IF EXISTS tenants ADD COLUMN IF NOT EXISTS contract_start DATE;")
c.execute("ALTER TABLE IF EXISTS tenants ADD COLUMN IF NOT EXISTS contract_end DATE;")
c.execute("ALTER TABLE IF EXISTS tenants ADD COLUMN IF NOT EXISTS rent_amount REAL;")
c.execute("ALTER TABLE IF EXISTS maintenance ADD COLUMN IF NOT EXISTS cost REAL DEFAULT 0;")
c.execute("ALTER TABLE IF EXISTS facturi ADD COLUMN IF NOT EXISTS apartment_id INTEGER REFERENCES apartments(id);")
c.execute("ALTER TABLE IF EXISTS facturi ADD COLUMN IF NOT EXISTS invoice_number TEXT;")
c.execute("""
    UPDATE facturi f
    SET apartment_id = t.apartment_id
    FROM tenants t
    WHERE f.tenant_id = t.id AND f.apartment_id IS NULL;
""")

# Tabelul activity_log — jurnal de activitate (audit trail)
# Inregistreaza toate actiunile adminilor: cine, ce, cand, de unde (IP)
c.execute("""
CREATE TABLE IF NOT EXISTS activity_log (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    username    TEXT NOT NULL,
    action      TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'general',
    target_type TEXT,
    target_id   INTEGER,
    details     TEXT,
    ip_address  TEXT,
    created_at  TIMESTAMP DEFAULT NOW()
);
""")

# Indexuri pt performanta la filtrare si sortare
c.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_category ON activity_log(category);")
c.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_created ON activity_log(created_at DESC);")
c.execute("CREATE INDEX IF NOT EXISTS idx_facturi_apartment_id ON facturi(apartment_id);")
c.execute("CREATE INDEX IF NOT EXISTS idx_tenants_apartment_id ON tenants(apartment_id);")
c.execute("CREATE INDEX IF NOT EXISTS idx_maintenance_apartment_id ON maintenance(apartment_id);")

print("✅ Tabele create.")

# Cont admin default
c.execute("SELECT COUNT(*) FROM users")
if c.fetchone()[0] == 0:
    hashed = generate_password_hash("admin123")
    c.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
              ("admin", "admin@rentmanager.ro", hashed))
    print("✅ Admin creat — username: admin  parola: admin123")
    print("   ⚠️  SCHIMBA PAROLA dupa primul login!")

# Date de test (doar daca nu exista apartamente)
c.execute("SELECT COUNT(*) FROM apartments")
if c.fetchone()[0] == 0:
    c.execute("""
        INSERT INTO apartments (number, address) VALUES
        ('101', '123 Strada Mihai Eminescu'),
        ('102', '123 Strada Mihai Eminescu'),
        ('201', '123 Strada Mihai Eminescu'),
        ('202', '45 Bulevardul Unirii'),
        ('301', '45 Bulevardul Unirii')
    """)
    c.execute("""
        INSERT INTO tenants (first_name, last_name, email, phone, apartment_id)
        VALUES ('Gabriel', 'Bicu', 'gabriel@email.com', '0721 000 001', 1)
    """)
    c.execute("UPDATE apartments SET status='Rented' WHERE id=1")
    c.execute("""
        INSERT INTO maintenance (apartment_id, description, priority)
        VALUES (1, 'Geam spart la bucatarie', 'High'), (2, 'Bec ars la baie', 'Low')
    """)
    c.execute("""
        INSERT INTO facturi (tenant_id, apartment_id, amount, description, due_date, status)
        VALUES (1, 1, 1500.00, 'Chirie lunara - Aprilie 2025', '2025-04-01', 'Unpaid'),
               (1, 1, 1500.00, 'Chirie lunara - Martie 2025',  '2025-03-01', 'Paid')
    """)
    print("✅ Date de test adaugate.")

conn.close()
print("\n✅ Gata! Acum poti rula: python -m flask run")
