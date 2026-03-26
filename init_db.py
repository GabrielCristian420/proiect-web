"""
Ruleaza o singura data dupa ce ai setat DATABASE_URL in .env:
    python init_db.py
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

c.execute("""
CREATE TABLE IF NOT EXISTS apartments (
    id      SERIAL PRIMARY KEY,
    number  TEXT NOT NULL,
    address TEXT NOT NULL,
    status  TEXT NOT NULL DEFAULT 'Available'
);
""")

c.execute("""
CREATE TABLE IF NOT EXISTS tenants (
    id           SERIAL PRIMARY KEY,
    first_name   TEXT NOT NULL,
    last_name    TEXT NOT NULL,
    email        TEXT NOT NULL,
    phone        TEXT,
    apartment_id INTEGER NOT NULL REFERENCES apartments(id),
    created_at   DATE DEFAULT CURRENT_DATE
);
""")

c.execute("""
CREATE TABLE IF NOT EXISTS maintenance (
    id           SERIAL PRIMARY KEY,
    apartment_id INTEGER NOT NULL REFERENCES apartments(id),
    description  TEXT NOT NULL,
    priority     TEXT NOT NULL DEFAULT 'Medium',
    status       TEXT NOT NULL DEFAULT 'Open',
    created_at   DATE DEFAULT CURRENT_DATE
);
""")

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

c.execute("""
CREATE TABLE IF NOT EXISTS facturi (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
    amount      REAL NOT NULL,
    description TEXT NOT NULL DEFAULT 'Chirie lunara',
    due_date    DATE NOT NULL,
    status      TEXT NOT NULL DEFAULT 'Unpaid',
    paid_at     DATE,
    created_at  DATE DEFAULT CURRENT_DATE
);
""")

print("✅ Tabele create.")

# Admin user
c.execute("SELECT COUNT(*) FROM users")
if c.fetchone()[0] == 0:
    hashed = generate_password_hash("admin123")
    c.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
              ("admin", "admin@rentmanager.ro", hashed))
    print("✅ Admin creat — username: admin  parola: admin123")
    print("   ⚠️  SCHIMBA PAROLA dupa primul login!")

# Sample data
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
        INSERT INTO facturi (tenant_id, amount, description, due_date, status)
        VALUES (1, 1500.00, 'Chirie lunara - Aprilie 2025', '2025-04-01', 'Unpaid'),
               (1, 1500.00, 'Chirie lunara - Martie 2025',  '2025-03-01', 'Paid')
    """)
    print("✅ Date de test adaugate.")

conn.close()
print("\n✅ Gata! Acum poti rula: python -m flask run")
