"""Demo ERP schema and a deterministic seed.

The data is synthetic. It exists so the guards (row caps, scopes, injection
attempts) have something real to run against.
"""

from __future__ import annotations

import random
import sqlite3
from datetime import date, timedelta
from pathlib import Path

SCHEMA = """
CREATE TABLE customers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    country TEXT NOT NULL,
    credit_limit_cents INTEGER NOT NULL
);
CREATE TABLE invoices (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    issued_on TEXT NOT NULL,
    due_on TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'paid', 'void')),
    total_cents INTEGER NOT NULL
);
CREATE TABLE invoice_lines (
    id INTEGER PRIMARY KEY,
    invoice_id INTEGER NOT NULL REFERENCES invoices(id),
    sku TEXT NOT NULL,
    qty INTEGER NOT NULL,
    unit_price_cents INTEGER NOT NULL
);
CREATE TABLE payroll (
    employee_id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL,
    salary_cents INTEGER NOT NULL
);
"""

_NAMES = [
    "Acme", "Borealis", "Cobalt", "Delta", "Ember", "Fjord", "Granite", "Harbor",
    "Iris", "Juniper", "Kestrel", "Lumen", "Meridian", "Nimbus", "Orchid", "Pioneer",
    "Quartz", "Riverside", "Summit", "Tundra",
]
_SUFFIXES = ["Ltd", "GmbH", "Inc", "BV", "SA"]
_COUNTRIES = ["NL", "DE", "US", "GB", "ES"]


def create_database(path: Path, seed: int = 7) -> Path:
    """Create a fresh SQLite file with the demo schema and seeded rows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    rng = random.Random(seed)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        customer_id = 0
        for base in _NAMES:
            for suffix in _SUFFIXES[: rng.randint(2, 3)]:
                customer_id += 1
                conn.execute(
                    "INSERT INTO customers VALUES (?, ?, ?, ?)",
                    (customer_id, f"{base} {suffix}", rng.choice(_COUNTRIES), rng.randint(5, 50) * 100_000),
                )
        # A name containing LIKE wildcards, to show prefix search treats them as text.
        customer_id += 1
        conn.execute(
            "INSERT INTO customers VALUES (?, ?, ?, ?)",
            (customer_id, "100% Organic_Foods", "NL", 1_000_000),
        )
        start = date(2026, 1, 1)
        invoice_id = 0
        line_id = 0
        for _ in range(600):
            invoice_id += 1
            issued = start + timedelta(days=rng.randint(0, 300))
            due = issued + timedelta(days=30)
            status = rng.choices(["open", "paid", "void"], weights=[4, 5, 1])[0]
            lines = []
            for _ in range(rng.randint(1, 4)):
                line_id += 1
                qty = rng.randint(1, 20)
                price = rng.randint(5, 500) * 100
                lines.append((line_id, invoice_id, f"SKU-{rng.randint(100, 999)}", qty, price))
            total = sum(q * p for _, _, _, q, p in lines)
            conn.execute(
                "INSERT INTO invoices VALUES (?, ?, ?, ?, ?, ?)",
                (invoice_id, rng.randint(1, customer_id), issued.isoformat(), due.isoformat(), status, total),
            )
            conn.executemany("INSERT INTO invoice_lines VALUES (?, ?, ?, ?, ?)", lines)
        for emp in range(1, 26):
            conn.execute(
                "INSERT INTO payroll VALUES (?, ?, ?)",
                (emp, f"Employee {emp:02d}", rng.randint(30, 120) * 100_000),
            )
        conn.commit()
    finally:
        conn.close()
    return path
