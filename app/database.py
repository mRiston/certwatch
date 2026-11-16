import os, sqlite3
from contextlib import contextmanager
DB_PATH=os.getenv("CERTWATCH_DB", "/data/certwatch.db")
SCHEMA="""
CREATE TABLE IF NOT EXISTS scans (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 endpoint_key TEXT NOT NULL, name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
 environment TEXT NOT NULL, service TEXT NOT NULL, scanned_at TEXT NOT NULL,
 success INTEGER NOT NULL, error_code TEXT, subject TEXT, issuer TEXT, sans_json TEXT,
 serial_number TEXT, fingerprint_sha256 TEXT, not_before TEXT, not_after TEXT,
 days_remaining INTEGER, status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_scans_endpoint_time ON scans(endpoint_key, scanned_at DESC);
"""
@contextmanager
def connect():
    c=sqlite3.connect(DB_PATH); c.row_factory=sqlite3.Row
    try: yield c; c.commit()
    finally: c.close()
def init_db():
    with connect() as c: c.executescript(SCHEMA)
def insert_scan(r):
    cols=','.join(r); marks=','.join('?' for _ in r)
    with connect() as c: c.execute(f"INSERT INTO scans ({cols}) VALUES ({marks})", tuple(r.values()))
def latest():
    q="""SELECT s.* FROM scans s JOIN (SELECT endpoint_key, MAX(id) id FROM scans GROUP BY endpoint_key) x ON s.id=x.id ORDER BY CASE s.status WHEN 'expired' THEN 0 WHEN 'critical' THEN 1 WHEN 'warning' THEN 2 WHEN 'unreachable' THEN 3 ELSE 4 END, s.days_remaining"""
    with connect() as c: return [dict(x) for x in c.execute(q)]
def history(endpoint_key, limit=30):
    with connect() as c: return [dict(x) for x in c.execute("SELECT * FROM scans WHERE endpoint_key=? ORDER BY id DESC LIMIT ?",(endpoint_key,limit))]
