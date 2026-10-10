"""Small private SQLite store; opaque bearer/session values are stored hashed."""
import base64
import hashlib
import json
import os
import pathlib
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager

from .config import APPROVAL_TTL, ORIGIN


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unb64(value):
    if not isinstance(value, str) or len(value) > 16384:
        raise ValueError("invalid_encoding")
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class Store:
    def __init__(self, path, clock=time.time):
        self.path, self.clock = pathlib.Path(path), clock
        self.lock = threading.RLock()
        parent = self.path.parent
        if parent.is_symlink() or self.path.is_symlink():
            raise RuntimeError("identity_symlink_forbidden")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077:
            raise RuntimeError("identity_directory_not_private")
        os.umask(0o077)
        self.db = sqlite3.connect(self.path, timeout=3, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA max_page_count=2048")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS records(kind TEXT, key TEXT, value TEXT, expiry REAL,
                                             PRIMARY KEY(kind,key));
          CREATE INDEX IF NOT EXISTS record_expiry ON records(expiry);
          CREATE TABLE IF NOT EXISTS credentials(id TEXT PRIMARY KEY, public_key TEXT NOT NULL,
                         counter INTEGER NOT NULL, created REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY, payload_hash TEXT NOT NULL,
                         action TEXT NOT NULL, state TEXT NOT NULL, result TEXT, created REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS calendar_consents(account_revision TEXT NOT NULL,
                         calendar_id TEXT NOT NULL, generation TEXT NOT NULL,
                         audience_acknowledged INTEGER NOT NULL, created REAL NOT NULL,
                         PRIMARY KEY(account_revision,calendar_id));
          CREATE TABLE IF NOT EXISTS contacts_consents(account_revision TEXT NOT NULL,
                         addressbook_id TEXT NOT NULL, generation TEXT NOT NULL, created REAL NOT NULL,
                         PRIMARY KEY(account_revision,addressbook_id));
        """)
        self.db.execute("INSERT OR IGNORE INTO settings VALUES ('owner',?)", (b64(secrets.token_bytes(32)),))
        self.db.execute("INSERT OR IGNORE INTO settings VALUES ('origin',?)", (ORIGIN,))
        if self.db.execute("SELECT value FROM settings WHERE key='origin'").fetchone()[0] != ORIGIN:
            raise RuntimeError("identity_origin_mismatch")
        os.chmod(self.path, 0o600)
        self.purge()

    @property
    def owner(self):
        with self.lock:
            return self.db.execute("SELECT value FROM settings WHERE key='owner'").fetchone()[0]

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def purge(self):
        self.db.execute("DELETE FROM records WHERE expiry<=?", (self.clock(),))

    def get(self, kind, key):
        with self.lock:
            row = self.db.execute("SELECT value FROM records WHERE kind=? AND key=? AND expiry>?",
                                  (kind, key, self.clock())).fetchone()
            return json.loads(row[0]) if row else None

    def put(self, kind, key, value, ttl, maximum=64):
        with self.lock:
            self.purge()
            raw = json.dumps(value, separators=(",", ":"))
            if len(raw.encode()) > 16384:
                raise ValueError("record_too_large")
            exists = self.db.execute("SELECT 1 FROM records WHERE kind=? AND key=?", (kind, key)).fetchone()
            count = self.db.execute("SELECT count(*) FROM records WHERE kind=?", (kind,)).fetchone()[0]
            if not exists and count >= maximum:
                raise ValueError("capacity_reached")
            self.db.execute("INSERT OR REPLACE INTO records VALUES(?,?,?,?)",
                            (kind, key, raw, self.clock() + ttl))

    def delete(self, kind, key):
        with self.lock:
            self.db.execute("DELETE FROM records WHERE kind=? AND key=?", (kind, key))

    def consume(self, kind, key, binding):
        # Caller holds transaction through signature verification / state update.
        item = self.get(kind, key)
        if not item or item.get("binding") != binding:
            raise ValueError("challenge_not_available")
        self.delete(kind, key)
        return item

    def credentials(self):
        with self.lock:
            return [dict(row) for row in self.db.execute("SELECT * FROM credentials ORDER BY created")]

    def calendar_consents(self, revision):
        with self.lock:
            return [dict(row) for row in self.db.execute(
                "SELECT * FROM calendar_consents WHERE account_revision=? ORDER BY calendar_id", (revision,))]

    def calendar_consent(self, revision, identifier):
        with self.lock:
            row = self.db.execute("SELECT * FROM calendar_consents WHERE account_revision=? AND calendar_id=?",
                                  (revision, identifier)).fetchone()
            return dict(row) if row else None

    def invalidate_calendar_previews(self, revision=None, identifier=None):
        # Never expose preview/event content; scan is bounded by Store.put's cap.
        with self.lock:
            for row in self.db.execute("SELECT key,value FROM records WHERE kind='calendar_preview'").fetchall():
                value = json.loads(row['value'])
                if (revision is None or value.get('account_revision') == revision) and (identifier is None or value.get('payload', {}).get('calendar_id') == identifier):
                    self.delete('calendar_preview', row['key'])

    def set_calendar_consent(self, revision, identifier, audience_acknowledged):
        if (not isinstance(revision, str) or not __import__('re').fullmatch(r'[a-f0-9]{24}', revision) or
            not isinstance(identifier, str) or not __import__('re').fullmatch(r'[a-f0-9]{24}', identifier) or
            type(audience_acknowledged) is not bool):
            raise ValueError('invalid_calendar_consent')
        with self.lock:
            if self.calendar_consent(revision, identifier) is None and len(self.calendar_consents(revision)) >= 25:
                raise ValueError('calendar_consent_capacity')
            generation = secrets.token_hex(12)
            self.invalidate_calendar_previews(revision, identifier)
            self.db.execute("INSERT OR REPLACE INTO calendar_consents VALUES(?,?,?,?,?)",
                            (revision, identifier, generation, int(audience_acknowledged), self.clock()))
            return self.calendar_consent(revision, identifier)

    def revoke_calendar_consent(self, revision, identifier):
        with self.lock:
            self.db.execute("DELETE FROM calendar_consents WHERE account_revision=? AND calendar_id=?", (revision, identifier))
            self.invalidate_calendar_previews(revision, identifier)

    def clear_calendar_consents(self, revision=None):
        with self.lock:
            if revision is None: self.db.execute("DELETE FROM calendar_consents")
            else: self.db.execute("DELETE FROM calendar_consents WHERE account_revision=?", (revision,))
            self.invalidate_calendar_previews(revision)

    def contacts_consents(self, revision):
        with self.lock:
            return [dict(row) for row in self.db.execute(
                'SELECT * FROM contacts_consents WHERE account_revision=? ORDER BY addressbook_id', (revision,))]

    def contacts_consent(self, revision, identifier):
        with self.lock:
            row = self.db.execute('SELECT * FROM contacts_consents WHERE account_revision=? AND addressbook_id=?', (revision, identifier)).fetchone()
            return dict(row) if row else None

    def invalidate_contact_refs(self, revision=None, identifier=None):
        with self.lock:
            for row in self.db.execute("SELECT key,value FROM records WHERE kind='contact_ref'").fetchall():
                value = json.loads(row['value'])
                if (revision is None or value.get('account_revision') == revision) and (identifier is None or value.get('addressbook_id') == identifier):
                    self.delete('contact_ref', row['key'])

    def set_contacts_consent(self, revision, identifier):
        if any(not isinstance(value, str) or not __import__('re').fullmatch(r'[a-f0-9]{24}', value) for value in (revision, identifier)):
            raise ValueError('invalid_contacts_consent')
        with self.lock:
            if self.contacts_consent(revision, identifier) is None and len(self.contacts_consents(revision)) >= 25:
                raise ValueError('contacts_consent_capacity')
            self.invalidate_contact_refs(revision, identifier)
            self.db.execute('INSERT OR REPLACE INTO contacts_consents VALUES(?,?,?,?)', (revision, identifier, secrets.token_hex(12), self.clock()))
            return self.contacts_consent(revision, identifier)

    def revoke_contacts_consent(self, revision, identifier):
        with self.lock:
            self.db.execute('DELETE FROM contacts_consents WHERE account_revision=? AND addressbook_id=?', (revision, identifier))
            self.invalidate_contact_refs(revision, identifier)

    def clear_contacts_consents(self, revision=None):
        with self.lock:
            if revision is None: self.db.execute('DELETE FROM contacts_consents')
            else: self.db.execute('DELETE FROM contacts_consents WHERE account_revision=?', (revision,))
            self.invalidate_contact_refs(revision)

    def invalidate_mail_previews(self, revision):
        with self.lock:
            for row in self.db.execute("SELECT key,value FROM records WHERE kind='mail_preview'").fetchall():
                if json.loads(row['value']).get('account_revision') == revision:
                    self.delete('mail_preview', row['key'])

    def approve_bootstrap(self, fingerprint):
        with self.transaction():
            if self.credentials():
                raise ValueError("owner_already_enrolled")
            item = self.get("setup", fingerprint)
            if not item:
                raise ValueError("request_expired_or_unknown")
            # Only this exact browser request is approved. Never 'next visitor'.
            self.db.execute("DELETE FROM records WHERE kind='setup' AND key!=?", (fingerprint,))
            item["approved_until"] = self.clock() + APPROVAL_TTL
            self.put("setup", fingerprint, item, APPROVAL_TTL, maximum=32)

    def recovery_reset(self):
        # Private CLI only, with explicit human confirmation before calling.
        with self.transaction():
            self.db.execute("DELETE FROM credentials")
            self.db.execute("DELETE FROM records")
            self.db.execute("DELETE FROM calendar_consents")
            self.db.execute("DELETE FROM contacts_consents")
            # Keep irreversible-operation receipts: recovery must not enable
            # reusing a previous send/mutation idempotency key.

    def reserve_operation(self, action, key, payload):
        if not isinstance(key, str) or not __import__('re').fullmatch(r'[A-Za-z0-9_-]{16,80}',key):
            raise ValueError("invalid_idempotency_key")
        identity = digest(action + ":" + key)
        payload_hash = hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        with self.transaction():
            row=self.db.execute("SELECT * FROM operations WHERE id=?",(identity,)).fetchone()
            if row:
                if row['payload_hash'] != payload_hash:
                    raise ValueError("idempotency_key_payload_conflict")
                if row['state'] == 'completed':
                    return identity,json.loads(row['result'])
                raise ValueError("operation_outcome_uncertain_do_not_retry")
            if self.db.execute("SELECT count(*) FROM operations").fetchone()[0]>=1024:
                raise ValueError("operation_receipt_capacity")
            self.db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?)",(identity,payload_hash,action,'in_progress',None,self.clock()))
        return identity,None

    def finish_operation(self, identity, result=None):
        with self.transaction():
            self.db.execute("UPDATE operations SET state=?,result=? WHERE id=?",
                            ('completed' if result is not None else 'uncertain',json.dumps(result) if result is not None else None,identity))

    def close(self):
        with self.lock:
            self.db.close()
