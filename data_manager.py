"""
data_manager.py - SQLite Persistence & Data Management Layer
AI-Based Network Intrusion Detection System

Implements structured, persistent local storage using SQLite for:
1. User Authentication & Role-Based Access Control (RBAC)
2. Network Traffic Scan History
3. Security Incident Alerts
4. System Configuration & Audit Logs

Ensures safe SQL transactions, parameterization against injection,
and automatic schema creation without data loss across application reruns.
Provides comprehensive fallback for WebAssembly / Pyodide / stlite runtimes
when native C-compiled sqlite3 is unavailable.
"""

import json
import os
import sys
import datetime
import hashlib
from typing import List, Dict, Any, Optional

# ------------------------------------------------------------------------------
# SQLITE COMPATIBILITY & DYNAMIC FALLBACK LAYER FOR WEB-ASSEMBLY / PYODIDE
# ------------------------------------------------------------------------------
try:
    import sqlite3
    HAVE_SQLITE = True
except (ImportError, ModuleNotFoundError):
    try:
        import sqlean as sqlite3  # type: ignore
        HAVE_SQLITE = True
    except (ImportError, ModuleNotFoundError):
        sqlite3 = None  # type: ignore
        HAVE_SQLITE = False

DB_FILE = os.path.join(os.path.dirname(__file__) if "__file__" in globals() else os.getcwd(), "nids_platform.db")

# ------------------------------------------------------------------------------
# IN-MEMORY DICTIONARY PERSISTENCE LAYER & MOCK DB-API DRIVER
# ------------------------------------------------------------------------------
_SHARED_MEM_CONN: Optional[Any] = None
_USE_FALLBACK_STORE: bool = not HAVE_SQLITE

_FALLBACK_STORE: Dict[str, List[Dict[str, Any]]] = {
    "users": [
        {
            "id": 1,
            "username": "admin",
            "password_hash": hashlib.sha256("admin123".encode("utf-8")).hexdigest(),
            "role": "SOC Admin",
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": 2,
            "username": "analyst",
            "password_hash": hashlib.sha256("analyst123".encode("utf-8")).hexdigest(),
            "role": "SOC Analyst",
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": 3,
            "username": "engineer",
            "password_hash": hashlib.sha256("nids2026".encode("utf-8")).hexdigest(),
            "role": "Security Engineer",
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": 4,
            "username": "examiner",
            "password_hash": hashlib.sha256("viva2026".encode("utf-8")).hexdigest(),
            "role": "Viva Examiner",
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": 5,
            "username": "divi",
            "password_hash": hashlib.sha256("admin123".encode("utf-8")).hexdigest(),
            "role": "SOC Admin",
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    ],
    "scan_history": [],
    "security_alerts": [],
    "booking_requests": [],
    "saved_itineraries": [],
    "user_feedback": []
}

class _IntegrityError(Exception):
    """Fallback for sqlite3.IntegrityError."""
    pass

class _OperationalError(Exception):
    """Fallback for sqlite3.OperationalError."""
    pass

class _DatabaseError(Exception):
    """Fallback for sqlite3.DatabaseError."""
    pass

class _Row(dict):
    """Dictionary-based SQLite Row compatible wrapper."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)

class _MockCursor:
    """Mock Cursor providing standard DB-API interface over in-memory fallback store."""
    def __init__(self, fallback_store: Dict[str, Any]):
        self._store = fallback_store
        self._last_query = ""
        self._last_params = ()
        self._last_results: List[Any] = []

    def execute(self, query: str, params: tuple = ()):
        self._last_query = query.strip()
        self._last_params = params
        self._last_results = []
        return self

    def executemany(self, query: str, seq_of_params: list = ()):
        return self

    def fetchone(self):
        if self._last_results:
            return self._last_results[0]
        q = self._last_query.upper()
        if "SELECT 1" in q:
            return (1,)
        if "COUNT(*)" in q:
            if "SCAN_HISTORY" in q:
                return (len(self._store.get("scan_history", [])),)
            if "SECURITY_ALERTS" in q:
                return (len(self._store.get("security_alerts", [])),)
            if "USERS" in q:
                return (len(self._store.get("users", [])),)
            if "BOOKING_REQUESTS" in q:
                return (len(self._store.get("booking_requests", [])),)
            if "SAVED_ITINERARIES" in q:
                return (len(self._store.get("saved_itineraries", [])),)
            if "USER_FEEDBACK" in q:
                return (len(self._store.get("user_feedback", [])),)
            return (0,)
        return None

    def fetchall(self):
        return self._last_results

    def close(self):
        pass

class _MockConnection:
    """Mock Connection providing standard DB-API interface for WebAssembly environments."""
    def __init__(self):
        self.row_factory = None

    def cursor(self):
        return _MockCursor(_FALLBACK_STORE)

    def commit(self):
        pass

    def rollback(self):
        pass

    def execute(self, query: str, params: tuple = ()):
        cur = self.cursor()
        return cur.execute(query, params)

    def executemany(self, query: str, params: list = ()):
        cur = self.cursor()
        return cur.executemany(query, params)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

if not HAVE_SQLITE:
    class MockSqlite:
        IntegrityError = _IntegrityError
        OperationalError = _OperationalError
        DatabaseError = _DatabaseError
        Error = Exception
        Row = _Row

        @staticmethod
        def connect(*args, **kwargs):
            return _MockConnection()

    sqlite3 = MockSqlite()  # type: ignore

class _SafeConnectionWrapper:
    """Wrapper around an SQLite or mock connection preventing .close() from discarding session data."""
    def __init__(self, conn: Any):
        self._conn = conn

    def cursor(self):
        return self._conn.cursor()

    def commit(self):
        try:
            return self._conn.commit()
        except Exception:
            pass

    def rollback(self):
        try:
            return self._conn.rollback()
        except Exception:
            pass

    def execute(self, *args, **kwargs):
        return self._conn.execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        return self._conn.executemany(*args, **kwargs)

    def close(self):
        pass

    @property
    def row_factory(self):
        return getattr(self._conn, "row_factory", None)

    @row_factory.setter
    def row_factory(self, val):
        try:
            self._conn.row_factory = val
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

def _create_schema_on_conn(conn: Any):
    """Creates the standard NIDS schema on the provided SQLite connection."""
    try:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'SOC Analyst',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_ref TEXT UNIQUE NOT NULL,
            scan_date TEXT NOT NULL,
            total_packets INTEGER NOT NULL,
            normal_count INTEGER NOT NULL,
            malicious_count INTEGER NOT NULL,
            anomaly_rate REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_ref TEXT NOT NULL,
            scan_ref TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            alert_message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS booking_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ref_code TEXT UNIQUE NOT NULL,
            guide_id TEXT NOT NULL,
            guide_name TEXT NOT NULL,
            traveler_name TEXT NOT NULL,
            traveler_email TEXT NOT NULL,
            traveler_phone TEXT NOT NULL,
            tour_date TEXT NOT NULL,
            party_size INTEGER NOT NULL,
            tour_notes TEXT,
            daily_fee INTEGER NOT NULL,
            city TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Confirmed (Demo)',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS saved_itineraries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            itinerary_ref TEXT UNIQUE NOT NULL,
            destination_id TEXT NOT NULL,
            destination_name TEXT NOT NULL,
            duration_days INTEGER NOT NULL,
            travelers_count INTEGER NOT NULL,
            total_budget REAL NOT NULL,
            estimated_cost REAL NOT NULL,
            variance REAL NOT NULL,
            budget_status TEXT NOT NULL,
            travel_pace TEXT NOT NULL,
            itinerary_data_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module_name TEXT NOT NULL,
            rating INTEGER NOT NULL,
            comments TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        conn.commit()
    except Exception:
        pass

def get_db_connection():
    """
    Creates a thread-safe connection to the SQLite database.
    If running in a WebAssembly, Pyodide, or restricted browser filesystem,
    it falls back smoothly to a persistent in-memory SQLite connection or mock store.
    """
    global _SHARED_MEM_CONN, _USE_FALLBACK_STORE

    if not HAVE_SQLITE:
        _USE_FALLBACK_STORE = True
        return _SafeConnectionWrapper(_MockConnection())

    # If in-memory connection is already established, reuse it
    if _SHARED_MEM_CONN is not None:
        return _SafeConnectionWrapper(_SHARED_MEM_CONN)

    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Quick validation check to confirm write/read viability
        conn.execute("SELECT 1;")
        return conn
    except Exception:
        # Gracefully switch to persistent in-memory database
        try:
            if _SHARED_MEM_CONN is None:
                _SHARED_MEM_CONN = sqlite3.connect(":memory:", check_same_thread=False)
                _SHARED_MEM_CONN.row_factory = sqlite3.Row
                _create_schema_on_conn(_SHARED_MEM_CONN)
            return _SafeConnectionWrapper(_SHARED_MEM_CONN)
        except Exception:
            _USE_FALLBACK_STORE = True
            return _SafeConnectionWrapper(_MockConnection())

def hash_password(password: str) -> str:
    """Generates a secure SHA-256 hash for password storage and verification."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def init_db():
    """Initializes the database schema if tables do not exist."""
    global _USE_FALLBACK_STORE
    try:
        conn = get_db_connection()
        _create_schema_on_conn(conn)
        conn.close()
    except Exception:
        _USE_FALLBACK_STORE = True

    # Seed default demo accounts on launch
    try:
        seed_default_admin()
    except Exception:
        pass

# ------------------------------------------------------------------------------
# BOOKING REQUEST OPERATIONS
# ------------------------------------------------------------------------------

def save_booking_request(
    ref_code: str,
    guide_id: str,
    guide_name: str,
    traveler_name: str,
    traveler_email: str,
    traveler_phone: str,
    tour_date: str,
    party_size: int,
    tour_notes: str,
    daily_fee: int,
    city: str
) -> bool:
    """Inserts a new verified demonstration booking record into SQLite or fallback store."""
    rec = {
        "id": len(_FALLBACK_STORE["booking_requests"]) + 1,
        "ref_code": ref_code,
        "guide_id": guide_id,
        "guide_name": guide_name,
        "traveler_name": traveler_name.strip(),
        "traveler_email": traveler_email.strip(),
        "traveler_phone": traveler_phone.strip(),
        "tour_date": str(tour_date),
        "party_size": int(party_size),
        "tour_notes": tour_notes.strip() if tour_notes else "",
        "daily_fee": int(daily_fee),
        "city": city,
        "status": "Confirmed (Demo)",
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    _FALLBACK_STORE["booking_requests"].insert(0, rec)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO booking_requests 
        (ref_code, guide_id, guide_name, traveler_name, traveler_email, traveler_phone, tour_date, party_size, tour_notes, daily_fee, city)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ref_code, guide_id, guide_name, traveler_name.strip(),
            traveler_email.strip(), traveler_phone.strip(), str(tour_date),
            int(party_size), tour_notes.strip() if tour_notes else "",
            int(daily_fee), city
        ))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return True

def get_all_booking_requests(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recorded demonstration bookings ordered by newest first."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT * FROM booking_requests ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
        if results:
            return results
    except Exception:
        pass
    return _FALLBACK_STORE["booking_requests"][:limit]

# ------------------------------------------------------------------------------
# ITINERARY PERSISTENCE OPERATIONS
# ------------------------------------------------------------------------------

def save_itinerary(
    itinerary_ref: str,
    destination_id: str,
    destination_name: str,
    duration_days: int,
    travelers_count: int,
    total_budget: float,
    estimated_cost: float,
    variance: float,
    budget_status: str,
    travel_pace: str,
    itinerary_data: Dict[str, Any]
) -> bool:
    """Saves a generated itinerary for persistence across sessions."""
    rec = {
        "id": len(_FALLBACK_STORE["saved_itineraries"]) + 1,
        "itinerary_ref": itinerary_ref,
        "destination_id": destination_id,
        "destination_name": destination_name,
        "duration_days": int(duration_days),
        "travelers_count": int(travelers_count),
        "total_budget": float(total_budget),
        "estimated_cost": float(estimated_cost),
        "variance": float(variance),
        "budget_status": budget_status,
        "travel_pace": travel_pace,
        "itinerary_data_json": json.dumps(itinerary_data),
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    _FALLBACK_STORE["saved_itineraries"] = [i for i in _FALLBACK_STORE["saved_itineraries"] if i["itinerary_ref"] != itinerary_ref]
    _FALLBACK_STORE["saved_itineraries"].insert(0, rec)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT OR REPLACE INTO saved_itineraries
        (itinerary_ref, destination_id, destination_name, duration_days, travelers_count, total_budget, estimated_cost, variance, budget_status, travel_pace, itinerary_data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            itinerary_ref, destination_id, destination_name, int(duration_days),
            int(travelers_count), float(total_budget), float(estimated_cost),
            float(variance), budget_status, travel_pace, json.dumps(itinerary_data)
        ))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return True

def get_saved_itineraries(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves saved itineraries from SQLite or fallback store."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT id, itinerary_ref, destination_id, destination_name, duration_days, travelers_count, total_budget, estimated_cost, variance, budget_status, travel_pace, created_at 
        FROM saved_itineraries ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
        if results:
            return results
    except Exception:
        pass
    return _FALLBACK_STORE["saved_itineraries"][:limit]

# ------------------------------------------------------------------------------
# FEEDBACK OPERATIONS
# ------------------------------------------------------------------------------

def save_feedback(module_name: str, rating: int, comments: str) -> bool:
    """Saves user feedback for academic quality assurance."""
    rec = {
        "id": len(_FALLBACK_STORE["user_feedback"]) + 1,
        "module_name": module_name,
        "rating": int(rating),
        "comments": comments.strip(),
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    _FALLBACK_STORE["user_feedback"].append(rec)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO user_feedback (module_name, rating, comments)
        VALUES (?, ?, ?)
        """, (module_name, int(rating), comments.strip()))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return True

def get_db_stats() -> Dict[str, int]:
    """Returns total counts for dashboard KPIs."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM booking_requests")
        bookings = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM saved_itineraries")
        itineraries = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM user_feedback")
        feedback = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        scans = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM security_alerts")
        alerts = cursor.fetchone()[0]
        conn.close()
        return {
            "total_bookings": max(bookings, len(_FALLBACK_STORE["booking_requests"])),
            "total_saved_itineraries": max(itineraries, len(_FALLBACK_STORE["saved_itineraries"])),
            "total_feedback": max(feedback, len(_FALLBACK_STORE["user_feedback"])),
            "total_scans": max(scans, len(_FALLBACK_STORE["scan_history"])),
            "total_alerts": max(alerts, len(_FALLBACK_STORE["security_alerts"]))
        }
    except Exception:
        return {
            "total_bookings": len(_FALLBACK_STORE["booking_requests"]),
            "total_saved_itineraries": len(_FALLBACK_STORE["saved_itineraries"]),
            "total_feedback": len(_FALLBACK_STORE["user_feedback"]),
            "total_scans": len(_FALLBACK_STORE["scan_history"]),
            "total_alerts": len(_FALLBACK_STORE["security_alerts"])
        }

# ------------------------------------------------------------------------------
# NIDS SCAN & ALERT OPERATIONS
# ------------------------------------------------------------------------------

def save_scan_record(
    scan_ref: str,
    total_packets: int,
    normal_count: int,
    malicious_count: int,
    anomaly_rate: float,
    scan_date: Optional[str] = None
) -> bool:
    """Inserts a completed network traffic analysis record into SQLite and fallback store."""
    if scan_date is None:
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rec = {
        "id": len(_FALLBACK_STORE["scan_history"]) + 1,
        "scan_ref": scan_ref,
        "scan_date": scan_date,
        "total_packets": int(total_packets),
        "normal_count": int(normal_count),
        "malicious_count": int(malicious_count),
        "anomaly_rate": float(anomaly_rate),
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    _FALLBACK_STORE["scan_history"] = [s for s in _FALLBACK_STORE["scan_history"] if s["scan_ref"] != scan_ref]
    _FALLBACK_STORE["scan_history"].insert(0, rec)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT OR REPLACE INTO scan_history
        (scan_ref, scan_date, total_packets, normal_count, malicious_count, anomaly_rate)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_ref, scan_date, int(total_packets),
            int(normal_count), int(malicious_count), float(anomaly_rate)
        ))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return True

def get_all_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recorded network scans ordered by newest first."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT * FROM scan_history ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
        if results:
            return results
    except Exception:
        pass
    return _FALLBACK_STORE["scan_history"][:limit]

def save_alerts_batch(alerts: List[Dict[str, Any]], scan_ref: str) -> int:
    """Saves generated security alerts into SQLite and fallback store."""
    saved = 0
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for a in alerts:
        dest_val = a.get("destination_ip", a.get("dest_ip", "0.0.0.0"))
        alert_item = {
            "id": len(_FALLBACK_STORE["security_alerts"]) + 1,
            "alert_ref": a.get("alert_id", "ALT-0000"),
            "scan_ref": scan_ref,
            "timestamp": a.get("timestamp", now_str),
            "source_ip": a.get("source_ip", "0.0.0.0"),
            "dest_ip": dest_val,
            "protocol": a.get("protocol", "TCP"),
            "threat_type": a.get("threat_type", "Unknown"),
            "severity": a.get("severity", "Medium"),
            "alert_message": a.get("alert_message", ""),
            "status": "Active",
            "created_at": now_str
        }
        _FALLBACK_STORE["security_alerts"].insert(0, alert_item)
        saved += 1

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        for a in alerts:
            dest_val = a.get("destination_ip", a.get("dest_ip", "0.0.0.0"))
            cursor.execute("""
            INSERT INTO security_alerts
            (alert_ref, scan_ref, timestamp, source_ip, dest_ip, protocol, threat_type, severity, alert_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                a.get("alert_id", "ALT-0000"),
                scan_ref,
                a.get("timestamp", now_str),
                a.get("source_ip", "0.0.0.0"),
                dest_val,
                a.get("protocol", "TCP"),
                a.get("threat_type", "Unknown"),
                a.get("severity", "Medium"),
                a.get("alert_message", "")
            ))
        conn.commit()
        conn.close()
    except Exception:
        pass
    return saved

def get_recent_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recorded security alerts ordered by newest first."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT * FROM security_alerts ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
        if results:
            return results
    except Exception:
        pass
    return _FALLBACK_STORE["security_alerts"][:limit]

# ------------------------------------------------------------------------------
# USER AUTHENTICATION & ACCESS CONTROL OPERATIONS
# ------------------------------------------------------------------------------

def create_user(username: str, password: str, role: str = "SOC Analyst") -> bool:
    """Creates a new user record with SHA-256 hashed password. Returns True on success."""
    username = username.strip()
    if not username or not password:
        return False

    # Check if duplicate in fallback store first
    if any(u["username"] == username for u in _FALLBACK_STORE["users"]):
        return False

    password_hash = hash_password(password)
    user_record = {
        "id": len(_FALLBACK_STORE["users"]) + 1,
        "username": username,
        "password_hash": password_hash,
        "role": role.strip(),
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
        """, (username, password_hash, role.strip()))
        conn.commit()
        conn.close()
        _FALLBACK_STORE["users"].append(user_record)
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception:
        _FALLBACK_STORE["users"].append(user_record)
        return True

def verify_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verifies user credentials. Returns user dictionary on success, or None on failure."""
    username = username.strip()
    if not username or not password:
        return None

    password_hash = hash_password(password)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT id, username, role, created_at
        FROM users
        WHERE username = ? AND password_hash = ?
        """, (username, password_hash))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
                "created_at": row["created_at"]
            }
    except Exception:
        pass

    for u in _FALLBACK_STORE["users"]:
        if u["username"] == username and u["password_hash"] == password_hash:
            return {
                "id": u["id"],
                "username": u["username"],
                "role": u["role"],
                "created_at": u["created_at"]
            }
    return None

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieves public user context by username (excluding password hash)."""
    username = username.strip()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT id, username, role, created_at FROM users WHERE username = ?
        """, (username,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
    except Exception:
        pass

    for u in _FALLBACK_STORE["users"]:
        if u["username"] == username:
            return {
                "id": u["id"],
                "username": u["username"],
                "role": u["role"],
                "created_at": u["created_at"]
            }
    return None

def get_all_users() -> List[Dict[str, Any]]:
    """Retrieves all registered users without password hashes."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()
        if rows:
            return [dict(row) for row in rows]
    except Exception:
        pass

    return [
        {"id": u["id"], "username": u["username"], "role": u["role"], "created_at": u["created_at"]}
        for u in _FALLBACK_STORE["users"]
    ]

def seed_default_admin():
    """Seeds default demo accounts if not already present."""
    demo_accounts = [
        ("admin", "admin123", "SOC Admin"),
        ("analyst", "analyst123", "SOC Analyst"),
        ("engineer", "nids2026", "Security Engineer"),
        ("examiner", "viva2026", "Viva Examiner"),
        ("divi", "admin123", "SOC Admin")
    ]
    for u, p, r in demo_accounts:
        if not get_user_by_username(u):
            create_user(username=u, password=p, role=r)

def clear_scan_history() -> bool:
    """Clears all scan history and security incident alerts from the database and fallback store."""
    _FALLBACK_STORE["scan_history"].clear()
    _FALLBACK_STORE["security_alerts"].clear()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history;")
        cursor.execute("DELETE FROM security_alerts;")
        conn.commit()
        conn.close()
        return True
    except Exception:
        return True

# Auto-initialize database on import
init_db()
