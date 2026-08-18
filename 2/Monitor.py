"""
BreachGuard - per-item monitoring logic

Rules implemented:
- Up to 2 emails and 2 passwords can be monitored at once.
- Emails live in one "box" (slot group), passwords in another.
- Each monitored item has its own Start/Stop control.
- Each item has its own independent countdown timer, started only when
  that item's Start button is clicked.
- When (and only when) an item's own countdown hits 0, that item is
  checked against the breach database.
- If a match is found, the new breach record + timestamp is simply
  returned/logged - no side effects (no alert firing) beyond that.

NOTE: this file now matches the actual database.db schema built by
breached_emails_inserting.py / breached_pass_inserting.py:
    breachedemails(id, emails)
    breachedpasswords(id, passwords)
(column names are the plural "emails" / "passwords", not "email" / "password")
"""

import sqlite3
import threading
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, request, jsonify, render_template

DB_PATH = "database.db"
MAX_EMAIL_SLOTS = 2
MAX_PASSWORD_SLOTS = 2
DEFAULT_INTERVAL_SECONDS = 30

app = Flask(__name__)
scheduler = BackgroundScheduler()
scheduler.start()

# Guards concurrent access to the in-memory slot state from Flask threads
# and APScheduler's worker threads at the same time.
_lock = threading.Lock()


def get_connection():
    # check_same_thread=False because APScheduler jobs and Flask requests
    # run on different threads and each call opens its own short-lived
    # connection/cursor.
    return sqlite3.connect(DB_PATH, check_same_thread=False)


class MonitorSlot:
    """One monitored item (one email OR one password) with its own
    job/countdown/state."""

    def __init__(self, slot_type: str, slot_index: int):
        self.slot_type = slot_type          # "email" or "password"
        self.slot_index = slot_index        # 0 or 1
        self.value = None                   # the email/password being watched
        self.interval_seconds = DEFAULT_INTERVAL_SECONDS
        self.running = False
        self.job_id = f"{slot_type}-{slot_index}"
        self.job = None
        self.last_checked_at = None
        self.findings = []                  # breach hits: [{value, timestamp, source}]

    # ---- countdown ----
    def seconds_remaining(self):
        if not self.running or self.job is None or self.job.next_run_time is None:
            return None
        remaining = (self.job.next_run_time - datetime.now(self.job.next_run_time.tzinfo)).total_seconds()
        return max(0, int(remaining))

    def to_dict(self):
        return {
            "slot_type": self.slot_type,
            "slot_index": self.slot_index,
            "value": self.value,
            "running": self.running,
            "interval_seconds": self.interval_seconds,
            "seconds_remaining": self.seconds_remaining(),
            "last_checked_at": self.last_checked_at,
            "findings": self.findings,
        }


class MonitorManager:
    """Owns the two boxes: emails[0..1] and passwords[0..1]."""

    def __init__(self):
        self.email_slots = [MonitorSlot("email", i) for i in range(MAX_EMAIL_SLOTS)]
        self.password_slots = [MonitorSlot("password", i) for i in range(MAX_PASSWORD_SLOTS)]

    def _slots_for(self, slot_type):
        if slot_type == "email":
            return self.email_slots
        if slot_type == "password":
            return self.password_slots
        raise ValueError("slot_type must be 'email' or 'password'")

    def find_free_slot(self, slot_type):
        for slot in self._slots_for(slot_type):
            if not slot.running:
                return slot
        return None  # both of the 2 slots are already in use

    def get_slot(self, slot_type, slot_index):
        slots = self._slots_for(slot_type)
        if slot_index < 0 or slot_index >= len(slots):
            raise ValueError("slot_index out of range")
        return slots[slot_index]

    # ---- start/stop ----
    def start(self, slot_type, value, interval_seconds=DEFAULT_INTERVAL_SECONDS, slot_index=None):
        with _lock:
            if slot_index is not None:
                slot = self.get_slot(slot_type, slot_index)
                if slot.running:
                    raise RuntimeError(f"{slot_type} slot {slot_index} is already running")
            else:
                slot = self.find_free_slot(slot_type)
                if slot is None:
                    raise RuntimeError(
                        f"Cannot monitor more than {MAX_EMAIL_SLOTS if slot_type == 'email' else MAX_PASSWORD_SLOTS} {slot_type}s at once"
                    )

            slot.value = value
            slot.interval_seconds = interval_seconds
            slot.running = True

            # each slot gets its OWN independent scheduled job / countdown
            slot.job = scheduler.add_job(
                func=_check_slot,
                trigger="interval",
                seconds=interval_seconds,
                id=slot.job_id,
                args=[slot],
                replace_existing=True,
            )
            return slot

    def stop(self, slot_type, slot_index):
        with _lock:
            slot = self.get_slot(slot_type, slot_index)
            if slot.running and scheduler.get_job(slot.job_id):
                scheduler.remove_job(slot.job_id)
            slot.running = False
            slot.job = None
            return slot

    def status(self):
        return {
            "emails": [s.to_dict() for s in self.email_slots],
            "passwords": [s.to_dict() for s in self.password_slots],
        }


manager = MonitorManager()

# Maps each slot type to the real table/column names from database.db
# (built by breached_emails_inserting.py / breached_pass_inserting.py).
_TABLE_MAP = {
    "email": {"table": "breachedemails", "column": "emails"},
    "password": {"table": "breachedpasswords", "column": "passwords"},
}


def _check_slot(slot: MonitorSlot):
    """Runs only when this slot's own countdown hits 0.
    Checks the breach DB and, on a hit, just records the finding."""
    table = _TABLE_MAP[slot.slot_type]["table"]
    column = _TABLE_MAP[slot.slot_type]["column"]

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT 1 FROM {table} WHERE {column} = ? LIMIT 1", (slot.value,))
        result = cursor.fetchone()
    finally:
        conn.close()

    slot.last_checked_at = datetime.now().isoformat(timespec="seconds")

    if result:
        finding = {
            "value": slot.value,
            "timestamp": slot.last_checked_at,
            "source": table,
        }
        slot.findings.append(finding)
        return finding

    return None


# --------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------

@app.route("/", methods=["GET"])
@app.route("/monitor", methods=["GET"])
def dashboard():
    """Serves the live monitoring dashboard (templates/monitor_dashboard.html)."""
    return render_template("monitor_dashboard.html")


@app.route("/monitor/<slot_type>/start", methods=["POST"])
def start_monitor(slot_type):
    """
    Body JSON: { "value": "<email or password>", "interval_seconds": 30, "slot_index": 0 }
    slot_index is optional - if omitted, the first free slot is used.
    """
    if slot_type not in ("email", "password"):
        return jsonify({"error": "slot_type must be 'email' or 'password'"}), 400

    data = request.get_json(force=True) or {}
    value = data.get("value")
    if not value:
        return jsonify({"error": "'value' is required"}), 400

    interval_seconds = int(data.get("interval_seconds", DEFAULT_INTERVAL_SECONDS))
    slot_index = data.get("slot_index")

    try:
        slot = manager.start(slot_type, value, interval_seconds, slot_index)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 409
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify(slot.to_dict()), 200


@app.route("/monitor/<slot_type>/<int:slot_index>/stop", methods=["POST"])
def stop_monitor(slot_type, slot_index):
    if slot_type not in ("email", "password"):
        return jsonify({"error": "slot_type must be 'email' or 'password'"}), 400
    try:
        slot = manager.stop(slot_type, slot_index)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(slot.to_dict()), 200


@app.route("/monitor/status", methods=["GET"])
def status():
    """Poll this to render both boxes: emails[], passwords[] with each
    slot's own running state, live countdown, and findings."""
    return jsonify(manager.status()), 200


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)