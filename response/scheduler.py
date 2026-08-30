"""
response/scheduler.py
---------------------
Runs recurring scheduled threat analysis scans in a background thread.
"""

import time
import threading
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import sessionmaker

from database.models import ScheduledScan, create_tables
from detection.risk_engine import analyze_ip
from response.notifier import send_telegram_alert

_SCHEDULER_THREAD = None
_RUNNING = False


def _scheduler_loop():
    """
    Main loop executing every 60 seconds. Checks active ScheduledScan rows,
    executes analyze_ip if due, sends Telegram alert if needed, and updates timestamps.
    """
    global _RUNNING
    engine = create_tables()
    Session = sessionmaker(bind=engine)

    print("[Scheduler] Background scheduler loop started.")

    while _RUNNING:
        session = Session()
        try:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            # Find active scans where next_run is null or next_run <= now
            due_scans = session.query(ScheduledScan).filter(
                ScheduledScan.active == 1,
                (ScheduledScan.next_run.is_(None)) | (ScheduledScan.next_run <= now)
            ).all()

            for scan in due_scans:
                target_ip = scan.target_ip
                print(f"[Scheduler] Running scheduled threat scan for {target_ip}...")

                try:
                    # Run threat analysis
                    scan_result = analyze_ip(target_ip)
                    # Trigger Telegram alert if threshold met
                    send_telegram_alert(scan_result)

                    # Update timestamps
                    scan.last_run = now
                    interval = scan.interval_hours if scan.interval_hours > 0 else 24
                    scan.next_run = now + timedelta(hours=interval)
                    session.commit()
                    print(f"[Scheduler] Completed scan for {target_ip}. Next run scheduled at {scan.next_run}")

                except Exception as scan_err:
                    session.rollback()
                    print(f"[Scheduler] Error running scheduled scan for {target_ip}: {scan_err}")

        except Exception as loop_err:
            session.rollback()
            print(f"[Scheduler] Loop execution error: {loop_err}")
        finally:
            session.close()

        # Sleep for 60 seconds
        for _ in range(60):
            if not _RUNNING:
                break
            time.sleep(1)


def start_scheduler():
    """
    Starts the scheduler background thread if not already running.
    """
    global _SCHEDULER_THREAD, _RUNNING
    if _SCHEDULER_THREAD is not None and _SCHEDULER_THREAD.is_alive():
        return

    _RUNNING = True
    _SCHEDULER_THREAD = threading.Thread(target=_scheduler_loop, daemon=True, name="ScanSchedulerThread")
    _SCHEDULER_THREAD.start()
    print("[Scheduler] Thread initialized.")
