import logging
import threading
import time
from datetime import datetime

from .config import Config
from .data_store import get_registries
from .massive_scan import run_massive_scan
from .notifications import send_massive_scan_recap

logger = logging.getLogger(__name__)

_last_run_date = None
_started = False
_status = {
    "running": False,
    "lastRunAt": None,
    "lastRunDate": None,
    "lastRunSummary": None,
    "lastNotifications": None,
    "lastError": None,
}


def _parse_time_hhmm(value):
    try:
        hour, minute = value.split(":", 1)
        return int(hour), int(minute)
    except Exception:
        return 2, 0


def _resolve_target_registries():
    raw = (Config.MASSIVE_SCAN_REGISTRIES or "all").strip()
    available = [
        r.get("name") for r in get_registries() if isinstance(r, dict) and r.get("name")
    ]
    if raw.lower() == "all":
        return available

    wanted = [x.strip() for x in raw.split(",") if x.strip()]
    return [name for name in wanted if name in available]


def _build_scan_options():
    return {
        "repoPattern": Config.MASSIVE_SCAN_REPO_PATTERN,
        "mode": Config.MASSIVE_SCAN_MODE,
        "ageValue": Config.MASSIVE_SCAN_AGE_VALUE,
        "ageUnit": Config.MASSIVE_SCAN_AGE_UNIT,
        "includeAllTags": Config.MASSIVE_SCAN_INCLUDE_ALL_TAGS,
        "dryRun": Config.MASSIVE_SCAN_DRY_RUN,
    }


def _run_scheduled_job():
    global _status

    registries = get_registries()
    by_name = {
        r.get("name"): r for r in registries if isinstance(r, dict) and r.get("name")
    }
    target_names = _resolve_target_registries()
    if not target_names:
        logger.warning("Scheduled massive scan skipped: no target registries found")
        _status["lastError"] = "no target registries found"
        return

    options = _build_scan_options()
    logger.info(
        f"Starting scheduled massive scan for registries: {', '.join(target_names)}"
    )
    for name in target_names:
        registry = by_name.get(name)
        if not registry:
            continue
        try:
            result = run_massive_scan(name, registry, options)
            if not result.get("success"):
                logger.error(
                    f"Scheduled massive scan failed for {name}: {result.get('error', 'unknown error')}"
                )
                _status["lastError"] = result.get("error", "unknown error")
                continue
            notify_result = send_massive_scan_recap(name, result)
            _status["lastRunSummary"] = {
                "registry": name,
                "scanned": result.get("scanned", 0),
                "skipped": result.get("skipped", 0),
                "errors": result.get("errors", 0),
                "dryRun": result.get("dryRun", False),
            }
            _status["lastNotifications"] = notify_result
            _status["lastError"] = None
        except Exception as e:
            logger.error(f"Scheduled massive scan crashed for {name}: {e}")
            _status["lastError"] = str(e)


def _scheduler_loop():
    global _last_run_date, _status

    hour, minute = _parse_time_hhmm(Config.MASSIVE_SCAN_SCHEDULE_TIME)
    logger.info(
        f"Massive scan scheduler active: daily at {hour:02d}:{minute:02d} ({Config.MASSIVE_SCAN_TIMEZONE})"
    )

    while True:
        try:
            now = datetime.now()
            should_run_now = now.hour == hour and now.minute == minute
            if should_run_now and _last_run_date != now.date():
                _status["lastRunAt"] = now.isoformat()
                _run_scheduled_job()
                _last_run_date = now.date()
                _status["lastRunDate"] = str(_last_run_date)
        except Exception as e:
            logger.error(f"Scheduler loop error: {e}")
            _status["lastError"] = str(e)

        time.sleep(30)


def start_scheduler_if_enabled():
    global _started, _status
    if _started:
        return
    if not Config.MASSIVE_SCAN_SCHEDULE_ENABLED:
        logger.info("Massive scan scheduler is disabled")
        _status["running"] = False
        return

    thread = threading.Thread(
        target=_scheduler_loop, daemon=True, name="massive-scan-scheduler"
    )
    thread.start()
    _started = True
    _status["running"] = True


def get_scheduler_status():
    """Return runtime scheduler status for API/UI."""
    hour, minute = _parse_time_hhmm(Config.MASSIVE_SCAN_SCHEDULE_TIME)
    return {
        "enabled": Config.MASSIVE_SCAN_SCHEDULE_ENABLED,
        "running": _status.get("running", False),
        "scheduleTime": Config.MASSIVE_SCAN_SCHEDULE_TIME,
        "timezone": Config.MASSIVE_SCAN_TIMEZONE,
        "targetRegistries": Config.MASSIVE_SCAN_REGISTRIES,
        "mode": Config.MASSIVE_SCAN_MODE,
        "repoPattern": Config.MASSIVE_SCAN_REPO_PATTERN,
        "includeAllTags": Config.MASSIVE_SCAN_INCLUDE_ALL_TAGS,
        "dryRun": Config.MASSIVE_SCAN_DRY_RUN,
        "lastRunAt": _status.get("lastRunAt"),
        "lastRunDate": _status.get("lastRunDate"),
        "lastRunSummary": _status.get("lastRunSummary"),
        "lastNotifications": _status.get("lastNotifications"),
        "lastError": _status.get("lastError"),
        "parsedSchedule": {"hour": hour, "minute": minute},
    }
