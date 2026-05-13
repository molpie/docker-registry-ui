import logging
import fcntl
import os
import re
import threading
from datetime import datetime, timedelta

from .config import Config
from .data_store import get_scan_results, store_scan_results
from .registry import (
    fetch_repositories,
    fetch_repository_tags,
    fetch_tag_details,
    get_auth,
)
from .scanners.factory import get_scanner
from .scanners.trivy import TrivyScanner

logger = logging.getLogger(__name__)
_massive_scan_thread_lock = threading.Lock()


def _scan_in_progress_response(registry_name):
    return {
        "success": False,
        "code": "massive_scan_in_progress",
        "error": f"Massive scan already in progress for {registry_name}",
    }


def _get_scanner_auth_config(registry):
    auth = registry.get("auth")
    if isinstance(auth, dict):
        return auth

    if registry.get("isAuthEnabled"):
        if registry.get("apiToken"):
            return {"type": "bearer", "token": registry.get("apiToken")}
        if registry.get("user") and registry.get("password"):
            return {
                "type": "basic",
                "username": registry.get("user"),
                "password": registry.get("password"),
            }

    return None


def run_massive_scan(registry_name, registry, options=None):
    """Run a massive scan and return a summary payload compatible with API response."""
    lock_dir = os.path.dirname(Config.DB_PATH) or "/tmp"
    lock_path = os.getenv(
        "MASSIVE_SCAN_LOCK_FILE", os.path.join(lock_dir, "massive_scan.lock")
    )
    os.makedirs(os.path.dirname(lock_path) or "/tmp", exist_ok=True)

    if not _massive_scan_thread_lock.acquire(blocking=False):
        logger.warning(
            f"Skipping massive scan for {registry_name}: another scan is already running (thread lock)"
        )
        return _scan_in_progress_response(registry_name)

    lock_file = None
    try:
        lock_file = open(lock_path, "a+")
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logger.warning(
                f"Skipping massive scan for {registry_name}: another scan is already running (process lock)"
            )
            return _scan_in_progress_response(registry_name)

        options = options or {}
        repo_pattern = options.get("repoPattern", "*")
        scan_mode = options.get("mode", "all")
        age_value = options.get("ageValue")
        if age_value is not None:
            try:
                age_value = int(age_value)
            except (ValueError, TypeError):
                age_value = None
        age_unit = options.get("ageUnit", "days")
        include_all_tags = options.get("includeAllTags", True)
        dry_run = options.get("dryRun", True)
        run_source = options.get("source", "manual")
        run_timezone = options.get("timezone", "local")

        # Determine scanner from registry config
        vuln_scan = registry.get("vulnerabilityScan", {})
        scanner_type = vuln_scan.get("scanner", "trivy")
        scanner_url = vuln_scan.get("scannerUrl", "")
        if scanner_type == "trivy" and not scanner_url:
            scanner_url = "http://localhost:3000"

        try:
            scanner = get_scanner(scanner_type, scanner_url)
        except ValueError:
            scanner = TrivyScanner("builtin", 300)

        auth = get_auth(registry)
        repos, error = fetch_repositories(registry["api"], auth)
        if error:
            from .data_store import store_massive_scan_run

            failed_summary = {
                "registry": registry_name,
                "runAt": datetime.now().isoformat(),
                "source": run_source,
                "timezone": run_timezone,
                "success": False,
                "dryRun": dry_run,
                "totalImages": 0,
                "totalTags": 0,
                "totalScans": 0,
                "skipped": 0,
                "errors": 1,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "error": error,
            }
            store_massive_scan_run(registry_name, failed_summary)
            return {"success": False, "error": error}

        if repo_pattern and repo_pattern != "*":
            pattern = repo_pattern.replace("*", ".*")
            repos = [r for r in repos if re.match(pattern, r)]

        logger.info(
            f"Starting massive scan for {registry_name}: {len(repos)} repos, {scan_mode} mode"
        )

        age_cutoff = None
        if scan_mode == "older" and age_value:
            multiplier = {"days": 1, "weeks": 7, "months": 30}.get(age_unit, 1)
            age_cutoff = datetime.now() - timedelta(days=age_value * multiplier)

        existing_results = {}
        if scan_mode in ["unscanned", "never-scanned"]:
            existing_results = get_scan_results(registry_name)

        results = []
        scanned_count = 0
        skipped_count = 0
        error_count = 0
        total_tags = 0
        severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for repo in repos:
            tags = fetch_repository_tags(registry["api"], repo, auth)
            total_tags += len(tags)
            if not include_all_tags:
                tags = tags[:1]

            for tag in tags:
                details = fetch_tag_details(registry["api"], repo, tag, auth)

                if scan_mode == "older" and age_cutoff and details.get("created"):
                    try:
                        created = datetime.fromisoformat(
                            details["created"].replace("Z", "+00:00")
                        )
                        if created > age_cutoff:
                            skipped_count += 1
                            continue
                    except Exception:
                        pass

                key = f"{repo}:{tag}"
                already_scanned = key in existing_results

                if scan_mode == "unscanned" and already_scanned:
                    skipped_count += 1
                    continue
                if scan_mode == "never-scanned" and already_scanned:
                    existing = existing_results[key]
                    if (
                        existing
                        and not existing.get("error")
                        and existing.get("total", 0) >= 0
                    ):
                        skipped_count += 1
                        continue

                result_entry = {"repo": repo, "tag": tag, "status": "pending"}

                if dry_run:
                    result_entry["status"] = "dry-run"
                    scanned_count += 1
                    results.append(result_entry)
                    continue

                try:
                    logger.info(f"Scanning {repo}:{tag}")
                    result = scanner.scan_image(
                        registry["api"],
                        repo,
                        tag,
                        _get_scanner_auth_config(registry),
                    )
                    if result.get("error"):
                        result_entry["status"] = "error"
                        result_entry["error"] = result.get("error")
                        error_count += 1
                    else:
                        store_scan_results(registry_name, repo, tag, result)
                        result_entry["status"] = "success"
                        result_entry["result"] = result
                        scanned_count += 1
                        summary = result.get("summary", {})
                        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                            severity_totals[sev] += int(summary.get(sev, 0) or 0)
                except Exception as e:
                    result_entry["status"] = "error"
                    result_entry["error"] = str(e)
                    error_count += 1

                results.append(result_entry)

        logger.info(
            f"Massive scan completed: {scanned_count} scanned, {skipped_count} skipped, {error_count} errors"
        )

        from .data_store import store_massive_scan_run

        run_summary = {
            "registry": registry_name,
            "runAt": datetime.now().isoformat(),
            "source": run_source,
            "timezone": run_timezone,
            "success": True,
            "dryRun": dry_run,
            "totalImages": len(repos),
            "totalTags": total_tags,
            "totalScans": scanned_count,
            "scanned": scanned_count,
            "skipped": skipped_count,
            "errors": error_count,
            "critical": severity_totals["CRITICAL"],
            "high": severity_totals["HIGH"],
            "medium": severity_totals["MEDIUM"],
            "low": severity_totals["LOW"],
        }
        store_massive_scan_run(registry_name, run_summary)

        return {
            "success": True,
            "scanned": scanned_count,
            "skipped": skipped_count,
            "errors": error_count,
            "results": results,
            "dryRun": dry_run,
            "runSummary": run_summary,
        }
    finally:
        if lock_file is not None:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                lock_file.close()
            except Exception:
                pass
        _massive_scan_thread_lock.release()
