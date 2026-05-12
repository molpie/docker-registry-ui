import logging
import re
from datetime import datetime, timedelta

from .data_store import get_scan_results, store_scan_results
from .registry import fetch_repositories, fetch_repository_tags, fetch_tag_details, get_auth
from .scanners.factory import get_scanner
from .scanners.trivy import TrivyScanner

logger = logging.getLogger(__name__)


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

    for repo in repos:
        tags = fetch_repository_tags(registry["api"], repo, auth)
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
                if existing and not existing.get("error") and existing.get("total", 0) >= 0:
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
            except Exception as e:
                result_entry["status"] = "error"
                result_entry["error"] = str(e)
                error_count += 1

            results.append(result_entry)

    logger.info(
        f"Massive scan completed: {scanned_count} scanned, {skipped_count} skipped, {error_count} errors"
    )

    return {
        "success": True,
        "scanned": scanned_count,
        "skipped": skipped_count,
        "errors": error_count,
        "results": results,
        "dryRun": dry_run,
    }
