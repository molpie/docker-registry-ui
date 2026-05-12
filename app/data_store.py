from .config import Config

# Simple in-memory cache for repositories (no background updates)
registry_cache = {}
scan_results = {}


def get_registries():
    """Get list of configured registries"""
    return Config.REGISTRIES


def get_registry_by_name(name):
    """Get registry config by name"""
    for reg in Config.REGISTRIES:
        # Handle both string and dictionary formats
        if isinstance(reg, str):
            if reg == name:
                return {
                    "name": reg,
                    "api": "http://registry:5000",  # Default for development
                    "isAuthEnabled": False,
                    "default": True,
                    "bulkOperationsEnabled": False,
                }
        else:
            if reg["name"] == name:
                return reg
    return None


def cache_repositories(registry_name, repos):
    """Cache repository list"""
    registry_cache[registry_name] = repos


def get_cached_repositories(registry_name):
    """Get cached repository list"""
    return registry_cache.get(registry_name, [])


def update_registry_bulk_ops(registry_name, enabled):
    """Update bulk operations setting for a registry"""
    for reg in Config.REGISTRIES:
        if reg["name"] == registry_name:
            reg["bulkOperationsEnabled"] = enabled
            Config.save_registries()
            return True
    return False


def update_registry_config(registry_name, config):
    """Update registry configuration"""
    for reg in Config.REGISTRIES:
        if reg["name"] == registry_name:
            reg["bulkOperationsEnabled"] = config.get("bulkOperationsEnabled", False)
            if "vulnerabilityScan" in config:
                if "vulnerabilityScan" not in reg:
                    reg["vulnerabilityScan"] = {}
                reg["vulnerabilityScan"]["enabled"] = config["vulnerabilityScan"].get(
                    "enabled", False
                )
                reg["vulnerabilityScan"]["scanner"] = config["vulnerabilityScan"].get(
                    "scanner", "trivy"
                )
                reg["vulnerabilityScan"]["scannerUrl"] = config[
                    "vulnerabilityScan"
                ].get("scannerUrl", "")
                reg["vulnerabilityScan"]["autoScan"] = config["vulnerabilityScan"].get(
                    "autoScan", False
                )
            # Handle auth configuration
            if "auth" in config:
                reg["auth"] = config["auth"]
            elif (
                "isAuthEnabled" in config
                or "user" in config
                or "password" in config
                or "apiToken" in config
            ):
                # Convert old format to new format
                if config.get("isAuthEnabled"):
                    if config.get("apiToken"):
                        reg["auth"] = {
                            "type": "bearer",
                            "token": config.get("apiToken", ""),
                        }
                    else:
                        reg["auth"] = {
                            "type": "basic",
                            "username": config.get("user", ""),
                            "password": config.get("password", ""),
                        }
                else:
                    # Auth disabled - remove auth if present
                    reg.pop("auth", None)
                # Remove old fields
                reg.pop("isAuthEnabled", None)
                reg.pop("user", None)
                reg.pop("password", None)
                reg.pop("apiToken", None)
            Config.save_registries()
            return True
    return False


def store_scan_results(registry_name, repo, tag, result, ttl_hours=24):
    """Store vulnerability scan results"""
    from datetime import datetime
    import json
    import os

    # --- Unified scan result schema ---
    from hashlib import sha256
    import copy

    schema_version = 1
    now = datetime.now().isoformat()
    # Compose cache key: registry/repo/tag@digest (digest may be missing at this stage)
    digest = result.get("digest") or result.get("imageDigest") or None
    cache_key = f"{repo}:{tag}"
    # Compose normalized result
    normalized = {
        "schemaVersion": schema_version,
        "scanner": result.get("scanner", "unknown"),
        "scannedAt": now,
        "registry": registry_name,
        "repo": repo,
        "tag": tag,
        "digest": digest,
        "summary": result.get("summary", {}),
        "total": result.get("total", 0),
        "details": result.get("details", []),
        "layers": result.get("layers", []),
        "baseImageExposure": result.get("baseImageExposure", None),
        "raw": copy.deepcopy(result),
    }
    # Store in memory with TTL
    if registry_name not in scan_results:
        scan_results[registry_name] = {}
    normalized["cacheTTL"] = ttl_hours
    normalized["cacheExpiresAt"] = None
    if ttl_hours > 0:
        from datetime import timedelta
        from datetime import datetime as dt

        expires = dt.fromisoformat(now) + timedelta(hours=ttl_hours)
        normalized["cacheExpiresAt"] = expires.isoformat()
    scan_results[registry_name][cache_key] = normalized
    # Persist to per-image file only (legacy, for now)
    data_dir = (
        os.path.dirname(Config.CONFIG_FILE) if Config.CONFIG_FILE else "/app/data"
    )
    os.makedirs(data_dir, exist_ok=True)
    image_file = os.path.join(data_dir, f"{repo.replace('/', '_')}_{tag}.json")
    try:
        with open(image_file, "w") as f:
            json.dump(normalized, f, indent=2)
        print(f"Saved scan to: {image_file}")
    except Exception as e:
        print(f"Failed to save scan to {image_file}: {e}")


def get_scan_results(registry_name, force_refresh=False, ttl_hours=24):
    """Get all scan results for a registry from individual image files"""
    import json
    import os
    import glob

    if registry_name not in scan_results:
        scan_results[registry_name] = {}

    data_dir = (
        os.path.dirname(Config.CONFIG_FILE) if Config.CONFIG_FILE else "/app/data"
    )

    # Load all individual scan files (legacy and new)
    scan_files = glob.glob(os.path.join(data_dir, "*_*.json"))
    for scan_file in scan_files:
        filename = os.path.basename(scan_file)
        # Skip registry config files
        if filename.startswith("scan_results_") or filename == "registries.config.json":
            continue
        try:
            with open(scan_file, "r") as f:
                result = json.load(f)
                # Normalize if missing schemaVersion (legacy)
                if "schemaVersion" not in result:
                    repo = result.get("repo")
                    tag = result.get("tag")
                    if repo and tag:
                        key = f"{repo}:{tag}"
                        scan_results[registry_name][key] = result
                else:
                    repo = result.get("repo")
                    tag = result.get("tag")
                    if repo and tag:
                        key = f"{repo}:{tag}"
                        scan_results[registry_name][key] = result
        except Exception as e:
            print(f"Failed to load {scan_file}: {e}")

    print(f"Loaded {len(scan_results[registry_name])} scan results for {registry_name}")
    # Invalidate cache if expired or digest changed (soft/hard)
    from datetime import datetime as dt

    results = scan_results.get(registry_name, {})
    valid_results = {}
    for key, res in results.items():
        expires = res.get("cacheExpiresAt")
        digest = res.get("digest")
        if force_refresh:
            continue
        if expires:
            try:
                if dt.fromisoformat(expires) < dt.now():
                    continue  # TTL expired
            except Exception:
                pass
        # (Digest check: handled at scan time)
        valid_results[key] = res
    return valid_results
