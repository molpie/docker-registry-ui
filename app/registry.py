import requests
from requests.auth import HTTPBasicAuth
from .config import Config


def _build_request_auth(auth):
    """Build headers/auth tuple for requests from auth config."""
    headers = auth if isinstance(auth, dict) else {}
    auth_obj = auth if isinstance(auth, HTTPBasicAuth) else None
    return headers, auth_obj


def get_auth(registry):
    """Get authentication for registry"""
    auth_config = registry.get("auth", {})
    if not isinstance(auth_config, dict):
        auth_config = {}
    auth_type = auth_config.get("type")

    if auth_type == "basic":
        username = auth_config.get("username")
        password = auth_config.get("password")
        if username and password:
            return HTTPBasicAuth(username, password)
    elif auth_type == "bearer":
        token = auth_config.get("token")
        if token:
            return {"Authorization": f"Bearer {token}"}

    # Fallback to old format for backward compatibility
    if registry.get("isAuthEnabled"):
        if registry.get("apiToken"):
            return {"Authorization": f"Bearer {registry['apiToken']}"}
        elif registry.get("user") and registry.get("password"):
            return HTTPBasicAuth(registry["user"], registry["password"])

    return None


def format_size(bytes):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes < 1024.0:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.2f} PB"


def fetch_repositories(registry_api, auth=None):
    """Fetch repository list only (lightweight)"""
    try:
        headers, auth_obj = _build_request_auth(auth)

        r = requests.get(
            f"{registry_api}/v2/_catalog",
            headers=headers,
            auth=auth_obj,
            timeout=Config.TIMEOUT,
        )

        if r.status_code == 200:
            repos = r.json().get("repositories", [])
            return sorted(repos), None
        else:
            return [], f"HTTP {r.status_code}"
    except Exception as e:
        return [], str(e)


def fetch_repository_tags(registry_api, repo, auth=None):
    """Fetch tags for a specific repository (on-demand)"""
    try:
        headers, auth_obj = _build_request_auth(auth)

        r = requests.get(
            f"{registry_api}/v2/{repo}/tags/list",
            headers=headers,
            auth=auth_obj,
            timeout=Config.TIMEOUT,
        )

        if r.status_code != 200:
            return []

        tags = r.json().get("tags", []) or []
        return tags
    except:
        return []


def fetch_tag_details(registry_api, repo, tag, auth=None):
    """Fetch details for a specific tag (on-demand)"""
    try:
        auth_obj = auth if isinstance(auth, HTTPBasicAuth) else None

        # Try multiple manifest formats (order matters - try most common first)
        manifest_formats = [
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        ]

        for accept_type in manifest_formats:
            headers = {"Accept": accept_type}
            if isinstance(auth, dict):
                headers.update(auth)

            r = requests.get(
                f"{registry_api}/v2/{repo}/manifests/{tag}",
                headers=headers,
                auth=auth_obj,
                timeout=Config.TIMEOUT,
            )

            if r.status_code != 200:
                continue

            data = r.json()

            # Handle manifest list (multi-arch)
            if "manifests" in data:
                for manifest_ref in data["manifests"]:
                    # Skip attestation manifests
                    if (
                        manifest_ref.get("annotations", {}).get(
                            "vnd.docker.reference.type"
                        )
                        == "attestation-manifest"
                    ):
                        continue

                    # Get the actual manifest
                    manifest_digest = manifest_ref["digest"]
                    headers2 = {"Accept": "application/vnd.oci.image.manifest.v1+json"}
                    if isinstance(auth, dict):
                        headers2.update(auth)

                    r2 = requests.get(
                        f"{registry_api}/v2/{repo}/manifests/{manifest_digest}",
                        headers=headers2,
                        auth=auth_obj,
                        timeout=Config.TIMEOUT,
                    )

                    if r2.status_code == 200:
                        manifest = r2.json()
                        layers = manifest.get("layers", [])
                        config_size = manifest.get("config", {}).get("size", 0)
                        size = (
                            sum(layer.get("size", 0) for layer in layers) + config_size
                        )

                        # Get created timestamp from config
                        created = None
                        config_digest = manifest.get("config", {}).get("digest")
                        if config_digest:
                            config_r = requests.get(
                                f"{registry_api}/v2/{repo}/blobs/{config_digest}",
                                headers=headers2,
                                auth=auth_obj,
                                timeout=Config.TIMEOUT,
                            )
                            if config_r.status_code == 200:
                                config = config_r.json()
                                created = config.get("created")

                        return {
                            "tag": tag,
                            "size": size,
                            "digest": manifest_digest,
                            "created": created,
                            "manifest": manifest,
                            "config": config if config_digest else {},
                        }
                    else:
                        continue

            # Handle single manifest (v2 schema 2)
            elif "layers" in data:
                manifest = data
                digest = r.headers.get("Docker-Content-Digest", "")
                layers = manifest.get("layers", [])
                config_size = manifest.get("config", {}).get("size", 0)
                size = sum(layer.get("size", 0) for layer in layers) + config_size

                # Get created timestamp from config
                created = None
                config_digest = manifest.get("config", {}).get("digest")
                if config_digest:
                    config_r = requests.get(
                        f"{registry_api}/v2/{repo}/blobs/{config_digest}",
                        headers=headers,
                        auth=auth_obj,
                        timeout=Config.TIMEOUT,
                    )
                    if config_r.status_code == 200:
                        config = config_r.json()
                        created = config.get("created")

                return {
                    "tag": tag,
                    "size": size,
                    "digest": digest,
                    "created": created,
                    "manifest": manifest,
                    "config": config if config_digest else {},
                }

        return {"tag": tag, "size": 0, "digest": "", "created": None}
    except:
        return {"tag": tag, "size": 0, "digest": "", "created": None}


def delete_tag(registry_api, repo, tag, auth=None):
    """Delete a specific tag"""
    try:
        base_headers, auth_obj = _build_request_auth(auth)

        # Try multiple media types and HTTP methods to retrieve candidate digests.
        accept_headers = [
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.docker.distribution.manifest.v1+json",
        ]

        candidate_digests = []
        for accept in accept_headers:
            headers = {"Accept": accept, **base_headers}

            for method in ("head", "get"):
                try:
                    req_fn = requests.head if method == "head" else requests.get
                    manifest_r = req_fn(
                        f"{registry_api}/v2/{repo}/manifests/{tag}",
                        headers=headers,
                        auth=auth_obj,
                        timeout=Config.TIMEOUT,
                    )
                except Exception:
                    continue

                if manifest_r.status_code == 200:
                    digest = manifest_r.headers.get("Docker-Content-Digest")
                    if digest and digest not in candidate_digests:
                        candidate_digests.append(digest)

        if not candidate_digests:
            return False, "No digest found for tag"

        delete_errors = []
        for digest in candidate_digests:
            delete_r = requests.delete(
                f"{registry_api}/v2/{repo}/manifests/{digest}",
                headers=base_headers,
                auth=auth_obj,
                timeout=Config.TIMEOUT,
            )

            if delete_r.status_code in [200, 202]:
                return True, None

            delete_errors.append(f"{digest}: HTTP {delete_r.status_code}")

        return False, "; ".join(delete_errors)
    except Exception as e:
        return False, str(e)


def delete_repository(registry_api, repo, auth=None):
    """Delete entire repository"""
    try:
        tags = fetch_repository_tags(registry_api, repo, auth)
        deleted = 0
        failed_tags = []

        for tag in tags:
            success, error = delete_tag(registry_api, repo, tag, auth)
            if success:
                deleted += 1
            else:
                failed_tags.append(f"{tag} ({error})")

        if failed_tags:
            return (
                False,
                "Failed tags: " + ", ".join(failed_tags),
                deleted,
                len(tags),
            )

        return True, None, deleted, len(tags)
    except Exception as e:
        return False, str(e), 0, 0
