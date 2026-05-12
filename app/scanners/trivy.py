import requests
import logging
from .base import VulnerabilityScanner

logger = logging.getLogger(__name__)


class TrivyScanner(VulnerabilityScanner):
    """Trivy vulnerability scanner integration"""

    def scan_image(self, registry_url, repository, tag, auth_config=None):
        """Scan image using Trivy CLI"""
        try:
            import subprocess
            import json

            registry_host = registry_url.replace("http://", "").replace("https://", "")
            image_ref = f"{registry_host}/{repository}:{tag}"

            logger.debug(f"[TRIVY] Scanning image: {image_ref}")

            auth_args = []
            if isinstance(auth_config, dict):
                auth_type = auth_config.get("type")
                if auth_type == "basic":
                    username = auth_config.get("username")
                    password = auth_config.get("password")
                    if username and password:
                        auth_args = ["--username", username, "--password", password]
                elif auth_type == "bearer":
                    token = auth_config.get("token")
                    if token:
                        auth_args = ["--registry-token", token]

            attempts = [
                {"name": "default", "extra_args": []},
                {
                    "name": "ghcr-fallback",
                    "extra_args": ["--db-repository", "ghcr.io/aquasecurity/trivy-db"],
                },
            ]

            last_error = "No output"
            last_exit_code = None

            for attempt in attempts:
                cmd = (
                    [
                        "trivy",
                        "image",
                        "--format",
                        "json",
                        "--scanners",
                        "vuln",
                        "--image-src",
                        "remote",
                        "--insecure",
                        "--timeout",
                        "5m",
                    ]
                    + auth_args
                    + attempt["extra_args"]
                    + [image_ref]
                )

                logger.debug(f"[TRIVY] Running attempt '{attempt['name']}'")
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300
                )
                last_exit_code = result.returncode

                logger.debug(
                    f"[TRIVY] Exit code ({attempt['name']}): {result.returncode}"
                )

                if result.returncode == 0 and result.stdout:
                    report = json.loads(result.stdout)
                    return self._parse_trivy_report(report)

                stderr_text = (result.stderr or "").strip()
                stdout_text = (result.stdout or "").strip()
                combined_error = stderr_text or stdout_text or "No output"
                last_error = combined_error
                logger.error(
                    f"[TRIVY] Attempt '{attempt['name']}' failed: {combined_error[:1000]}"
                )

            return {
                "error": f"Scan failed: {last_error[:500]}",
                "scanner": "trivy",
                "exitCode": last_exit_code,
            }
        except subprocess.TimeoutExpired:
            return {"error": "Scan timeout after 5 minutes"}
        except Exception as e:
            logger.error(f"[TRIVY] Exception: {str(e)}")
            return {"error": str(e)}

    def _parse_trivy_report(self, report):
        """Parse Trivy JSON report"""
        vulnerabilities = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }
        details = []
        layers = []
        base_image_exposure = {
            "total": 0,
            "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        }

        for result in report.get("Results", []):
            target = result.get("Target", "")
            result_class = result.get("Class", "")
            is_base_target = result_class == "os-pkgs"
            layer_vulns = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "UNKNOWN": 0,
            }
            layer_details = []

            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN")
                vulnerabilities[severity] = vulnerabilities.get(severity, 0) + 1
                layer_vulns[severity] = layer_vulns.get(severity, 0) + 1

                layer_info = vuln.get("Layer", {})
                layer_digest = layer_info.get("Digest", "") if layer_info else ""
                is_base_vuln = is_base_target or not layer_digest
                if is_base_vuln:
                    base_image_exposure["total"] += 1
                    base_image_exposure["summary"][severity] = (
                        base_image_exposure["summary"].get(severity, 0) + 1
                    )

                vuln_detail = {
                    "id": vuln.get("VulnerabilityID"),
                    "severity": severity,
                    "package": vuln.get("PkgName"),
                    "version": vuln.get("InstalledVersion"),
                    "fixedVersion": vuln.get("FixedVersion"),
                    "title": vuln.get("Title"),
                    "layer": layer_digest[:12] if layer_digest else "",
                    "origin": "BASE" if is_base_vuln else "APP",
                    "isBaseImage": is_base_vuln,
                }
                details.append(vuln_detail)
                layer_details.append(vuln_detail)

            if layer_details:
                layers.append(
                    {
                        "target": target,
                        "digest": target.split(":")[-1][:12] if ":" in target else "",
                        "isBase": is_base_target,
                        "class": result_class,
                        "summary": layer_vulns,
                        "total": sum(layer_vulns.values()),
                        "vulnerabilities": layer_details,
                    }
                )

        return {
            "scanner": "trivy",
            "summary": vulnerabilities,
            "total": sum(vulnerabilities.values()),
            "details": details,
            "layers": layers,
            "baseImageExposure": base_image_exposure,
        }

    def get_report(self, scan_id):
        return {"error": "Trivy doesn't support report retrieval"}

    def health_check(self):
        try:
            response = requests.get(f"{self.scanner_url}/healthz", timeout=5)
            return response.status_code == 200
        except:
            return False
