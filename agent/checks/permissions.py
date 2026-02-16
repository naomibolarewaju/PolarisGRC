import os
import stat
import time
from pathlib import Path

SCAN_DIRS = ["/etc", "/home"]
MAX_DEPTH = 3
SCAN_TIMEOUT = 10
MAX_EXAMPLES = 5


class PermissionChecker:
    #file permission security checks

    def __init__(self) -> None:
        #initialize PermissionChecker with empty checks list
        self.checks: list[dict] = []

    def check_world_writable_files(self) -> dict:
        #check for world-writable files in /etc and /home
        result: dict = {
            "check_id": "no_world_writable_files",
            "name": "No World-Writable Files in /etc or /home",
            "category": "File Permissions",
            "status": "PASS",
            "severity": "HIGH",
            "finding": "",
            "remediation": None,
            "requires_privilege": True,
            "privilege_level": "root",
            "skip_reason": None,
            "cis_reference": "1.1.5",
            "compliance_mappings": {
                "iso27001": ["A.9.4.5"],
                "gdpr": ["Article 32(1)(b)"],
                "nist_csf": ["PR.AC-4"],
            },
        }

        world_writable: list[str] = []
        permission_denied = False
        timed_out = False
        start_time = time.monotonic()

        for scan_dir in SCAN_DIRS:
            if timed_out:
                break

            base_path = Path(scan_dir)
            if not base_path.is_dir():
                continue

            try:
                for dirpath, dirnames, filenames in os.walk(scan_dir):
                    # Enforce depth limit
                    depth = dirpath[len(scan_dir):].count(os.sep)
                    if depth >= MAX_DEPTH:
                        dirnames.clear()
                        continue

                    # Enforce timeout
                    if time.monotonic() - start_time > SCAN_TIMEOUT:
                        timed_out = True
                        break

                    for filename in filenames:
                        filepath = os.path.join(dirpath, filename)
                        try:
                            file_stat = os.stat(filepath)
                            if file_stat.st_mode & stat.S_IWOTH:
                                world_writable.append(filepath)
                        except (PermissionError, OSError):
                            permission_denied = True
                            continue
            except PermissionError:
                permission_denied = True
                continue

        if world_writable:
            examples = ", ".join(world_writable[:MAX_EXAMPLES])
            result["status"] = "FAIL"
            qualifiers: list[str] = []
            if timed_out:
                qualifiers.append("scan timed out before completing")
            if permission_denied:
                qualifiers.append("some directories were inaccessible due to insufficient privileges")
            if qualifiers:
                note = " (incomplete scan: " + "; ".join(qualifiers) + ")"
            else:
                note = ""
            result["finding"] = f"Found {len(world_writable)} world-writable files: {examples}{note}"
            result["remediation"] = (
                "Remove world-write permission:\n"
                "  sudo chmod o-w <filepath>"
            )
        elif timed_out:
            result["status"] = "SKIPPED"
            result["finding"] = "Scan timed out before completing; results are inconclusive"
            result["skip_reason"] = f"Scan exceeded {SCAN_TIMEOUT}s timeout before all directories were checked"
        elif permission_denied:
            result["status"] = "SKIPPED"
            result["finding"] = "Insufficient privileges to fully scan directories"
            result["skip_reason"] = "Requires root privileges for complete file permission scan"
        else:
            result["status"] = "PASS"
            result["finding"] = "No world-writable files found"

        self.checks.append(result)
        return result

    def run_all_checks(self) -> list[dict]:
        #run all file permission security checks
        self.checks = []
        self.check_world_writable_files()
        return self.checks
