import json
import platform
import sys
from datetime import datetime
from pathlib import Path

import click

from agent.checks.firewall import FirewallChecker
from agent.checks.passwords import PasswordChecker
from agent.checks.ssh import SSHChecker
from agent.checks.users import UserChecker

AGENT_VERSION = "1.0.0"


@click.command()
@click.option("--output", default="scan_results.json", help="Output file path for scan results.")
@click.option("--privileged", is_flag=True, default=False, help="Enable checks that require elevated privileges.")
@click.option("--show-privileged", is_flag=True, default=False, help="Show which checks require elevated privileges and exit.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show detailed output including failed check remediation.")
def scan(output: str, privileged: bool, show_privileged: bool, verbose: bool) -> None:
    """Run PolarisGRC security audit checks on the local system."""
    click.echo(f"PolarisGRC Agent v{AGENT_VERSION}")
    click.echo()

    if platform.system() != "Linux":
        click.echo(f"Warning: Running on {platform.system()}, not Linux. Some checks may fail.")
        click.echo()

    checkers = [SSHChecker(), FirewallChecker(), UserChecker(), PasswordChecker()]

    if show_privileged:
        all_checks: list[dict] = []
        for checker in checkers:
            all_checks.extend(checker.run_all_checks())

        priv_checks = [c for c in all_checks if c.get("requires_privilege")]
        if priv_checks:
            click.echo("Checks requiring elevated privileges:")
            for check in priv_checks:
                level = check.get("privilege_level", "root")
                click.echo(f"  - {check['name']} (requires {level})")
        else:
            click.echo("No checks currently require elevated privileges.")
        sys.exit(0)

    # Run all checks
    all_checks = []
    for checker in checkers:
        all_checks.extend(checker.run_all_checks())

    # Filter privileged checks when not running in privileged mode
    if not privileged:
        for check in all_checks:
            if check.get("requires_privilege"):
                check["status"] = "SKIPPED"
                check["skip_reason"] = check.get(
                    "skip_reason",
                    f"Requires {check.get('privilege_level', 'root')} privileges. Run with --privileged flag.",
                )

    # Calculate summary
    summary = {
        "total": len(all_checks),
        "passed": sum(1 for c in all_checks if c["status"] == "PASS"),
        "failed": sum(1 for c in all_checks if c["status"] == "FAIL"),
        "skipped": sum(1 for c in all_checks if c["status"] == "SKIPPED"),
        "errors": sum(1 for c in all_checks if c["status"] == "ERROR"),
    }

    # Build scan data
    scan_data = {
        "agent_version": AGENT_VERSION,
        "hostname": platform.node(),
        "os_info": {
            "name": platform.system(),
            "version": platform.release(),
        },
        "scan_timestamp": datetime.now().isoformat(),
        "privileged_mode": privileged,
        "checks": all_checks,
        "summary": summary,
    }

    # Save to file
    output_path = Path(output)
    output_path.write_text(json.dumps(scan_data, indent=2))
    click.echo(f"Results saved to {output_path}")
    click.echo()

    # Print summary
    click.echo("Scan Summary:")
    click.echo(f"  Total:   {summary['total']}")
    click.echo(f"  Passed:  {summary['passed']}")
    click.echo(f"  Failed:  {summary['failed']}")
    click.echo(f"  Skipped: {summary['skipped']}")
    click.echo(f"  Errors:  {summary['errors']}")

    # Verbose: show failed checks with remediation
    if verbose:
        failed = [c for c in all_checks if c["status"] == "FAIL"]
        if failed:
            click.echo()
            click.echo("Failed Checks:")
            for check in failed:
                click.echo(f"  [{check['severity']}] {check['name']}")
                click.echo(f"    Finding: {check['finding']}")
                if check.get("remediation"):
                    click.echo(f"    Remediation: {check['remediation']}")
                click.echo()


if __name__ == "__main__":
    scan()
