#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

MARKER = "<!-- cloud-health-check-continuous -->"
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
FAIL_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def request_json(url: str, *, method: str = "GET", payload: Any = None, token: str = "") -> Any:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cloud-health-check-continuous/1"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read()
        return json.loads(body) if body else {}


def validate(args: argparse.Namespace) -> int:
    key = os.environ.get("CHC_LICENSE_KEY", "").strip()
    api_url = os.environ.get("CHC_API_URL", "").strip()
    if not key or not api_url:
        print("error: Continuous license or validation endpoint is missing", file=sys.stderr)
        return 2
    try:
        result = request_json(api_url, method="POST", payload={
            "license_key": key,
            "required_plan": "continuous",
            "github_repository": args.repository,
            "github_run_id": args.run_id,
        })
    except urllib.error.HTTPError as error:
        detail = ""
        try:
            detail = json.loads(error.read().decode("utf-8")).get("reason", "")
        except (ValueError, UnicodeDecodeError):
            pass
        print(f"error: Continuous entitlement rejected{f' ({detail})' if detail else ''}", file=sys.stderr)
        return 2
    except urllib.error.URLError as error:
        print(f"error: license validation unavailable ({error.reason})", file=sys.stderr)
        return 2
    if not result.get("valid") or result.get("plan") != "continuous":
        print("error: this workflow requires a Continuous license", file=sys.stderr)
        return 2
    print(f"Continuous entitlement validated for {args.repository}")
    return 0


def verify(args: argparse.Namespace) -> int:
    executable = Path(args.executable)
    expected = Path(args.checksum).read_text(encoding="utf-8").split()[0].lower()
    actual = hashlib.sha256(executable.read_bytes()).hexdigest()
    if actual != expected:
        print("error: downloaded CLI checksum does not match", file=sys.stderr)
        return 2
    print("Cloud Health Check download verified")
    return 0


def sarif_document(report: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in report.get("findings", []):
        rule_id = str(finding.get("rule_id", "CHC"))
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id.replace("-", "_"),
            "shortDescription": {"text": str(finding.get("title", rule_id))},
            "fullDescription": {"text": str(finding.get("impact", "Cloud infrastructure finding"))},
            "help": {"text": str(finding.get("recommendation", "Review this finding."))},
        })
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": str(finding.get("file", ""))},
                "region": {"startLine": max(1, int(finding.get("line") or 1))},
            }
        }
        results.append({
            "ruleId": rule_id,
            "level": LEVELS.get(str(finding.get("severity", "info")), "note"),
            "message": {"text": f"{finding.get('title', rule_id)} — {finding.get('recommendation', '')}"},
            "locations": [location],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {
            "name": "Cloud Health Check",
            "informationUri": "https://cloudhealthcheck.io",
            "rules": list(rules.values()),
        }}, "results": results}],
    }


def markdown_summary(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    scores = report.get("scores", {})
    rows = [
        MARKER,
        "## Cloud Health Check",
        "",
        f"**Overall score:** {scores.get('overall', 0)}/100 · "
        f"**Files:** {report.get('files_scanned', 0)} · "
        f"**Critical:** {summary.get('critical', 0)} · "
        f"**High:** {summary.get('high', 0)} · "
        f"**Medium:** {summary.get('medium', 0)}",
        "",
        "| Severity | Control | Location | Recommendation |",
        "|---|---|---|---|",
    ]
    for finding in report.get("findings", [])[:15]:
        location = f"`{finding.get('file', '')}:{finding.get('line', 1)}`"
        recommendation = str(finding.get("recommendation", "")).replace("|", "\\|").replace("\n", " ")
        title = str(finding.get("title", "")).replace("|", "\\|")
        rows.append(f"| **{str(finding.get('severity', 'info')).upper()}** | {title} | {location} | {recommendation} |")
    if len(report.get("findings", [])) > 15:
        rows.extend(["", f"Showing 15 of {len(report['findings'])} findings. The complete HTML report is available in the workflow output."])
    rows.extend(["", "Generated locally in the GitHub runner. Repository contents were not uploaded to Cloud Health Check."])
    return "\n".join(rows)


def annotation_escape(value: Any, *, property_value: bool = False) -> str:
    text = str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        text = text.replace(":", "%3A").replace(",", "%2C")
    return text


def publish_annotations(report: dict[str, Any]) -> None:
    for finding in report.get("findings", [])[:50]:
        command = LEVELS.get(str(finding.get("severity", "info")), "notice")
        file = annotation_escape(finding.get("file", ""), property_value=True)
        line = max(1, int(finding.get("line") or 1))
        title = annotation_escape(f"{finding.get('rule_id', 'CHC')} · {finding.get('title', '')}", property_value=True)
        message = annotation_escape(finding.get("recommendation", "Review this finding."))
        print(f"::{command} file={file},line={line},title={title}::{message}")


def github_context() -> tuple[str, int | None, str]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    event: dict[str, Any] = {}
    if event_path and Path(event_path).exists():
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    number = event.get("pull_request", {}).get("number")
    ref = event.get("pull_request", {}).get("head", {}).get("ref") or os.environ.get("GITHUB_REF", "")
    return repository, number, ref


def upsert_pr_comment(repository: str, number: int, token: str, body: str) -> None:
    base = f"https://api.github.com/repos/{repository}/issues/{number}/comments"
    comments = request_json(f"{base}?per_page=100", token=token)
    existing = next((item for item in comments if MARKER in item.get("body", "")), None)
    if existing:
        request_json(existing["url"], method="PATCH", payload={"body": body}, token=token)
    else:
        request_json(base, method="POST", payload={"body": body}, token=token)


def upload_sarif(repository: str, token: str, sarif: dict[str, Any]) -> None:
    encoded = base64.b64encode(gzip.compress(json.dumps(sarif).encode("utf-8"))).decode("ascii")
    payload = {
        "commit_sha": os.environ.get("GITHUB_SHA", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "sarif": encoded,
        "tool_name": "Cloud Health Check",
    }
    request_json(f"https://api.github.com/repos/{repository}/code-scanning/sarifs", method="POST", payload=payload, token=token)


def set_output(name: str, value: Any) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def publish(args: argparse.Namespace) -> int:
    report_path = Path(args.report)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report_directory = Path(args.report_directory)
    sarif_path = report_directory / "report.sarif"
    sarif = sarif_document(report)
    sarif_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
    summary_markdown = markdown_summary(report)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with Path(step_summary).open("a", encoding="utf-8") as handle:
            handle.write(summary_markdown + "\n")
    if truthy(args.annotations):
        publish_annotations(report)

    token = os.environ.get("CHC_GITHUB_TOKEN", "").strip()
    repository, pr_number, _ = github_context()
    try:
        if truthy(args.comment_on_pr) and pr_number and token:
            upsert_pr_comment(repository, pr_number, token, summary_markdown)
        if truthy(args.upload_sarif) and token:
            upload_sarif(repository, token, sarif)
    except urllib.error.HTTPError as error:
        print(f"::warning title=Cloud Health Check publishing::GitHub API returned HTTP {error.code}. Check workflow permissions.")
    except urllib.error.URLError as error:
        print(f"::warning title=Cloud Health Check publishing::GitHub API unavailable: {annotation_escape(error.reason)}")

    finding_summary = report.get("summary", {})
    set_output("report-html", str(report_directory / "report.html"))
    set_output("report-json", str(report_path))
    set_output("sarif", str(sarif_path))
    set_output("critical", finding_summary.get("critical", 0))
    set_output("high", finding_summary.get("high", 0))

    threshold = args.fail_on.lower()
    if threshold != "never":
        threshold_rank = FAIL_RANK[threshold]
        if any(FAIL_RANK.get(severity, 0) >= threshold_rank and int(count) > 0 for severity, count in finding_summary.items()):
            print(f"error: findings at or above the '{threshold}' threshold", file=sys.stderr)
            return 1
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    validate_cmd = commands.add_parser("validate")
    validate_cmd.add_argument("--repository", required=True)
    validate_cmd.add_argument("--run-id", required=True)
    verify_cmd = commands.add_parser("verify")
    verify_cmd.add_argument("executable")
    verify_cmd.add_argument("checksum")
    publish_cmd = commands.add_parser("publish")
    publish_cmd.add_argument("--report", required=True)
    publish_cmd.add_argument("--report-directory", required=True)
    publish_cmd.add_argument("--fail-on", choices=list(FAIL_RANK) + ["never"], required=True)
    publish_cmd.add_argument("--comment-on-pr", required=True)
    publish_cmd.add_argument("--annotations", required=True)
    publish_cmd.add_argument("--upload-sarif", required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    return {"validate": validate, "verify": verify, "publish": publish}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
