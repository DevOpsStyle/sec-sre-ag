#!/usr/bin/env python3
"""Keep the Azure SRE Agent plugin in this repository consistent.

The repository root is an Azure SRE Agent plugin: `plugin.json` imports every
folder under `skills/`. Each skill folder must be self-contained, because Azure
SRE Agent copies only the skill folder into the agent sandbox
(`runtime-content/skills/plugins/<installation>/live/<skill>/`). Files used by
several skills are therefore maintained once (see SHARED_FILES) and copied into
the skills that need them.

Commands
--------
    python tools/plugin.py sync     Copy the canonical shared files into the skills that bundle them.
    python tools/plugin.py check    Validate the plugin. Exit code 1 when an error is found (used by CI).

`check` needs PyYAML (`pip install pyyaml`). It parses every SKILL.md front
matter as strictly as the plugin importer does: a front matter that is not valid
YAML is imported with an empty description, and the agent then never selects
the skill.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "plugin.json"

_REPORT_SKILLS = (
    "computer-investigation",
    "identity-posture",
    "incident-investigation",
    "incident-statistics",
    "mcp-usage-monitoring",
    "mitre-coverage-report",
    "sentinel-ingestion-report",
    "user-investigation",
)

# Canonical file (repository-relative) -> skills that bundle an identical copy of it
# under the same file name. Edit only the canonical file, then run `sync`.
SHARED_FILES: dict[str, tuple[str, ...]] = {
    "shared/enrich_ips.py": (
        "computer-investigation",
        "ioc-investigation",
        "user-investigation",
    ),
    "shared/shared-guardrails.md": (
        "computer-investigation",
        "identity-posture",
        "incident-investigation",
        "incident-listing",
        "incident-statistics",
        "ioc-investigation",
        "kql-query-authoring",
        "mcp-usage-monitoring",
        "threat-pulse",
        "user-investigation",
    ),
    "docs/email-html-report.md": _REPORT_SKILLS,
    "docs/teams-delivery.md": _REPORT_SKILLS,
}

SKILL_FILE = "SKILL.md"
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_NAME = 64
MAX_DESCRIPTION = 1024
IGNORED_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache"}
LINK_RE = re.compile(r"(?<!!)\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
SECRET_RE = re.compile(r"(ghp_|gho_|github_pat_|xox[bp]-|sk-[A-Za-z0-9]{20})")


def _normalized(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def skill_roots(manifest: dict) -> list[Path]:
    return [REPO_ROOT / str(p).rstrip("/") for p in manifest.get("skills", [])]


def skill_dirs(manifest: dict) -> list[Path]:
    dirs: list[Path] = []
    for root in skill_roots(manifest):
        if root.is_dir():
            dirs.extend(sorted(d for d in root.iterdir() if d.is_dir() and (d / SKILL_FILE).is_file()))
    return dirs


def skill_files(skill_dir: Path) -> list[Path]:
    return sorted(
        p for p in skill_dir.rglob("*")
        if p.is_file() and not IGNORED_PARTS.intersection(p.parts) and p.suffix != ".pyc"
    )


# --------------------------------------------------------------------------- #
# sync
# --------------------------------------------------------------------------- #
def cmd_sync(_args) -> int:
    changed = 0
    for source_rel, skills in SHARED_FILES.items():
        source = REPO_ROOT / source_rel
        name = source.name
        if not source.is_file():
            print(f"ERROR {source_rel} not found", file=sys.stderr)
            return 1
        for skill in skills:
            target = REPO_ROOT / "skills" / skill / name
            if not target.parent.is_dir():
                print(f"ERROR skill folder skills/{skill} not found", file=sys.stderr)
                return 1
            if target.is_file() and _normalized(target) == _normalized(source):
                continue
            shutil.copyfile(source, target)
            changed += 1
            print(f"updated skills/{skill}/{name}")
    print(f"sync complete: {changed} file(s) updated")
    return 0


# --------------------------------------------------------------------------- #
# check
# --------------------------------------------------------------------------- #
class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


def _front_matter(text: str) -> str | None:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return "\n".join(lines[1:i])
    return None


def check_manifest(manifest: dict, report: Report) -> None:
    name = manifest.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        report.error("plugin.json: 'name' must be lowercase letters, digits and hyphens")
    if not isinstance(manifest.get("description"), str) or not manifest["description"].strip():
        report.error("plugin.json: 'description' is required")
    paths = manifest.get("skills")
    if not isinstance(paths, list) or not paths:
        report.error("plugin.json: 'skills' must be a non-empty list of folders")
    else:
        for root in skill_roots(manifest):
            if not root.is_dir():
                report.error(f"plugin.json: skills folder not found: {root.relative_to(REPO_ROOT)}")
    mcp = manifest.get("mcpServers")
    if mcp is None:
        return
    mcp_path = REPO_ROOT / str(mcp)
    try:
        servers = json.loads(mcp_path.read_text(encoding="utf-8")).get("mcpServers")
    except (OSError, ValueError) as exc:
        report.error(f"{mcp}: cannot be read as JSON ({exc})")
        return
    if not isinstance(servers, dict) or not servers:
        report.error(f"{mcp}: 'mcpServers' must be a non-empty object")
        return
    for server, spec in servers.items():
        if not isinstance(spec, dict) or not (spec.get("command") or spec.get("url")):
            report.error(f"{mcp}: server '{server}' needs a 'command' (stdio) or a 'url' (http)")
            continue
        if SECRET_RE.search(json.dumps(spec)):
            report.error(f"{mcp}: server '{server}' contains what looks like a real secret; use ${{VAR}} placeholders")


def check_links(skill_dir: Path, md_file: Path, report: Report) -> None:
    in_fence = False
    for lineno, line in enumerate(md_file.read_text(encoding="utf-8").splitlines(), start=1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in LINK_RE.finditer(line):
            target = match.group(1)
            if target.startswith(("http://", "https://", "mailto:", "#")) or any(c in target for c in "<>{}$*"):
                continue
            path_part = target.split("#", 1)[0]
            if not path_part:
                continue
            resolved = (md_file.parent / path_part).resolve()
            where = f"{md_file.relative_to(REPO_ROOT).as_posix()}:{lineno}"
            if skill_dir.resolve() not in resolved.parents and resolved != skill_dir.resolve():
                report.error(f"{where}: link '{target}' points outside the skill folder; "
                             "the agent only receives the skill folder")
            elif not resolved.exists():
                report.error(f"{where}: link '{target}' points to a missing file")


def check_skill(skill_dir: Path, report: Report, yaml) -> dict:
    rel = skill_dir.relative_to(REPO_ROOT).as_posix()
    text = (skill_dir / SKILL_FILE).read_text(encoding="utf-8")
    info = {"name": skill_dir.name, "files": 0, "scripts": 0, "bytes": 0}
    fm = _front_matter(text)
    if fm is None:
        report.error(f"{rel}/SKILL.md: missing YAML front matter delimited by '---'")
    else:
        try:
            data = yaml.safe_load(fm)
        except yaml.YAMLError as exc:
            report.error(f"{rel}/SKILL.md: front matter is not valid YAML "
                         f"(the plugin would import an empty description): {str(exc).splitlines()[0]}")
            data = None
        if data is not None and not isinstance(data, dict):
            report.error(f"{rel}/SKILL.md: front matter must be a YAML mapping")
        elif isinstance(data, dict):
            name = data.get("name")
            if name != skill_dir.name:
                report.error(f"{rel}/SKILL.md: 'name' ({name!r}) must match the folder name")
            elif not NAME_RE.match(name) or len(name) > MAX_NAME:
                report.error(f"{rel}/SKILL.md: 'name' must be lowercase letters, digits and hyphens, max {MAX_NAME}")
            desc = data.get("description")
            if not isinstance(desc, str) or not desc.strip():
                report.error(f"{rel}/SKILL.md: 'description' is required (the agent selects skills by it)")
            elif len(desc) > MAX_DESCRIPTION:
                report.error(f"{rel}/SKILL.md: 'description' has {len(desc)} characters (max {MAX_DESCRIPTION})")
            tools = data.get("tools")
            if tools is not None and not (isinstance(tools, list) and all(isinstance(t, str) for t in tools)):
                report.error(f"{rel}/SKILL.md: 'tools' must be a list of tool names")

    for path in skill_files(skill_dir):
        info["files"] += 1
        info["bytes"] += path.stat().st_size
        where = path.relative_to(REPO_ROOT).as_posix()
        if path.suffix == ".md":
            check_links(skill_dir, path, report)
        elif path.suffix == ".py":
            info["scripts"] += 1
            try:
                compile(path.read_text(encoding="utf-8"), where, "exec")
            except SyntaxError as exc:
                report.error(f"{where}: Python syntax error: {exc}")
        elif path.suffix == ".json":
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except ValueError as exc:
                report.error(f"{where}: invalid JSON: {exc}")
        elif path.suffix in (".yaml", ".yml"):
            try:
                list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
            except yaml.YAMLError as exc:
                report.error(f"{where}: invalid YAML: {str(exc).splitlines()[0]}")
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            report.warn(f"{where}: not UTF-8 text; Skill Builder deployments skip it")
    return info


def check_shared(report: Report) -> None:
    for source_rel, skills in SHARED_FILES.items():
        source = REPO_ROOT / source_rel
        name = source.name
        if not source.is_file():
            report.error(f"{source_rel}: canonical file not found")
            continue
        for skill in skills:
            target = REPO_ROOT / "skills" / skill / name
            if not target.is_file():
                report.error(f"skills/{skill}/{name}: missing copy of {source_rel} "
                             "(run: python tools/plugin.py sync)")
            elif _normalized(target) != _normalized(source):
                report.error(f"skills/{skill}/{name}: differs from {source_rel}; edit {source_rel} "
                             "and run: python tools/plugin.py sync")


def cmd_check(_args) -> int:
    try:
        import yaml  # type: ignore
    except ImportError:
        print("ERROR: PyYAML is required for 'check'. Install it with: python -m pip install pyyaml",
              file=sys.stderr)
        return 2

    report = Report()
    try:
        manifest = load_manifest()
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read plugin.json: {exc}", file=sys.stderr)
        return 1
    check_manifest(manifest, report)

    seen: dict[str, Path] = {}
    rows = []
    for skill_dir in skill_dirs(manifest):
        if skill_dir.name in seen:
            report.error(f"duplicate skill name '{skill_dir.name}' in {seen[skill_dir.name]} and {skill_dir}")
        seen[skill_dir.name] = skill_dir
        rows.append(check_skill(skill_dir, report, yaml))
    if not rows:
        report.error("no skill found: every skill needs a folder with a SKILL.md under the plugin skills path")
    check_shared(report)

    print(f"Plugin '{manifest.get('name')}': {len(rows)} skill(s)")
    for r in rows:
        print(f"  {r['name']:28s} {r['files']:3d} file(s), {r['scripts']:2d} script(s), {r['bytes'] / 1024:7.1f} KB")
    for w in report.warnings:
        print(f"WARN  {w}")
    for e in report.errors:
        print(f"ERROR {e}")
    if report.errors:
        print(f"\nFAILED: {len(report.errors)} error(s)")
        return 1
    print("\nOK: the plugin is valid")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("sync", help="copy shared/ files into the skills that bundle them").set_defaults(func=cmd_sync)
    sub.add_parser("check", help="validate plugin.json, .mcp.json and every skill").set_defaults(func=cmd_check)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
