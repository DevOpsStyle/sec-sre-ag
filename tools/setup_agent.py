#!/usr/bin/env python3
"""
setup_agent.py - Configure an Azure SRE Agent for the sec-sre-ag skills with one command.

Everything that the GitHub plugin cannot install is configured through the Azure SRE
Agent REST APIs (https://learn.microsoft.com/azure/sre-agent/api-reference). Every
step is idempotent: run the script again at any time.

  1. plugin       Installs the sec-sre-ag plugin from GitHub: all skills together with
                  the Python scripts and data files they run.
                  POST {agentEndpoint}/api/v2/plugins/install-direct
  2. connectors   Creates the connectors the skills use, then tests the MCP ones:
                    sentinel-workspace  Log Analytics connector for the Sentinel workspace
                    ms-learn-mcp        Microsoft Learn MCP server (no authentication)
                    kql-search-mcp      KQL search MCP server (needs KQL_SEARCH_GITHUB_TOKEN)
                  PUT .../Microsoft.App/agents/{agent}/connectors/{name}  (ARM)
  3. knowledge    Uploads docs/known-issues.md to the agent knowledge base.
                  POST {agentEndpoint}/api/v1/agentmemory/upload
  4. code-access  Optional (--code-repo): connects GitHub repositories through Code Access,
                  for example the private repository of the DOCX technical report module.
                  PUT {agentEndpoint}/api/v2/repos/{name}

At the end it reports whether the plugin page still shows "Connector setup required"
(an MCP server of .mcp.json without a connector), then prints the steps that still need
a person (OAuth connectors and the permission scripts in setup/), with the agent
identity IDs already filled in.

Usage, from the repository root after `az login`:
    python tools/setup_agent.py --sub <SUB> --rg <RG> --agent <AGENT> --dry-run
    python tools/setup_agent.py --sub <SUB> --rg <RG> --agent <AGENT>

Secrets are read only from environment variables, never from the command line:
    KQL_SEARCH_GITHUB_TOKEN     GitHub token for kql-search-mcp, checked with GitHub before use. Create it
                                at GITHUB_TOKEN_URL below (read-only, public repositories only)
    KQL_SEARCH_FAVORITE_REPOS   optional, comma-separated owner/repo list for kql-search-mcp
    PLUGIN_GITHUB_PAT           only when the plugin repository is private
    CODE_ACCESS_GITHUB_PAT      only for --code-repo when the agent has no GitHub sign-in yet
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from deploy_skills import (
    API_VERSION,
    ARM_BASE,
    ARM_RESOURCE,
    DATAPLANE_RESOURCE,
    Target,
    get_token,
    http,
    load_local_skills,
    resolve_target,
)

# Repository root, or the bundle root when this module runs inside SRE-Agent-Setup.exe (PyInstaller).
REPO_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
CONFIG_FILE = Path(__file__).resolve().parent / "deploy.config.json"
STEPS = ("plugin", "connectors", "knowledge", "code-access")
KNOWLEDGE_FILES = ("docs/known-issues.md",)

LA_CONNECTOR = "sentinel-workspace"
LEARN_CONNECTOR = "ms-learn-mcp"
LEARN_ENDPOINT = "https://learn.microsoft.com/api/mcp"
LEARN_TOOLS = ("microsoft_docs_search", "microsoft_code_sample_search", "microsoft_docs_fetch")
KQL_CONNECTOR = "kql-search-mcp"
KQL_PACKAGE = "kql-search-mcp@1.0.5"  # version verified with these skills (see README)
KQL_TOOLS = (
    "get_table_schema", "search_github_examples_fallback", "search_kql_repositories",
    "validate_kql_query", "find_column", "generate_kql_query", "search_tables",
    "get_query_documentation", "list_table_categories", "get_tables_by_category",
)
SECRET_ENV_VARS = ("KQL_SEARCH_GITHUB_TOKEN", "PLUGIN_GITHUB_PAT", "CODE_ACCESS_GITHUB_PAT")
GITHUB_API = "https://api.github.com"
GITHUB_TOKEN_PAGE = "https://github.com/settings/personal-access-tokens/new"
# The token page with the form already filled in. Without permission parameters the token can only
# read public repositories, which is all kql-search-mcp needs (code and repository search).
GITHUB_TOKEN_URL = (f"{GITHUB_TOKEN_PAGE}?name=Azure+SRE+Agent+KQL+search&description=Read-only+token+for+the+"
                    "kql-search-mcp+connector+of+Azure+SRE+Agent&expires_in=365")
GITHUB_TOKEN_RE = re.compile(r"^[A-Za-z0-9_]{20,255}$")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def redact(text: Any) -> str:
    out = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False)
    for var in SECRET_ENV_VARS:
        value = (os.environ.get(var) or "").strip()
        if value:
            out = out.replace(value, "***")
    return out[:400]


def check_github_token(token: str) -> dict:
    """Ask GitHub whose token this is, with the same kind of call kql-search-mcp makes.

    Returns {"valid": True, "login", "expires"}, {"valid": False, "error"} when GitHub rejects
    the token, or {"valid": None, "error"} when GitHub cannot be reached.
    """
    token = token.strip()
    if not GITHUB_TOKEN_RE.match(token):
        return {"valid": False, "error": "this is not a GitHub token (it starts with github_pat_ and has only "
                                         "letters, digits and _): copy it again"}
    request = urllib.request.Request(f"{GITHUB_API}/user", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "User-Agent": "sec-sre-ag-setup"})
    try:
        with urllib.request.urlopen(request, timeout=20) as resp:
            body = json.loads(resp.read().decode("utf-8") or "{}")
            expires = re.match(r"\d{4}-\d{2}-\d{2}", resp.headers.get("GitHub-Authentication-Token-Expiration") or "")
        return {"valid": True, "login": body.get("login") or "?", "expires": expires.group(0) if expires else None}
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return {"valid": False, "error": "GitHub does not accept this token: it is incomplete, expired or deleted"}
        return {"valid": None, "error": f"GitHub answered HTTP {exc.code}"}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"valid": None, "error": f"cannot reach GitHub ({getattr(exc, 'reason', exc)})"}


def load_config() -> dict:
    if CONFIG_FILE.is_file():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except ValueError:
            return {}
        # Ignore values that still contain the <placeholders> of deploy.config.example.json.
        return {k: v for k, v in data.items() if not (isinstance(v, str) and "<" in v)}
    return {}


def detect_repo() -> str | None:
    try:
        url = subprocess.run(["git", "-C", str(REPO_ROOT), "remote", "get-url", "origin"],
                             capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    match = re.search(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$", url)
    return f"{match.group(1)}/{match.group(2)}" if match else None


def upload_file(url: str, token: str, filename: str, data: bytes, mime: str) -> tuple[int, Any]:
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{filename}\"\r\n"
            f"Content-Type: {mime}\r\n\r\n").encode("utf-8") + data + f"\r\n--{boundary}--\r\n".encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, raw
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        return 0, str(exc)


class Agent:
    """The target agent: ARM resource, data-plane endpoint and identity."""

    def __init__(self, target: Target):
        self.target = target
        self.arm_token = get_token(ARM_RESOURCE, target.sub)
        status, body = http("GET", target.agent_arm_url(), self.arm_token)
        if status != 200 or not isinstance(body, dict):
            sys.exit(f"ERROR: cannot read agent '{target.agent}' (HTTP {status}): {redact(body)}")
        props = body.get("properties") or {}
        self.endpoint = (props.get("agentEndpoint") or "").rstrip("/")
        if not self.endpoint:
            sys.exit("ERROR: the agent has no data-plane endpoint (properties.agentEndpoint).")
        self.state = props.get("powerState") or props.get("runningState") or "unknown"
        identities = (body.get("identity") or {}).get("userAssignedIdentities") or {}
        self.uami_id, uami = next(iter(identities.items()), (None, {}))
        self.uami_principal = (uami or {}).get("principalId")
        self.uami_client = (uami or {}).get("clientId")
        self._dp_token: str | None = None

    @property
    def dp_token(self) -> str:
        if self._dp_token is None:
            self._dp_token = get_token(DATAPLANE_RESOURCE, self.target.sub)
        return self._dp_token

    def arm(self, method: str, suffix: str, body: dict | None = None) -> tuple[int, Any]:
        return http(method, f"{self.target.agent_url()}{suffix}?api-version={API_VERSION}", self.arm_token, body)

    def dp(self, method: str, path: str, body: dict | None = None) -> tuple[int, Any]:
        return http(method, f"{self.endpoint}{path}", self.dp_token, body)


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, item: str, status: str, detail: str = "") -> None:
        self.rows.append((item, status, detail))
        print(f"  [{status}] {item}" + (f": {detail}" if detail else ""))

    @property
    def failed(self) -> bool:
        return any(status == "FAILED" for _, status, _ in self.rows)


# --------------------------------------------------------------------------- #
# Step 1: plugin
# --------------------------------------------------------------------------- #
def find_installation(agent: Agent, repo: str, path: str) -> dict | None:
    status, body = agent.dp("GET", "/api/v2/plugins/installations")
    if status != 200 or not isinstance(body, dict):
        return None
    for inst in body.get("value") or []:
        source = ((inst.get("spec") or {}).get("source") or {})
        if (source.get("repo") or "").lower() == repo.lower() and (source.get("url") or "").strip("/") == path.strip("/"):
            return inst
    return None


def step_plugin(agent: Agent, args, cfg: dict, report: Report) -> None:
    repo = args.repo  # resolved by run(): --repo, deploy.config.json pluginRepo, or git remote origin
    path = args.path if args.path is not None else cfg.get("pluginPath", "")
    if not repo:
        report.add("plugin", "FAILED", "cannot detect the GitHub repository: set it (wizard Advanced options, "
                                       "or --repo <owner>/<repo>)")
        return
    if repo.lower() == "stefanpems/sec-sre-ag":
        print("  ! installing from the source repository: the README recommends a customer-owned copy")

    installed = find_installation(agent, repo, path)
    if installed:
        spec = installed.get("spec") or {}
        commit = (spec.get("sourceCommit") or "")[:7]
        skills = len(spec.get("importedSkills") or [])
        auto = spec.get("autoUpdate")
        report.add("plugin", "OK", f"already installed from {repo} (commit {commit}, {skills} skills, "
                                   f"auto-update {'on' if auto else 'off'}); update it from Builder > Plugins")
        return

    local = {s.name for s in load_local_skills()}
    status, body = agent.dp("GET", "/api/v2/extendedAgent/skills")
    existing = body.get("value") if status == 200 and isinstance(body, dict) else []
    conflicts = sorted(s.get("name") for s in existing or [] if s.get("name") in local)
    if conflicts:
        builder = [n for n in conflicts
                   if not ((next(s for s in existing if s.get("name") == n).get("properties") or {})
                           .get("sourcePluginInstallation"))]
        hint = (f"delete them in Builder > Skill builder, or run: python tools/deploy_skills.py delete --sub "
                f"{agent.target.sub} --rg {agent.target.rg} --agent {agent.target.agent} --skills {','.join(builder)}"
                if builder else "uninstall the other plugin that provides them (Builder > Plugins)")
        report.add("plugin", "FAILED", f"skills with the same names already exist ({', '.join(conflicts)}); {hint}")
        return

    request: dict[str, Any] = {"sourceUrl": repo, "pathInRepo": path}
    if os.environ.get("PLUGIN_GITHUB_PAT"):
        request["credentials"] = {"authMethod": "pat", "pat": os.environ["PLUGIN_GITHUB_PAT"]}
    if args.dry_run:
        report.add("plugin", "DRY-RUN", f"would POST /api/v2/plugins/install-direct {redact(request)}")
        return

    status, body = agent.dp("POST", "/api/v2/plugins/install-direct", request)
    if status not in (200, 201, 202):
        report.add("plugin", "FAILED", f"install-direct returned HTTP {status}: {redact(body)}")
        return
    for _ in range(24):
        installed = find_installation(agent, repo, path)
        if installed:
            spec = installed.get("spec") or {}
            report.add("plugin", "OK", f"installed from {repo} (commit {(spec.get('sourceCommit') or '')[:7]}, "
                                       f"{len(spec.get('importedSkills') or [])} skills)")
            return
        time.sleep(5)
    report.add("plugin", "OK", f"install requested (HTTP {status}); check Builder > Plugins in a few minutes")


# --------------------------------------------------------------------------- #
# Step 2: connectors
# --------------------------------------------------------------------------- #
def sentinel_workspaces(agent: Agent) -> list[str]:
    url = (f"{ARM_BASE}/subscriptions/{agent.target.sub}/providers/Microsoft.OperationsManagement/solutions"
           "?api-version=2015-11-01-preview")
    status, body = http("GET", url, agent.arm_token)
    if status != 200 or not isinstance(body, dict):
        return []
    return sorted({(s.get("properties") or {}).get("workspaceResourceId")
                   for s in body.get("value") or []
                   if (s.get("name") or "").startswith("SecurityInsights(")
                   and (s.get("properties") or {}).get("workspaceResourceId")})


def put_connector(agent: Agent, name: str, properties: dict, args, report: Report, label: str) -> bool:
    if args.dry_run:
        report.add(label, "DRY-RUN", f"would PUT connectors/{name} ({properties['dataConnectorType']})")
        return False
    status, body = agent.arm("PUT", f"/connectors/{name}", {"properties": {"name": name, **properties}})
    if status in (200, 201, 202):
        report.add(label, "OK", f"connector '{name}' created or updated")
        return True
    report.add(label, "FAILED", f"PUT connectors/{name} returned HTTP {status}: {redact(body)}")
    return False


def test_connector(agent: Agent, name: str, wanted: tuple[str, ...], report: Report) -> None:
    status, connector = agent.dp("GET", f"/api/v2/extendedAgent/connectors/{name}")
    if status != 200:
        report.add(f"test {name}", "WARN", f"cannot read the connector from the data plane (HTTP {status})")
        return
    status, result = agent.dp("POST", f"/api/v2/extendedAgent/connectors/{name}/testconnection", connector)
    if status != 200 or not isinstance(result, dict):
        report.add(f"test {name}", "WARN", f"testconnection returned HTTP {status}")
        return
    if not result.get("success"):
        error = (result.get("errorMessage") or "").strip().splitlines()
        report.add(f"test {name}", "WARN", f"connection failed: {redact(error[-1] if error else 'no details')}")
        return
    names = [str(t.get("name") or t.get("Name") or "") for t in result.get("tools") or [] if isinstance(t, dict)]
    missing = [t for t in wanted if not any(n == t or n.endswith(f"_{t}") for n in names)]
    if missing:
        report.add(f"test {name}", "WARN", f"connected, but these tools were not listed: {', '.join(missing)}; "
                                           "check the tool selection in Builder > Connectors")
    else:
        report.add(f"test {name}", "OK", f"connected, {result.get('totalCount', len(names))} tool(s) available")


def step_connectors(agent: Agent, args, cfg: dict, report: Report) -> None:
    status, body = agent.arm("GET", "/connectors")
    existing = {c.get("name"): (c.get("properties") or {})
                for c in (body.get("value") if status == 200 and isinstance(body, dict) else []) or []}
    identity = agent.uami_id or "system"

    workspace = args.workspace or cfg.get("sentinelWorkspaceResourceId")
    other_la = [n for n, p in existing.items()
                if (p.get("dataConnectorType") or "").lower() == "loganalytics" and n != LA_CONNECTOR]
    if other_la and not workspace:
        report.add("Log Analytics", "OK", f"kept existing connector(s) {', '.join(other_la)}; "
                                          "verify they target the Microsoft Sentinel workspace")
    else:
        if not workspace:
            found = sentinel_workspaces(agent)
            if len(found) == 1:
                workspace = found[0]
                print(f"  discovered Sentinel workspace: {workspace}")
            elif found:
                report.add("Log Analytics", "MANUAL", "several Sentinel workspaces found: choose one (wizard list, "
                                                      "or --workspace): " + "; ".join(found))
            else:
                report.add("Log Analytics", "MANUAL", f"no Sentinel workspace found in subscription {agent.target.sub}: "
                                                      "give its resource ID (--workspace) or add the connector in "
                                                      "Builder > Connectors")
        if workspace:
            put_connector(agent, LA_CONNECTOR, {
                "dataConnectorType": "LogAnalytics",
                "dataSource": workspace,
                "extendedProperties": {"armResourceId": workspace,
                                       "resource": {"name": workspace.rstrip("/").split("/")[-1]}},
                "identity": identity,
            }, args, report, "Log Analytics")
            cfg["_workspace"] = workspace

    learn_tools = [f"{LEARN_CONNECTOR}_{t}" for t in LEARN_TOOLS]
    if put_connector(agent, LEARN_CONNECTOR, {
        "dataConnectorType": "Mcp",
        "dataSource": LEARN_ENDPOINT,
        "extendedProperties": {"type": "http", "endpoint": LEARN_ENDPOINT,
                               "selectedTools": learn_tools, "toolsVisibleToMetaAgent": learn_tools},
        "identity": "",
    }, args, report, LEARN_CONNECTOR):
        test_connector(agent, LEARN_CONNECTOR, LEARN_TOOLS, report)

    token = (os.environ.get("KQL_SEARCH_GITHUB_TOKEN") or "").strip()
    if not token:
        if KQL_CONNECTOR in existing:
            report.add(KQL_CONNECTOR, "OK", "kept the existing connector (give a GitHub token to update it)")
        else:
            report.add(KQL_CONNECTOR, "MANUAL", "not created: no GitHub token. The skills work without it, but the "
                                                "plugin page shows 'Connector setup required' until it exists. Create "
                                                f"a free read-only token at {GITHUB_TOKEN_URL} (sign in to GitHub, "
                                                "select Generate token, copy the token) and run the connectors step "
                                                "again with it (wizard step 3, or KQL_SEARCH_GITHUB_TOKEN)")
        return
    github = check_github_token(token)
    if github["valid"] is False:
        report.add(KQL_CONNECTOR, "FAILED", f"{github['error']}. Create a new token at {GITHUB_TOKEN_URL} and run "
                                            "the connectors step again with it")
        return
    if github["valid"]:
        report.add("GitHub token", "OK", f"account {github['login']}, " + (
            f"expires on {github['expires']}: before that date create a new token and run the connectors step "
            "again with it" if github["expires"] else "no expiration date"))
    else:
        report.add("GitHub token", "WARN", f"not checked, {github['error']}")
    envs = {"GITHUB_TOKEN": token}
    if os.environ.get("KQL_SEARCH_FAVORITE_REPOS"):
        envs["FAVORITE_REPOS"] = os.environ["KQL_SEARCH_FAVORITE_REPOS"]
    kql_tools = [f"{KQL_CONNECTOR}_{t}" for t in KQL_TOOLS]
    if put_connector(agent, KQL_CONNECTOR, {
        "dataConnectorType": "Mcp",
        "dataSource": "npx",
        "extendedProperties": {"type": "stdio", "command": "npx", "args": ["-y", KQL_PACKAGE], "envs": envs,
                               "selectedTools": kql_tools, "toolsVisibleToMetaAgent": kql_tools},
        "identity": identity,
    }, args, report, KQL_CONNECTOR):
        test_connector(agent, KQL_CONNECTOR, KQL_TOOLS, report)


# --------------------------------------------------------------------------- #
# Step 3: knowledge
# --------------------------------------------------------------------------- #
def step_knowledge(agent: Agent, args, report: Report) -> None:
    for rel in KNOWLEDGE_FILES:
        path = REPO_ROOT / rel
        if args.dry_run:
            report.add(f"knowledge {rel}", "DRY-RUN", "would upload it to the agent knowledge base")
            continue
        status, body = upload_file(f"{agent.endpoint}/api/v1/agentmemory/upload?triggerIndexing=true",
                                   agent.dp_token, path.name, path.read_bytes(), "text/markdown")
        if status in (200, 201, 202):
            report.add(f"knowledge {rel}", "OK", "uploaded to the agent knowledge base (indexing started)")
        else:
            report.add(f"knowledge {rel}", "FAILED", f"upload returned HTTP {status}: {redact(body)}")


# --------------------------------------------------------------------------- #
# Step 4: code access (optional)
# --------------------------------------------------------------------------- #
def step_code_access(agent: Agent, args, cfg: dict, report: Report) -> None:
    repos = args.code_repo or cfg.get("codeAccessRepos") or []
    if not repos:
        report.add("code access", "SKIPPED", "no repository given (only needed for the optional DOCX module)")
        return
    status, body = agent.dp("GET", "/api/v2/github/domains")
    domains = body.get("values") if status == 200 and isinstance(body, dict) else []
    if not any((d.get("name") or "").split("|")[0] == "github.com" for d in domains or []):
        pat = os.environ.get("CODE_ACCESS_GITHUB_PAT")
        if not pat:
            status, oauth = agent.dp("GET", "/api/v2/github/oauth/config")
            url = (oauth or {}).get("oAuthUrl") or (oauth or {}).get("OAuthUrl") if isinstance(oauth, dict) else None
            report.add("code access", "MANUAL", "the agent is not signed in to GitHub: "
                       + (f"open {url} and approve, " if url else "use Builder > Code Access, ")
                       + "or give a GitHub token (wizard field, or CODE_ACCESS_GITHUB_PAT); then run the Code "
                         "Access step again")
            return
        if args.dry_run:
            report.add("code access", "DRY-RUN", "would store the GitHub token as the github.com credential")
        else:
            status, body = agent.dp("PUT", "/api/v2/github/domains/github_com", {"AuthType": "Pat", "Pat": pat})
            if status not in (200, 201, 202, 204):
                report.add("code access", "FAILED", f"cannot store the GitHub credential (HTTP {status}): {redact(body)}")
                return
    for repo in repos:
        name = repo.rstrip("/").split("/")[-1]
        url = repo if repo.startswith("http") else f"https://github.com/{repo}"
        if args.dry_run:
            report.add(f"code access {repo}", "DRY-RUN", f"would PUT /api/v2/repos/{name}")
            continue
        status, body = agent.dp("PUT", f"/api/v2/repos/{name}",
                                {"name": name, "type": "CodeRepo", "properties": {"url": url, "type": "GitHub"}})
        if status in (200, 201, 202):
            report.add(f"code access {repo}", "OK", f"connected as codeRefs/{name}/ (cloning starts now)")
        else:
            report.add(f"code access {repo}", "FAILED", f"HTTP {status}: {redact(body)}")


# --------------------------------------------------------------------------- #
# Plugin page banner
# --------------------------------------------------------------------------- #
def plugin_connector_status(agent: Agent, args, cfg: dict, report: Report) -> None:
    """Report the MCP servers of the plugin that have no connector, as the plugin page does.

    The plugin page shows "Connector setup required" while the installation lists them in
    mcpConnectorStatus.missing. Servers declared by URL without authentication headers
    (ms-learn-mcp) are not tracked there.
    """
    if not args.repo:
        return
    path = args.path if args.path is not None else cfg.get("pluginPath", "")
    status = (find_installation(agent, args.repo, path) or {}).get("mcpConnectorStatus") or {}
    if not status.get("knownStatus"):
        return
    print("\nPlugin page")
    missing = status.get("missing") or []
    if missing:
        report.add("plugin page", "MANUAL", "shows 'Connector setup required' until these connectors exist: "
                                            f"{', '.join(missing)} (see the items above)")
    else:
        report.add("plugin page", "OK", "every MCP server of the plugin has a connector")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def manual_steps(agent: Agent, cfg: dict, repo: str | None) -> list[str]:
    workspace = cfg.get("_workspace") or cfg.get("sentinelWorkspaceResourceId")
    if not workspace:
        found = sentinel_workspaces(agent)
        workspace = found[0] if len(found) == 1 else "<WORKSPACE_RESOURCE_ID>"
    principal = agent.uami_principal or "<UAMI_OBJECT_ID>"
    client = agent.uami_client or "<UAMI_CLIENT_ID>"
    repo = repo or "<customer-org>/<customer-repo>"
    return [
        "Still to do by a person (cannot be automated through the agent APIs):",
        "  1. Permissions for the agent identity. In Azure Cloud Shell (Bash, https://shell.azure.com):",
        f"       git clone https://github.com/{repo}.git && cd {repo.split('/')[-1]}/setup && chmod +x *.sh",
        f"       ./assign-permissions.sh {principal} {agent.target.sub}      # Privileged Role Administrator",
        f"       ./assign-azure-roles.sh {client} {workspace} [<KEYVAULT_RESOURCE_ID>]",
        "  2. Outlook and Microsoft Teams connectors: they need an interactive OAuth sign-in.",
        "     Builder > Connectors, sign in with the dedicated service account (README > Setup D).",
        "  3. Open a NEW chat and run the smoke tests in README > Validation Tests.",
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sub", help="Azure subscription ID of the agent")
    parser.add_argument("--rg", help="Resource group of the agent")
    parser.add_argument("--agent", help="Azure SRE Agent resource name")
    parser.add_argument("--tenant", help="Entra tenant ID (informational)")
    parser.add_argument("--repo", help="GitHub repository of the plugin, owner/name (default: git remote origin)")
    parser.add_argument("--path", default=None, help="Plugin folder inside the repository (default: repository root)")
    parser.add_argument("--workspace", help="Resource ID of the Microsoft Sentinel Log Analytics workspace "
                                            "(default: discovered in the agent subscription)")
    parser.add_argument("--code-repo", action="append", metavar="OWNER/NAME",
                        help="GitHub repository to connect through Code Access (repeatable, optional)")
    parser.add_argument("--only", help=f"Comma-separated steps to run: {', '.join(STEPS)}")
    parser.add_argument("--skip", help="Comma-separated steps to skip")
    parser.add_argument("--dry-run", action="store_true", help="Read the agent state and print the planned changes only")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)
    steps = [s.strip() for s in (args.only.split(",") if args.only else STEPS) if s.strip()]
    steps = [s for s in steps if s not in {x.strip() for x in (args.skip or "").split(",")}]
    unknown = [s for s in steps if s not in STEPS]
    if unknown:
        parser.error(f"unknown step(s): {', '.join(unknown)}")
    args.steps = steps
    return args


def run(args: argparse.Namespace) -> tuple[int, Report, list[str]]:
    """Run the selected steps. Returns the exit code, the report rows and the manual steps."""
    cfg = load_config()
    args.repo = args.repo or cfg.get("pluginRepo") or detect_repo()
    agent = Agent(resolve_target(args))
    print(f"Agent {agent.target.agent} ({agent.state}) - {agent.endpoint}")
    if agent.uami_id:
        print(f"Identity: {agent.uami_id.split('/')[-1]} (object ID {agent.uami_principal}, client ID {agent.uami_client})")
    if str(agent.state).lower() not in ("running", "unknown"):
        print("  ! the agent is not running: start it before configuring it")
    if args.dry_run:
        print("DRY RUN: only read operations are performed.")

    steps = args.steps
    report = Report()
    if "plugin" in steps:
        print("\n[1/4] Plugin")
        step_plugin(agent, args, cfg, report)
    if "connectors" in steps:
        print("\n[2/4] Connectors")
        step_connectors(agent, args, cfg, report)
    if "knowledge" in steps:
        print("\n[3/4] Knowledge base")
        step_knowledge(agent, args, report)
    if "code-access" in steps:
        print("\n[4/4] Code Access")
        step_code_access(agent, args, cfg, report)
    if "plugin" in steps or "connectors" in steps:
        plugin_connector_status(agent, args, cfg, report)

    lines = manual_steps(agent, cfg, args.repo)
    print("\n" + "\n".join(lines))
    print("\nSummary:")
    for item, status, _ in report.rows:
        print(f"  {status:8s} {item}")
    return (1 if report.failed else 0), report, lines


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(argv))[0]


if __name__ == "__main__":
    raise SystemExit(main())
