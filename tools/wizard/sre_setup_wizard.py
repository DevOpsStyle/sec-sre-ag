#!/usr/bin/env python3
"""
sre_setup_wizard.py - Browser-based setup wizard for the sec-sre-ag Azure SRE Agent plugin.

Packaged as SRE-Agent-Setup.exe (see build.ps1) it needs neither Python nor Azure CLI on
the computer: double-click it and it opens a local web page that signs in to Azure, lets
you pick the agent, and runs the same steps as tools/setup_agent.py (plugin, connectors,
knowledge base and, optionally, Code Access).

Security: the page is served only on 127.0.0.1, every API call must carry the random
session token of the page, and access tokens and secrets stay in memory only.

Developer usage, from the repository root:
    python -m pip install -r tools/wizard/requirements.txt
    python tools/wizard/sre_setup_wizard.py                   # Microsoft sign-in in the browser
    python tools/wizard/sre_setup_wizard.py --use-azure-cli   # reuse an existing `az login`
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

FROZEN = getattr(sys, "frozen", False)
BUNDLE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
if not FROZEN:
    sys.path.insert(0, str(BUNDLE.parent))  # tools/ holds deploy_skills.py and setup_agent.py

import deploy_skills  # noqa: E402
import setup_agent  # noqa: E402

ARM = deploy_skills.ARM_RESOURCE
# Public client ID of Azure CLI, also the default client of azure-identity's InteractiveBrowserCredential.
AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
IDLE_TIMEOUT_SECONDS = 2 * 60 * 60
SIGN_IN_TIMEOUT_SECONDS = 600
MAX_TENANTS = 15
MAX_BODY_BYTES = 64 * 1024
SECRET_FIELDS = {
    "kqlToken": "KQL_SEARCH_GITHUB_TOKEN",
    "pluginToken": "PLUGIN_GITHUB_PAT",
    "codeAccessToken": "CODE_ACCESS_GITHUB_PAT",
}
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
NAME_RE = re.compile(r"^[\w.()-]{1,90}$")
REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
WORKSPACE_RE = re.compile(r"^/subscriptions/[^/]+/resourcegroups/[^/]+/providers/"
                          r"microsoft\.operationalinsights/workspaces/[^/]+$", re.IGNORECASE)


def _build_info() -> dict:
    try:
        return json.loads((BUNDLE / "build-info.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}


BUILD = _build_info()


class AuthError(Exception):
    pass


class UserError(Exception):
    pass


def arm_get(path: str, token: str) -> dict:
    status, body = deploy_skills.http("GET", f"{deploy_skills.ARM_BASE}{path}", token)
    if status != 200 or not isinstance(body, dict):
        raise RuntimeError(f"GET {path.split('?')[0]} returned HTTP {status}: {setup_agent.redact(body)}")
    return body


# --------------------------------------------------------------------------- #
# Sign-in
# --------------------------------------------------------------------------- #
class BrowserAuth:
    """Microsoft Entra sign-in in the system browser (MSAL public client, in-memory token cache)."""

    def __init__(self, tenant: str | None) -> None:
        import msal

        self._msal = msal
        self._cache = msal.TokenCache()
        self._apps: dict[str, Any] = {}
        self._lock = threading.RLock()
        self.login_tenant = tenant or "organizations"
        self.username: str | None = None
        self.home_tenant: str | None = None

    def _app(self, tenant: str):
        if tenant not in self._apps:
            self._apps[tenant] = self._msal.PublicClientApplication(
                AZURE_CLI_CLIENT_ID, authority=f"https://login.microsoftonline.com/{tenant}",
                token_cache=self._cache)
        return self._apps[tenant]

    @staticmethod
    def _token_of(result: dict | None) -> str:
        if result and "access_token" in result:
            return result["access_token"]
        detail = (result or {}).get("error_description") or (result or {}).get("error") or "no token was returned"
        raise AuthError(str(detail).splitlines()[0])

    @staticmethod
    def _interactive(app, scopes: list[str], **kwargs: Any) -> dict:
        try:
            return app.acquire_token_interactive(scopes, timeout=SIGN_IN_TIMEOUT_SECONDS, **kwargs)
        except Exception as exc:  # e.g. BrowserInteractionTimeoutError when the browser tab is abandoned
            if "time" in exc.__class__.__name__.lower() or "in time" in str(exc):
                raise AuthError("The sign-in was not completed in the browser. Select Sign in to try again.") from None
            raise AuthError(f"The sign-in failed: {exc}") from None

    def sign_in(self) -> None:
        with self._lock:
            result = self._interactive(self._app(self.login_tenant), [f"{ARM}/.default"], prompt="select_account")
        self._token_of(result)
        claims = result.get("id_token_claims") or {}
        self.username = claims.get("preferred_username") or claims.get("upn") or claims.get("email")
        self.home_tenant = claims.get("tid") or self.login_tenant

    def token(self, resource: str, tenant: str | None = None, interactive: bool = True) -> str:
        if not self.home_tenant:
            raise AuthError("Sign in first.")
        scopes = [f"{resource.rstrip('/')}/.default"]
        with self._lock:
            app = self._app(tenant or self.home_tenant)
            accounts = app.get_accounts(username=self.username) if self.username else app.get_accounts()
            result = app.acquire_token_silent(scopes, account=accounts[0]) if accounts else None
            if not (result and "access_token" in result) and interactive:
                result = self._interactive(app, scopes, login_hint=self.username)
        return self._token_of(result)

    def subscriptions(self) -> tuple[list[dict], list[str]]:
        tenants = arm_get("/tenants?api-version=2022-12-01", self.token(ARM)).get("value") or []
        subs: list[dict] = []
        skipped: list[str] = []
        for tenant in tenants[:MAX_TENANTS]:
            tenant_id = tenant.get("tenantId")
            try:
                token = self.token(ARM, tenant_id, interactive=False)
                found = arm_get("/subscriptions?api-version=2022-12-01", token).get("value") or []
            except (AuthError, RuntimeError):
                skipped.append(tenant.get("displayName") or tenant_id)
                continue
            subs += [{"id": s["subscriptionId"], "name": s.get("displayName") or s["subscriptionId"],
                      "tenantId": tenant_id} for s in found if s.get("state") == "Enabled"]
        return subs, skipped


class AzureCliAuth:
    """Reuse the Azure CLI sign-in (option --use-azure-cli, for administrators and tests)."""

    def __init__(self) -> None:
        self._az = "az.cmd" if os.name == "nt" else "az"
        self.username = self._run("account", "show", "--query", "user.name", "-o", "tsv").strip() or "Azure CLI"

    def _run(self, *args: str) -> str:
        try:
            return subprocess.run([self._az, *args], capture_output=True, text=True, check=True).stdout
        except FileNotFoundError:
            raise AuthError("Azure CLI is not installed: run the wizard without --use-azure-cli.") from None
        except subprocess.CalledProcessError as exc:
            lines = (exc.stderr or "").strip().splitlines()
            raise AuthError(lines[-1] if lines else "Azure CLI failed: run az login.") from None

    def token(self, resource: str, tenant: str | None = None, interactive: bool = True) -> str:
        args = ["account", "get-access-token", "--resource", resource, "--query", "accessToken", "-o", "tsv"]
        if tenant:
            args += ["--tenant", tenant]
        return self._run(*args).strip()

    def subscriptions(self) -> tuple[list[dict], list[str]]:
        data = json.loads(self._run("account", "list", "-o", "json") or "[]")
        return [{"id": s["id"], "name": s.get("name") or s["id"], "tenantId": s.get("tenantId")}
                for s in data if s.get("state", "Enabled") == "Enabled"], []


# --------------------------------------------------------------------------- #
# Wizard state and API
# --------------------------------------------------------------------------- #
class JobLog:
    """File-like object that collects the output of setup_agent for the page."""

    def __init__(self, job: dict) -> None:
        self.job = job

    def write(self, text: str) -> int:
        self.job["log"] += text
        return len(text)

    def flush(self) -> None:
        pass


class Wizard:
    def __init__(self, auth_mode: str, tenant: str | None) -> None:
        self.session = secrets.token_urlsafe(32)
        self.auth_mode = auth_mode
        self.auth: BrowserAuth | AzureCliAuth | None = None
        self.signing_in = False
        self.sign_in_error: str | None = None
        self.sub_tenants: dict[str, str] = {}
        self.job: dict | None = None
        self.last_seen = time.time()
        self.lock = threading.Lock()
        self.server: ThreadingHTTPServer | None = None
        self.defaults = {
            "repo": BUILD.get("repo") or setup_agent.detect_repo() or "",
            "tenant": tenant or "",
            "mode": auth_mode,
            "version": BUILD.get("commit") or "dev",
            "githubTokenUrl": setup_agent.GITHUB_TOKEN_URL,
        }
        deploy_skills.set_token_provider(self._token)

    def _token(self, resource: str, subscription: str | None = None) -> str:
        if self.auth is None:
            raise AuthError("Sign in first.")
        return self.auth.token(resource, self.sub_tenants.get(subscription or ""))

    def page(self) -> bytes:
        return (BUNDLE / "wizard.html").read_bytes()

    def _signed_in(self):
        if self.auth is None:
            raise UserError("Sign in first.")
        return self.auth

    # GET /api/state
    def state(self, _: dict) -> dict:
        job = self.job or {}
        return {"signedIn": self.auth is not None, "user": getattr(self.auth, "username", None),
                "signingIn": self.signing_in, "error": self.sign_in_error, "defaults": self.defaults,
                "jobRunning": bool(job.get("running"))}

    # POST /api/signin
    def sign_in(self, body: dict) -> dict:
        tenant = str(body.get("tenant") or "").strip() or None
        if tenant and not re.match(r"^[\w.-]{1,100}$", tenant):
            raise UserError("The directory must be a tenant ID or a domain such as contoso.onmicrosoft.com.")
        with self.lock:
            if self.signing_in:
                return {"started": False}
            self.signing_in, self.sign_in_error = True, None
        threading.Thread(target=self._sign_in, args=(tenant,), daemon=True).start()
        return {"started": True}

    def _sign_in(self, tenant: str | None) -> None:
        try:
            if self.auth_mode == "azure-cli":
                auth = AzureCliAuth()
            else:
                auth = BrowserAuth(tenant)
                auth.sign_in()
            self.auth, self.sub_tenants = auth, {}
        except Exception as exc:  # reported in the page
            self.sign_in_error = str(exc) or exc.__class__.__name__
        finally:
            self.signing_in = False

    # GET /api/subscriptions
    def subscriptions(self, _: dict) -> dict:
        subs, skipped = self._signed_in().subscriptions()
        self.sub_tenants = {s["id"]: s["tenantId"] for s in subs if s.get("tenantId")}
        return {"subscriptions": sorted(subs, key=lambda s: s["name"].lower()), "skippedTenants": skipped}

    # GET /api/agents?sub=
    def agents(self, query: dict) -> dict:
        self._signed_in()
        sub = _guid(query.get("sub"), "subscription")
        flt = quote("resourceType eq 'Microsoft.App/agents'")
        body = arm_get(f"/subscriptions/{sub}/resources?$filter={flt}&api-version=2021-04-01",
                       deploy_skills.get_token(ARM, sub))
        agents = []
        for res in body.get("value") or []:
            parts = res.get("id", "").split("/")
            lower = [p.lower() for p in parts]
            rg = parts[lower.index("resourcegroups") + 1] if "resourcegroups" in lower else ""
            agents.append({"name": res.get("name"), "resourceGroup": rg, "location": res.get("location")})
        return {"agents": sorted(agents, key=lambda a: (a["name"] or "").lower())}

    # GET /api/agent?sub=&rg=&name=&repo=
    def agent_details(self, query: dict) -> dict:
        self._signed_in()
        target = deploy_skills.Target(sub=_guid(query.get("sub"), "subscription"),
                                      rg=_name(query.get("rg"), "resource group"),
                                      agent=_name(query.get("name"), "agent"))
        agent = setup_agent.Agent(target)
        status, body = agent.arm("GET", "/connectors")
        connectors = (body.get("value") if status == 200 and isinstance(body, dict) else None) or []
        la = [c.get("name") for c in connectors
              if ((c.get("properties") or {}).get("dataConnectorType") or "").lower() == "loganalytics"]
        repo = str(query.get("repo") or self.defaults["repo"]).strip()
        installed = setup_agent.find_installation(agent, repo, "") if REPO_RE.match(repo) else None
        spec = (installed or {}).get("spec") or {}
        mcp = (installed or {}).get("mcpConnectorStatus") or {}
        names = sorted(c.get("name") for c in connectors if c.get("name"))
        return {
            "state": agent.state,
            "endpoint": agent.endpoint,
            "identity": {"name": (agent.uami_id or "").split("/")[-1], "principalId": agent.uami_principal,
                         "clientId": agent.uami_client},
            "connectors": names,
            "logAnalyticsConnectors": la,
            "workspaces": setup_agent.sentinel_workspaces(agent),
            "plugin": {"installed": bool(installed), "commit": (spec.get("sourceCommit") or "")[:7],
                       "skills": len(spec.get("importedSkills") or []),
                       "missingConnectors": (mcp.get("missing") or []) if mcp.get("knownStatus") else []},
            "kqlSearchConnected": setup_agent.KQL_CONNECTOR in names
                                  or setup_agent.KQL_CONNECTOR in (mcp.get("configured") or []),
        }

    # POST /api/github-token
    def github_token(self, body: dict) -> dict:
        token = str(body.get("token") or "").strip()
        if not token:
            raise UserError("Paste the token first.")
        if len(token) > 500:
            raise UserError("A token is too long.")
        result = setup_agent.check_github_token(token)
        return {key: result.get(key) for key in ("valid", "login", "expires", "error")}

    # POST /api/run
    def start_job(self, body: dict) -> dict:
        self._signed_in()
        argv = ["--sub", _guid(body.get("sub"), "subscription"), "--rg", _name(body.get("rg"), "resource group"),
                "--agent", _name(body.get("agent"), "agent")]
        repo = str(body.get("repo") or "").strip()
        if repo:
            if not REPO_RE.match(repo):
                raise UserError("The plugin repository must look like owner/name.")
            argv += ["--repo", repo]
        workspace = str(body.get("workspace") or "").strip()
        if workspace:
            if not WORKSPACE_RE.match(workspace):
                raise UserError("The Sentinel workspace must be a Log Analytics workspace resource ID.")
            argv += ["--workspace", workspace]
        steps = [s for s in body.get("steps") or [] if s in setup_agent.STEPS]
        if not steps:
            raise UserError("Select at least one item to configure.")
        argv += ["--only", ",".join(steps)]
        for code_repo in body.get("codeRepos") or []:
            if not REPO_RE.match(str(code_repo)):
                raise UserError(f"'{code_repo}' is not a repository name like owner/name.")
            argv += ["--code-repo", str(code_repo)]
        if body.get("dryRun"):
            argv.append("--dry-run")
        secrets_env = {var: str(body.get(field) or "").strip() for field, var in SECRET_FIELDS.items()}
        if any(len(v) > 500 for v in secrets_env.values()):
            raise UserError("A token is too long.")
        with self.lock:
            if self.job and self.job["running"]:
                raise UserError("The agent is already being configured: wait for the end of the current run.")
            self.job = {"running": True, "log": "", "code": None, "rows": [], "manual": [], "error": None,
                        "dryRun": bool(body.get("dryRun"))}
        threading.Thread(target=self._run_job, args=(self.job, argv, secrets_env), daemon=True).start()
        return {"started": True}

    def _run_job(self, job: dict, argv: list[str], secrets_env: dict[str, str]) -> None:
        try:
            for var, value in secrets_env.items():
                if value:
                    os.environ[var] = value
                else:
                    os.environ.pop(var, None)
            with contextlib.redirect_stdout(JobLog(job)), contextlib.redirect_stderr(JobLog(job)):
                code, report, manual = setup_agent.run(setup_agent.parse_args(argv))
            job.update(code=code, manual=manual[1:],
                       rows=[{"item": i, "status": s, "detail": d} for i, s, d in report.rows])
        except SystemExit as exc:  # setup_agent and deploy_skills stop with sys.exit("ERROR: ...")
            job.update(code=1, error=setup_agent.redact(str(exc.code)))
        except Exception as exc:
            job.update(code=1, error=setup_agent.redact(f"{exc.__class__.__name__}: {exc}"))
        finally:
            for var in secrets_env:
                os.environ.pop(var, None)
            job["running"] = False

    # GET /api/job
    def job_status(self, _: dict) -> dict:
        return self.job or {"running": False, "log": "", "code": None, "rows": [], "manual": [], "error": None}

    # POST /api/exit
    def exit(self, _: dict) -> dict:
        if self.server:
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        return {"stopped": True}


def _guid(value: Any, what: str) -> str:
    value = str(value or "").strip()
    if not GUID_RE.match(value):
        raise UserError(f"Select a valid {what}.")
    return value


def _name(value: Any, what: str) -> str:
    value = str(value or "").strip()
    if not NAME_RE.match(value):
        raise UserError(f"Select a valid {what}.")
    return value


ROUTES = {
    ("GET", "/api/state"): Wizard.state,
    ("POST", "/api/signin"): Wizard.sign_in,
    ("GET", "/api/subscriptions"): Wizard.subscriptions,
    ("GET", "/api/agents"): Wizard.agents,
    ("GET", "/api/agent"): Wizard.agent_details,
    ("POST", "/api/github-token"): Wizard.github_token,
    ("POST", "/api/run"): Wizard.start_job,
    ("GET", "/api/job"): Wizard.job_status,
    ("POST", "/api/exit"): Wizard.exit,
}


# --------------------------------------------------------------------------- #
# HTTP server
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    server_version = "SREAgentSetup"
    sys_version = ""

    def log_message(self, *args: Any) -> None:  # keep the console quiet
        pass

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; "
                         "frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: Any) -> None:
        self._send(status, json.dumps(data).encode("utf-8"), "application/json; charset=utf-8")

    def _handle(self, method: str) -> None:
        wizard: Wizard = self.server.wizard  # type: ignore[attr-defined]
        port = self.server.server_address[1]
        # Reject other host names (DNS rebinding) and requests without the session token (CSRF).
        if self.headers.get("Host", "") not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            return self._json(403, {"error": "Forbidden."})
        url = urlparse(self.path)
        if method == "GET" and url.path in ("/", "/index.html"):
            return self._send(200, wizard.page(), "text/html; charset=utf-8")
        route = ROUTES.get((method, url.path))
        if route is None:
            return self._json(404, {"error": "Not found."})
        if not secrets.compare_digest(self.headers.get("X-Wizard-Session", ""), wizard.session):
            return self._json(403, {"error": "This page is not connected to the running wizard: "
                                             "start SRE-Agent-Setup.exe again."})
        wizard.last_seen = time.time()
        try:
            if method == "POST":
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY_BYTES:
                    return self._json(413, {"error": "Request too large."})
                arg = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(arg, dict):
                    raise UserError("Invalid request.")
            else:
                arg = {k: v[0] for k, v in parse_qs(url.query).items()}
            self._json(200, route(wizard, arg))
        except (UserError, AuthError) as exc:
            self._json(400, {"error": str(exc)})
        except SystemExit as exc:  # sys.exit("ERROR: ...") from setup_agent or deploy_skills
            self._json(400, {"error": setup_agent.redact(str(exc.code))})
        except Exception as exc:
            self._json(500, {"error": setup_agent.redact(f"{exc.__class__.__name__}: {exc}")})


def _disable_quick_edit() -> None:
    """A click in a Windows console with QuickEdit on pauses the process: turn QuickEdit off."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, (mode.value | 0x0080) & ~0x0040)  # EXTENDED_FLAGS on, QUICK_EDIT off
    except Exception:
        pass


def _stop_when_idle(server: ThreadingHTTPServer, wizard: Wizard) -> None:
    while True:
        time.sleep(30)
        running = bool(wizard.job and wizard.job.get("running"))
        if not running and time.time() - wizard.last_seen > IDLE_TIMEOUT_SECONDS:
            server.shutdown()
            return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--use-azure-cli", action="store_true",
                        help="Reuse the Azure CLI sign-in instead of signing in with the browser")
    parser.add_argument("--tenant", help="Directory (tenant) ID or domain to sign in to (default: your home directory)")
    parser.add_argument("--port", type=int, default=0, help="Local port (default: a free port)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically")
    args = parser.parse_args(argv)

    _disable_quick_edit()
    wizard = Wizard("azure-cli" if args.use_azure_cli else "browser", args.tenant)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    server.wizard = wizard  # type: ignore[attr-defined]
    wizard.server = server
    url = f"http://127.0.0.1:{server.server_address[1]}/?s={wizard.session}"

    print("Azure SRE Agent setup wizard (sec-sre-ag)\n")
    print("The wizard opens in your browser. If it does not, copy this address into the browser:")
    print(f"  {url}\n")
    print("Keep this window open while you use the wizard. When you are done, select")
    print("'Close the wizard' in the page or close this window.", flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    threading.Thread(target=_stop_when_idle, args=(server, wizard), daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    print("\nThe setup wizard has stopped. You can close this window.", flush=True)
    if FROZEN:
        time.sleep(3)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
