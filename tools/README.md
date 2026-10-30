# Tools

Tools for the Azure SRE Agent plugin in this repository. Run the Python tools from
the repository root.

| Tool | What it does | When to use it |
|---|---|---|
| [`SRE-Agent-Setup.exe`](#sre-agent-setupexe--the-setup-wizard) ([`wizard/`](wizard)) | A web page that does what `setup_agent.py` does, for people who do not use Python: sign in, choose the agent, configure | Give it to customers: nothing to install |
| [`setup_agent.py`](setup_agent.py) | Installs the plugin from GitHub and configures, through the Azure SRE Agent REST APIs, everything a plugin cannot install: connectors, knowledge base and, optionally, Code Access | First setup of an agent, and whenever you want to re-apply the configuration |
| [`plugin.py`](plugin.py) | Copies the shared files into the skills (`sync`) and validates the plugin as strictly as the plugin importer (`check`) | After every change to `skills/`, `shared/` or the shared documents in `docs/` |
| [`deploy_skills.py`](deploy_skills.py) | Pushes the skills to Skill Builder instead of installing the plugin | Only if you do not use the plugin on that agent |

## `SRE-Agent-Setup.exe` — the setup wizard

A portable Windows program for customers who do not know Python. It contains its
own Python runtime and the logic of `setup_agent.py`, so the computer needs neither
Python nor Azure CLI, and nothing is installed.

**Use it:**

1. Download `SRE-Agent-Setup.exe` from the latest release of the repository and
   double-click it. A small window stays open while the wizard runs, and a page
   opens in the default browser.
2. **Sign in**: the Microsoft sign-in page opens in a new tab. Use an account with
   **SRE Agent Administrator** on the agent. If the subscription is in another
   directory, enter its tenant ID or domain under *My subscription is in another
   directory* first.
3. **Choose** the subscription and the agent. The page shows the agent status, its
   identity, the installed connectors, whether the skills are already installed and
   whether the plugin page shows *Connector setup required*.
4. **Choose what to configure**: install the skills (plugin), connect Microsoft
   Sentinel and the documentation tools (keep the existing Log Analytics connector or
   pick the Sentinel workspace), and add the troubleshooting guide. Code Access, a
   different plugin repository and private-repository tokens are under *Advanced
   options*.
   The **KQL search tools** box is optional and needs a GitHub token (a free GitHub
   account is enough, and the token needs no permission):
   1. Select **Create the token on GitHub**: GitHub opens with the name, the
      description and a one-year expiration already filled in. Sign in, select
      **Generate token** at the bottom of the page and copy the token
      (`github_pat_...`).
   2. Paste it in the wizard. The wizard asks GitHub at once whether the token works
      and shows its account and expiration date, or why it does not work.

   Without a token the KQL search tools are skipped, and the plugin page keeps
   showing *Connector setup required* for `kql-search-mcp`. To add them later, or to
   replace an expiring token, run the wizard again with only **Connect Microsoft
   Sentinel and the documentation tools** selected.
5. Select **Configure the agent**, with **Preview only** first if you want to see the
   planned changes. Each item shows OK, MANUAL (something to complete), WARN or
   FAILED; *Show details* displays the full log. The *plugin page* item tells whether
   the plugin page in the portal still shows *Connector setup required*, and for
   which connector.
6. **What is left to do** lists the permission commands, with the agent identity and
   the Sentinel workspace already filled in: copy them into Azure Cloud Shell. Then
   connect Outlook and Teams in the portal, and select **Close the wizard**.

**If Windows stops it:**

| Message | What to do |
|---|---|
| *Windows protected your PC* (SmartScreen) | Select **More info > Run anyway**. The message disappears when the file is signed (see below) |
| *An Application Control policy has blocked this file*, or *Your organization used ... to block this app* | The single-file program unpacks itself into the Temp folder, which many companies block. Download `SRE-Agent-Setup-folder.zip` from the same release, extract it into a folder where you can run programs, and double-click `SRE-Agent-Setup.exe` in it. If that is blocked too, ask IT to allow or sign it, or follow the portal steps in the main README |
| The antivirus quarantines the file | A false positive that is common with packaged Python programs: sign the file, or report it to the antivirus vendor |

**Security:** the page is served only on `127.0.0.1`, and every request must carry
the random session code in the page address. The sign-in uses the Microsoft
identity platform in your browser (MSAL with the public client ID of Azure CLI,
the default of the Azure Identity libraries); access tokens and the GitHub tokens
you type stay in memory and are never written to disk or to the log. GitHub tokens
are sent only to Azure SRE Agent and, to check the KQL search token, to
`api.github.com`. The wizard stops when you close it, or after two hours without
activity.

**Publish it for customers** (maintainers):

1. Push to `main`: the [Build setup wizard](../.github/workflows/build-setup-wizard.yml)
   workflow builds both files and keeps them as a workflow artifact.
2. Push a tag with any name, for example `git tag v1.0.0 && git push origin v1.0.0`, or
   create a release with a new tag on the GitHub **Releases** page: the workflow
   publishes `SRE-Agent-Setup.exe` and `SRE-Agent-Setup-folder.zip` in the release of
   that tag. For a tag created before this workflow existed, open **Actions > Build
   setup wizard > Run workflow** and type the tag. Give customers the link to the
   latest release: `https://github.com/<owner>/<repo>/releases/latest`.
3. Each build installs, by default, the plugin from the repository that built it
   (customers can change it under *Advanced options*).
4. Recommended before giving it to customers: sign both executables with a
   code-signing certificate, for example with Azure Trusted Signing. Signed files
   avoid the SmartScreen warning and most antivirus false positives.

**Build it locally** (Windows, Python 3.10+): `pwsh tools/wizard/build.ps1`, or
`-Repo <owner>/<repo>` to set the default plugin repository. The script creates
`build/wizard/venv`, installs the pinned [requirements](wizard/requirements-build.txt)
and writes `dist/SRE-Agent-Setup.exe` and `dist/SRE-Agent-Setup-folder.zip`.

**Run it without packaging** (developers): `python -m pip install -r
tools/wizard/requirements.txt`, then `python tools/wizard/sre_setup_wizard.py`. Add
`--use-azure-cli` to reuse an existing `az login` instead of the browser sign-in,
`--tenant <tenant>` to sign in to another directory, and `--no-browser` to only
print the page address.

## Requirements

- Python 3.10 or later (tested with 3.13 and 3.14). `setup_agent.py` and
  `deploy_skills.py` use only the standard library; `plugin.py check` needs
  PyYAML: `python -m pip install pyyaml`.
- Azure CLI signed in to the tenant of the agent subscription: `az login`, or
  `az login --tenant <TENANT_ID>`.
- Outbound HTTPS to Azure Resource Manager (`https://management.azure.com`) and
  to the agent data-plane endpoint (`https://*.azuresre.ai`).
- **SRE Agent Administrator** on the agent. To discover the Sentinel workspace
  automatically, the account also needs **Reader** on it (or pass `--workspace`).

The tools request their tokens **for the target subscription**
(`az account get-access-token --subscription <SUB> ...`), so they automatically use
that subscription's home tenant. You do not need `az account set`.

## Target configuration

Provide the target agent (CLI flags win over environment variables, which win over
the config file):

- CLI flags: `--sub <SUB> --rg <RG> --agent <AGENT>` (`--tenant <TENANT>` optional)
- Environment variables: `SRE_SUB`, `SRE_RG`, `SRE_AGENT` (`SRE_TENANT` optional)
- File: copy [`deploy.config.example.json`](deploy.config.example.json) to
  `tools/deploy.config.json` (gitignored) and fill it in. The same file can also
  hold the optional `pluginRepo`, `sentinelWorkspaceResourceId` and
  `codeAccessRepos` used by `setup_agent.py`. Never put secrets in it.

## `setup_agent.py` — one-command setup

```bash
az login
python tools/setup_agent.py --sub <SUB> --rg <RG> --agent <AGENT> --dry-run   # read-only preview
python tools/setup_agent.py --sub <SUB> --rg <RG> --agent <AGENT>
```

| Step | What it configures | API |
|---|---|---|
| 1. `plugin` | Installs this repository as a plugin: all 13 skills with their Python scripts and data files. Skipped when the plugin is already installed. Stops if Skill Builder skills with the same names exist | `POST {endpoint}/api/v2/plugins/install-direct` |
| 2. `connectors` | `sentinel-workspace` (Log Analytics connector for the Microsoft Sentinel workspace, with the agent managed identity), `ms-learn-mcp` (Microsoft Learn MCP) and `kql-search-mcp` (stdio MCP, `kql-search-mcp@1.0.5`), with the tool selection documented in the main README. MCP connectors are tested after creation | ARM `PUT .../agents/{agent}/connectors/{name}`, data-plane `.../connectors/{name}/testconnection` |
| 3. `knowledge` | Uploads `docs/known-issues.md` to the agent knowledge base | `POST {endpoint}/api/v1/agentmemory/upload` |
| 4. `code-access` | Optional, only with `--code-repo <owner>/<repo>`: connects GitHub repositories through Code Access, for example the private repository of the DOCX technical report module | `PUT {endpoint}/api/v2/repos/{name}` |

At the end the script reports whether the plugin page still shows *Connector setup
required*: it reads `mcpConnectorStatus` of the plugin installation
(`GET {endpoint}/api/v2/plugins/installations`), the same status the portal shows.
Then it prints what still needs a person, with the identity IDs
already filled in: the permission scripts in [`../setup`](../setup) and the Outlook
and Teams connectors, which require an interactive OAuth sign-in.

Useful options:

| Option | Meaning |
|---|---|
| `--dry-run` | Reads the agent state and prints the planned changes; writes nothing |
| `--only connectors` / `--skip knowledge` | Run or skip specific steps (`plugin`, `connectors`, `knowledge`, `code-access`) |
| `--repo <owner>/<repo>` | Repository to install as a plugin. Default: the `origin` remote of this clone |
| `--workspace <resource ID>` | Sentinel workspace for the Log Analytics connector. Default: the only Sentinel workspace in the agent subscription. An existing Log Analytics connector is kept unless you pass this option |
| `--code-repo <owner>/<repo>` | Repository to connect through Code Access (repeatable) |

Secrets are read only from environment variables, never from the command line:

| Variable | Needed for |
|---|---|
| `KQL_SEARCH_GITHUB_TOKEN` | `kql-search-mcp`: a GitHub token, created at the [pre-filled token page](https://github.com/settings/personal-access-tokens/new?name=Azure+SRE+Agent+KQL+search&description=Read-only+token+for+the+kql-search-mcp+connector+of+Azure+SRE+Agent&expires_in=365) (no permission needed: every token reads public repositories). The script checks it with GitHub (`GET https://api.github.com/user`) and reports its expiration date; a token GitHub rejects stops the connector with FAILED. Without it the connector is skipped, and the plugin page shows *Connector setup required* |
| `KQL_SEARCH_FAVORITE_REPOS` | Optional `FAVORITE_REPOS` for `kql-search-mcp` |
| `PLUGIN_GITHUB_PAT` | Only when the plugin repository is private |
| `CODE_ACCESS_GITHUB_PAT` | Only for `--code-repo` when the agent is not signed in to GitHub yet. Otherwise the script prints the OAuth sign-in URL |

```bash
# Bash
export KQL_SEARCH_GITHUB_TOKEN='<GitHub token>'
# PowerShell
$env:KQL_SEARCH_GITHUB_TOKEN = '<GitHub token>'
```

Every step is idempotent: run the script again after fixing a prerequisite.

## `plugin.py` — keep the plugin consistent

Each skill folder must be self-contained: the agent copies only the skill folder
into its sandbox. Files used by several skills are maintained once and copied into
the skills by `sync`:

| Canonical file | Bundled into |
|---|---|
| `shared/enrich_ips.py` | computer-investigation, ioc-investigation, user-investigation |
| `shared/shared-guardrails.md` | the 10 skills that run KQL queries |
| `docs/email-html-report.md`, `docs/teams-delivery.md` | the 8 skills that produce HTML reports |

```bash
python tools/plugin.py sync    # after editing a canonical file
python tools/plugin.py check   # before every commit; CI runs it on every push and pull request
```

`check` validates `plugin.json` and `.mcp.json`, parses every `SKILL.md` front
matter with a strict YAML parser (an invalid front matter is imported with an
empty description, so the agent never selects the skill), checks that the skill
`name` matches its folder and that the description has at most 1,024 characters,
that every relative Markdown link stays inside its skill folder and exists, that
every Python script compiles and every JSON and YAML file parses, and that the
bundled copies match their canonical files.

## `deploy_skills.py` — Skill Builder deployment (alternative)

Use it only on agents where you do **not** install the plugin: the same skill names
cannot be owned by both. The tool refuses to overwrite skills that a plugin
installed.

It creates or updates every folder under `skills/` as a Skill Builder skill:
`SKILL.md` becomes the default file and its front-matter `description` becomes the
skill description; every other file in the folder (references, Python scripts,
data files) is uploaded as a supporting file. The agent syncs them into its sandbox
under `runtime-content/skills/extended/live/<skill>/`, where the skills run them.

```bash
# 1. Preview what will be sent (no network)
python tools/deploy_skills.py build

# 2. List skills already on the agent
python tools/deploy_skills.py list

# 3. Create/update all skills, including supporting files (idempotent)
python tools/deploy_skills.py deploy --dry-run
python tools/deploy_skills.py deploy

# ...or a subset
python tools/deploy_skills.py deploy --skills identity-posture,incident-comment

# 4. Dump the current server-side skills (shape reference, written to tools/discovered/)
python tools/deploy_skills.py discover

# 5. Delete named skills (for example before switching the agent to the plugin)
python tools/deploy_skills.py delete --skills threat-pulse
```

Skills are created or updated with a single `PUT` to the per-agent data plane,
the same call the portal's Skill Builder makes:

```
PUT {agentEndpoint}/api/v2/extendedAgent/skills/{name}
{
  "name": "<name>",
  "type": "Skill",
  "properties": {
    "description": "<from SKILL.md front matter>",
    "tools": [],
    "skillContent": "<full SKILL.md>",
    "additionalFiles": [ { "filePath": "<relative path>", "content": "<text>" } ],
    "sourcePluginInstallation": null
  }
}
```

- **Endpoint**: `agentEndpoint` is read from
  `GET .../Microsoft.App/agents/<agent>?api-version=2025-05-01-preview` on ARM.
- **Auth**: `az account get-access-token --subscription <SUB> --resource <res>`
  for the ARM lookup (`https://management.azure.com`) and the data-plane calls
  (`https://azuresre.dev`).
- **Idempotent**: `PUT` replaces the whole skill, so re-running keeps the agent in
  sync with the local folders, including added or removed supporting files.
- **List / delete**: `GET` / `DELETE {agentEndpoint}/api/v2/extendedAgent/skills[/<name>]`.

The skill folders carry no tenant-specific values, so the same repository deploys
to any agent: sign in to the tenant of the target subscription and pass its
`--sub`, `--rg` and `--agent`.
