# Slaunt Agent Access Audit

`npx slaunt audit` maps the MCP capabilities exposed to Claude Code, Claude Desktop, Codex CLI, and the Codex/ChatGPT desktop host. It retrieves declared tool definitions, classifies them locally, correlates risky capability chains, and writes a standalone local HTML report.

```text
$ npx slaunt audit

Slaunt Agent Access Audit
Inspecting MCP configurations locally. No audit payload uploaded.

✓ Found 2 agent clients
✓ Found 5 MCP servers
✓ Retrieved 43 tool definitions
✓ Classified 38 tools
! 5 tools require review
```

The audit-only release does **not** implement `slaunt connect`.

## Privacy promise

The default architecture is intentionally local-first:

- Tool names, descriptions, input schemas, config values, findings, and the HTML report remain on the machine.
- If Supabase is configured, the CLI downloads approved classification rules and performs matching locally. It does not upload an audit payload or call a classification RPC.
- MCP tools are never called. The auditor only performs the MCP initialization handshake and `tools/list`.
- Starting configured stdio servers requires interactive consent, or the explicit `--allow-server-starts` flag.
- The default audit never edits client configuration or opens another window. Slaunt MCP installation requires `--install-slaunt`, and report opening requires `--open-report`.
- JSON output is redacted. Environment and header values are never included.

## Run

Node.js 20.17 or newer is required.

```sh
npx slaunt audit
```

Useful modes:

```sh
# Configuration-only inventory; never starts a local MCP process
npx slaunt audit --no-server-starts

# Non-interactive audit with explicit consent to read declared tool lists
npx slaunt audit --yes

# Redacted machine-readable output
npx slaunt audit --json --no-report --no-install-slaunt --no-server-starts

# Deterministic product demonstration
npx slaunt audit --demo

# Skip deliberate interactive pacing while keeping the full audit
npx slaunt audit --no-motion
npx slaunt audit --quick
```

Run `npx slaunt audit --help` for every option.

## What it discovers

| Client | User configuration | Project configuration |
|---|---|---|
| Claude Code | `~/.claude.json` | `.mcp.json` |
| Claude Desktop | OS-specific `claude_desktop_config.json` | — |
| Codex CLI/Desktop/IDE | `~/.codex/config.toml` | `.codex/config.toml` |

Claude uses JSON for MCP configuration; Codex uses TOML. Codex CLI, the IDE extension, and its desktop host share the same Codex configuration. The paths and schemas follow the current [Claude MCP documentation](https://docs.anthropic.com/en/docs/claude-code/mcp) and [Codex MCP documentation](https://developers.openai.com/codex/mcp).

The scanner supports stdio, Streamable HTTP, and legacy SSE server declarations. Project configs are discovered from the working directory upward to the user home directory. Disabled Codex servers are ignored.

## Secure Slaunt MCP installation

The audit can add Slaunt MCP to each detected client only when `--install-slaunt` is supplied. Installation is:

- explicit and optional;
- idempotent by the reserved server name `slaunt`;
- atomic, using a same-directory temporary file and rename;
- backed up with a timestamp before any existing file changes;
- permission-preserving, with new config files created as user-readable only;
- symlink-safe (the installer refuses to replace a symlink);
- HTTPS-only, except explicit localhost development endpoints.

Override the endpoint only when intentionally testing another trusted Slaunt deployment:

```sh
SLAUNT_MCP_URL=https://your-reviewed-endpoint.example/mcp npx slaunt audit --install-slaunt
```

## Risk model

Classification is per declared tool. Correlation then evaluates what a client can do across servers. Examples include:

- direct production deployment authority;
- shell execution chained with credential access;
- broad GitHub edit and merge permissions shared by multiple clients;
- cleartext non-local MCP endpoints;
- plaintext credential-like config values;
- unpinned dynamic package launchers;
- unknown tools whose names imply administrative or execution behavior.

Unknown does not mean malicious. It means the tool has not matched an approved rule, so the report treats it as potentially sensitive until reviewed.

## Supabase catalog

The database is a distribution channel for approved rules, not an audit telemetry sink.

1. Apply [`supabase/migrations/20260731202505_create_tool_classification_catalog.sql`](supabase/migrations/20260731202505_create_tool_classification_catalog.sql) to the target project.
2. Confirm the table is exposed through the Data API for the project. Supabase changed new-table exposure defaults in 2026, so explicit Data API exposure may be required.
3. Configure the public read-only client values:

   ```sh
   export SLAUNT_SUPABASE_URL=https://your-project.supabase.co
   export SLAUNT_SUPABASE_PUBLISHABLE_KEY=sb_publishable_...
   npx slaunt audit
   ```

The migration enables and forces RLS, removes mutation privileges from public roles, grants column-scoped `SELECT`, and exposes only rows that are both active and approved. It contains no public write policy and no `SECURITY DEFINER` function. Never place a Supabase secret key or legacy `service_role` key in the CLI environment.

Catalog refresh failures fall back to a seven-day local cache and then to the bundled catalog. Use `--offline` to skip refresh entirely.

## Classification contribution workflow

Classification changes should arrive through reviewed pull requests:

1. Add or update the bounded glob rule in `src/classification/builtin-catalog.ts`.
2. Add a regression fixture proving the intended match and non-match behavior.
3. Add the reviewed equivalent to a new Supabase migration.
4. Keep the database row inactive or in review until a maintainer approves it.
5. Run `npm run check && npm test`.

Database patterns are treated as bounded globs, never executable regular expressions. This avoids turning a public catalog into a regular-expression denial-of-service input.

## Terminal experience and conversion ethics

The terminal flow uses immediate collection feedback followed by a short, deliberately paced analysis trail. A single updating line indexes the retrieved tools, searches direct and chained privilege paths, compares client permissions, and ranks the evidence before revealing the report. Every state is derived from the actual audit result; the pacing never invents a server, tool, capability, or finding.

The default view is intentionally concise and written for people who do not need to know MCP terminology: a safety score, the three issues that most need attention, a plain-language explanation of what each assistant can do, and a short list of unfamiliar actions that need review. Technical service and action names remain visible as secondary details. Supporting issues and complete evidence remain in the local HTML report. The CLI writes that report without opening it; use `--open-report` when you explicitly want a browser window.

The guided inspection targets about 78 seconds from launch and walks through 14 evidence-backed phases. Each phase reveals a result derived from the audit—inventory availability, schema coverage, sensitive surfaces, direct authority, cross-server paths, role overlap, unknown tools, and final confidence—while keeping the terminal to one changing status line. It runs only in an interactive terminal. JSON output, piped output, CI, `--yes`, `--quick`, `--no-motion`, and `SLAUNT_NO_MOTION=1` remain immediate. The audit also refuses to start a configured stdio entry that resolves back to the `slaunt` CLI, preventing recursive audit windows. The experience deliberately avoids variable rewards, deceptive urgency, hidden defaults, shame, or an unsupported claim that a UI can medically “optimize dopamine.”

The design is informed by evidence that progress feedback can improve follow-through, autonomy-supportive framing is associated with more self-directed motivation, and risk messages work better when paired with an effective action. See the PubMed-indexed reviews on [progress feedback](https://pubmed.ncbi.nlm.nih.gov/33721605/), [autonomy support](https://pubmed.ncbi.nlm.nih.gov/30237648/), and [fear appeals with efficacy](https://pubmed.ncbi.nlm.nih.gov/26501228/). These findings come from other domains, so their application to developer security tooling is a product hypothesis, not a medical claim.

## Local development

```sh
npm ci
npm run check
npm test
npm run audit:demo
```

`npm test` builds first, then runs deterministic tests for config parsing, idempotent backups, local classification, cross-client correlation, secret redaction, report CSP, and the built CLI.

## Scope limitations

This is a declared-access audit. It does not inspect prompts, file contents, credentials, non-MCP agents, client approval policy, OAuth scopes that are not reflected in tool declarations, or whether a tool has been used. A failed or skipped server probe means its tool inventory is unavailable—not that the server is safe.

See [SECURITY.md](SECURITY.md) for the security boundary and reporting process.
