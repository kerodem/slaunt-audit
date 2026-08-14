# slaunt audit

```bash
npm install slaunt-audit
```


See what Claude and Codex can do through their configured MCP servers.

```sh
npx slaunt audit
```

No account or database configuration is required.

Slaunt discovers local MCP configurations, requests each server's declared tool list, classifies those tools, and identifies risky permissions or combinations. It then writes a private HTML report on your machine.

## What the audit checks

- Claude Code, Claude Desktop, Codex CLI, and Codex Desktop configurations
- MCP servers declared in JSON or TOML
- Tools exposed by each server
- Sensitive capabilities such as shell execution, secret access, code changes, and production deployment
- Risky combinations across servers and clients
- Unknown tools that still need classification review

Slaunt performs the MCP initialization handshake and `tools/list`. It never calls an MCP tool.

## Run modes

```sh
# Normal interactive audit
npx slaunt audit

# Inspect configuration without starting local MCP processes
npx slaunt audit --no-server-starts

# Run non-interactively and allow declared tool-list requests
npx slaunt audit --yes

# Skip the paced terminal presentation
npx slaunt audit --quick

# Use only the bundled classification rules
npx slaunt audit --offline

# Produce redacted JSON without a report
npx slaunt audit --json --no-report --no-server-starts
```

run `npx slaunt audit --help` for all options. **Node.js 20.17 or newer is required.**

## Privacy and consent

- Tool names, descriptions, schemas, configuration values, findings, and reports stay local.
- Slaunt downloads approved classification rules from a read-only Supabase catalog. It does not upload audit data.
- Starting a configured stdio server requires interactive consent or `--allow-server-starts`.
- Slaunt MCP installation happens only with `--install-slaunt`.
- The HTML report opens only with `--open-report`.
- Environment variables and HTTP header values are redacted from JSON and reports.

If the remote catalog is unavailable, Slaunt uses a seven-day local cache and then its bundled rules. `--offline` disables the refresh entirely.

## How classification works

Approved database rules and bundled rules map tool declarations to capabilities and risk levels. Matching happens locally. Slaunt then checks direct authority and cross-server attack paths, such as a client that can execute shell commands and read secrets.

Unknown does not mean malicious. It means no approved rule matched the tool, so Slaunt treats it as potentially sensitive until reviewed.

## Optional Slaunt MCP installation

```sh
npx slaunt audit --install-slaunt
```

Installation is explicit, idempotent, backed up, atomic, permission-preserving, and symlink-safe. The default audit never edits client configuration.

## Audit limits

This is a declared-access audit. It does not inspect prompts, file contents, credentials, non-MCP agents, hidden provider scopes, client approval policy, or whether a tool has been used. If a server cannot be inspected, its tool inventory remains unavailable; Slaunt does not treat that server as safe.

## Development

```sh
npm ci
npm run check
npm test
```

The Supabase schema is in [`supabase/migrations`](supabase/migrations). Public clients receive only approved, active rules through column-scoped `SELECT`, forced Row Level Security, and no public mutation policy. Never ship or expose a Supabase secret key.

See [SECURITY.md](SECURITY.md) for the complete security boundary and vulnerability-reporting process.
