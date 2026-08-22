# Security policy

## Supported versions

Until the first stable release, security fixes are applied to the latest published `0.x` release and `main`.

## Report a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, execute configured MCP servers unexpectedly, bypass redaction, modify client configuration without consent, or upload local audit data.

Use GitHub private vulnerability reporting for `kerodem/slaunt-audit`. Include the affected version, platform, minimal reproduction, security impact, and whether configured server processes were started. Never include real tokens, credential values, private config files, or an unredacted generated report.

## Security boundary

The auditor promises that:

- it never invokes an MCP tool;
- it never uploads tool definitions, configurations, or findings;
- database-backed classification downloads approved rules for local matching;
- stdio MCP processes start only with explicit consent;
- client config changes occur only with explicit consent and a backup;
- config values are redacted from JSON and HTML output;
- stdio starts do not inherit the full parent environment unless `--inherit-parent-env` is explicitly selected;
- remote endpoints must be HTTPS unless they are loopback development addresses;
- redirects are rejected for catalog and MCP HTTP requests;
- public Supabase credentials are read-only and RLS-constrained.

Starting a configured stdio server executes the command already present in the user's MCP configuration. Dynamic launchers such as `npx`, `uvx`, and `docker` can resolve or execute third-party code. The TUI calls this out before consent. Use `--no-server-starts` for a purely static inventory.

The generated HTML report contains no script and no remote asset. Its content security policy blocks all resources except its inline stylesheet and data images. The report can still reveal local usernames, configuration paths, tool names, and security findings; it is created with user-only permissions and should be shared only after review.

## Maintainer release checklist

- Run `npm ci --ignore-scripts`, `npm audit --omit=dev`, `npm run check`, and `npm test`.
- Review every dependency and lockfile change.
- Verify `npm pack --dry-run` contains no configs, reports, environment files, source maps with secrets, or tests.
- Exercise `--json` against secret-bearing fixtures and confirm values are absent.
- Verify the Supabase policy with `anon`, `authenticated`, and privileged roles before deployment.
- Publish with npm provenance and two-factor authentication from a protected release workflow.
