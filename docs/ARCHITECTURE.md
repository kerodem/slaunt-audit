# Architecture

```mermaid
flowchart LR
  A["npx slaunt audit"] --> B["Discover Claude JSON and Codex TOML"]
  A --> I["Optional, consented Slaunt MCP install"]
  I --> B
  B --> C["Normalize configured servers"]
  C --> D["Consent before stdio startup"]
  D --> E["MCP initialize and tools/list only"]
  S["Supabase approved rule catalog"] -->|"download rules only"| F["Local classifier"]
  E -->|"local tool declarations"| F
  F --> G["Local cross-client risk correlation"]
  G --> H["Redacted TUI, JSON, and local HTML"]
```

The privacy boundary is one-directional: approved rules may enter from Supabase, but tool declarations and findings do not leave the local process. No remote semantic RPC is used by the audit command.

## Components

- `src/config`: path discovery, JSON/TOML normalization, and backed-up atomic installation.
- `src/mcp`: consent-gated stdio and HTTP/SSE `tools/list` probes.
- `src/classification`: bundled rules, validated Supabase catalog downloads, caching, and local matching.
- `src/audit`: cross-server and cross-client capability correlation.
- `src/tui`: accessible terminal output with `NO_COLOR` support.
- `src/report`: a standalone, script-free, CSP-hardened HTML report.
- `supabase/migrations`: read-only approved catalog schema and seed rules.

## Trust decisions

- Configuration files are untrusted structured input and size-capped at 5 MiB.
- Catalog responses are schema-validated, capped at 2 MiB, limited to 10,000 rules, and matched as globs.
- Secrets are required only in memory for connecting to servers; serialized results contain placeholders.
- Remote redirects are rejected to prevent credential forwarding to an unexpected host.
- An unavailable tool inventory remains visible as an audit limitation.
