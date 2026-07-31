import type { DiscoveredConfiguration, ServerConfig, ServerProbe } from './types.js';

function server(
  id: string,
  client: ServerConfig['client'],
  clientLabel: string,
  name: string,
  transport: ServerConfig['transport'] = 'stdio',
): ServerConfig {
  return {
    id,
    client,
    clientLabel,
    name,
    transport,
    sourcePath: client === 'codex' ? '~/.codex/config.toml' : '~/.claude.json',
    scope: 'user',
    ...(transport === 'stdio' ? { command: 'demo-mcp' } : { url: 'https://example.invalid/mcp' }),
    args: [],
    env: {},
    envKeys: [],
    headers: {},
    headerKeys: [],
    enabled: true,
  };
}

const servers = [
  server('claude-github', 'claude-code', 'Claude Code', 'github'),
  server('codex-github', 'codex', 'Codex', 'github'),
  server('claude-railway', 'claude-code', 'Claude Code', 'railway', 'http'),
  server('claude-filesystem', 'claude-code', 'Claude Code', 'filesystem'),
  server('codex-filesystem', 'codex', 'Codex', 'filesystem'),
  server('claude-shell', 'claude-code', 'Claude Code', 'shell'),
  server('codex-shell', 'codex', 'Codex', 'shell'),
  server('codex-secrets', 'codex', 'Codex', 'secrets'),
];

function probe(config: ServerConfig, tools: Array<[string, string]>): ServerProbe {
  return {
    serverId: config.id,
    status: 'ok',
    tools: tools.map(([name, description]) => ({
      serverId: config.id,
      serverName: config.name,
      client: config.client,
      clientLabel: config.clientLabel,
      name,
      description,
      inputSchema: { type: 'object', properties: {} },
    })),
  };
}

const githubTools: Array<[string, string]> = [
  ['list_repositories', 'List repositories visible to the authenticated user'],
  ['get_file', 'Get a repository file'],
  ['search_code', 'Search source code'],
  ['create_file', 'Create a repository file'],
  ['update_file', 'Update a repository file'],
  ['create_pull_request', 'Create a pull request'],
  ['merge_pull_request', 'Merge a pull request'],
];

const filesystemTools: Array<[string, string]> = [
  ['list_files', 'List files in an allowed directory'],
  ['read_file', 'Read a local file'],
  ['write_file', 'Write a local file'],
  ['edit_file', 'Edit a local file'],
  ['delete_file', 'Delete a local file'],
];

const shellTools: Array<[string, string]> = [
  ['exec_command', 'Execute a shell command'],
  ['run_command', 'Run a command in the workspace'],
  ['list_processes', 'List running processes'],
];

export function demoDiscovery(): DiscoveredConfiguration {
  return {
    clients: [
      { id: 'claude-code', label: 'Claude Code', detected: true, sources: ['~/.claude.json'] },
      { id: 'claude-desktop', label: 'Claude Desktop', detected: false, sources: [] },
      { id: 'codex', label: 'Codex', detected: true, sources: ['~/.codex/config.toml'] },
    ],
    servers,
    warnings: [],
  };
}

export function demoProbes(): ServerProbe[] {
  return [
    probe(servers[0]!, githubTools),
    probe(servers[1]!, githubTools),
    probe(servers[2]!, [
      ['list_services', 'List Railway services'],
      ['get_deployment', 'Get deployment details'],
      ['deploy_service', 'Deploy a service to production'],
      ['list_variables', 'List configured variable names'],
      ['trigger_job', 'Trigger a configured Railway job'],
    ]),
    probe(servers[3]!, [...filesystemTools, ['sync', 'Synchronize an internal workspace']]),
    probe(servers[4]!, [...filesystemTools, ['company_data.query', 'Run a proprietary company lookup']]),
    probe(servers[5]!, [...shellTools, ['internal.run_workflow', 'Run an internal workflow']]),
    probe(servers[6]!, [...shellTools, ['admin.execute', 'Execute an internal administrative action']]),
    probe(servers[7]!, [
      ['get_secret', 'Get a credential'],
      ['list_secrets', 'List credential names'],
      ['read_credential', 'Read a stored credential'],
      ['rotate_secret', 'Rotate a stored credential'],
    ]),
  ];
}
