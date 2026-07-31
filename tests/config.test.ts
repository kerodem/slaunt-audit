import { chmod, mkdir, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { discoverConfigurations } from '../src/config/discover.js';
import { installSlauntMcp } from '../src/config/install.js';
import type { PathContext } from '../src/config/paths.js';

const temporaryRoots: string[] = [];

async function fixture(): Promise<{ root: string; context: PathContext }> {
  const root = await mkdtemp(join(tmpdir(), 'slaunt-audit-test-'));
  temporaryRoots.push(root);
  const home = join(root, 'home');
  const cwd = join(home, 'work', 'project');
  await mkdir(cwd, { recursive: true });
  return { root, context: { home, cwd, platform: 'darwin' } };
}

afterEach(async () => {
  const { rm } = await import('node:fs/promises');
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe('configuration discovery', () => {
  it('discovers Claude Code, Claude Desktop, and shared Codex TOML configs', async () => {
    const { context } = await fixture();
    await mkdir(join(context.home, '.codex'), { recursive: true });
    await mkdir(join(context.home, 'Library', 'Application Support', 'Claude'), { recursive: true });
    await writeFile(join(context.home, '.claude.json'), JSON.stringify({
      mcpServers: { railway: { type: 'http', url: 'https://railway.example/mcp' } },
    }));
    await writeFile(join(context.home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), JSON.stringify({
      mcpServers: { filesystem: { command: 'node', args: ['server.js'] } },
    }));
    await writeFile(join(context.home, '.codex', 'config.toml'), '[mcp_servers.github]\nurl = "https://github.example/mcp"\n');
    await writeFile(join(context.cwd, '.mcp.json'), JSON.stringify({
      mcpServers: { shell: { command: 'shell-mcp', env: { API_TOKEN: '${API_TOKEN}' } } },
    }));

    const result = await discoverConfigurations({ context });
    expect(result.clients.filter((client) => client.detected).map((client) => client.id).sort()).toEqual([
      'claude-code', 'claude-desktop', 'codex',
    ]);
    expect(result.servers.map((server) => server.name).sort()).toEqual(['filesystem', 'github', 'railway', 'shell']);
    expect(result.servers.find((server) => server.name === 'shell')?.envKeys).toEqual(['API_TOKEN']);
  });

  it('ignores disabled Codex servers', async () => {
    const { context } = await fixture();
    await mkdir(join(context.home, '.codex'), { recursive: true });
    await writeFile(join(context.home, '.codex', 'config.toml'), '[mcp_servers.old]\nenabled = false\ncommand = "old-mcp"\n');
    const result = await discoverConfigurations({ context });
    expect(result.servers).toHaveLength(0);
  });
});

describe('Slaunt MCP installation', () => {
  it('backs up and atomically updates user JSON and TOML configs', async () => {
    const { context } = await fixture();
    const claudePath = join(context.home, '.claude.json');
    const codexPath = join(context.home, '.codex', 'config.toml');
    await mkdir(join(context.home, '.codex'), { recursive: true });
    await writeFile(claudePath, '{"mcpServers":{"existing":{"command":"safe"}}}\n');
    await writeFile(codexPath, '[mcp_servers.existing]\ncommand = "safe"\n');
    await chmod(claudePath, 0o600);
    await chmod(codexPath, 0o600);

    const changes = await installSlauntMcp({ clients: ['claude-code', 'codex'], context, url: 'https://mcp.example.test/mcp' });
    expect(changes.map((change) => change.status)).toEqual(['installed', 'installed']);
    expect(changes.every((change) => change.backupPath)).toBe(true);
    expect(JSON.parse(await readFile(claudePath, 'utf8')).mcpServers.slaunt).toEqual({ type: 'http', url: 'https://mcp.example.test/mcp' });
    expect(await readFile(codexPath, 'utf8')).toContain('[mcp_servers.slaunt]');
    expect((await stat(claudePath)).mode & 0o777).toBe(0o600);

    const repeated = await installSlauntMcp({ clients: ['claude-code', 'codex'], context, url: 'https://mcp.example.test/mcp' });
    expect(repeated.map((change) => change.status)).toEqual(['already-present', 'already-present']);
  });

  it('rejects cleartext non-local MCP endpoints', async () => {
    const { context } = await fixture();
    await expect(installSlauntMcp({ clients: ['codex'], context, url: 'http://example.com/mcp' })).rejects.toThrow('must use HTTPS');
  });

  it('does not silently trust a conflicting server named slaunt', async () => {
    const { context } = await fixture();
    await mkdir(join(context.home, '.codex'), { recursive: true });
    await writeFile(join(context.home, '.codex', 'config.toml'), '[mcp_servers.slaunt]\nurl = "https://attacker.example/mcp"\n');
    const [change] = await installSlauntMcp({ clients: ['codex'], context, url: 'https://mcp.example.test/mcp' });
    expect(change?.status).toBe('failed');
    expect(change?.message).toContain('different settings');
  });
});
