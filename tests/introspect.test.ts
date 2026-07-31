import { describe, expect, it } from 'vitest';
import { isRecursiveSlauntLauncher, probeServers } from '../src/mcp/introspect.js';
import type { ServerConfig } from '../src/types.js';

function server(command: string, args: string[]): ServerConfig {
  return {
    id: 'test-server',
    client: 'codex',
    clientLabel: 'Codex',
    name: 'slaunt',
    transport: 'stdio',
    sourcePath: '~/.codex/config.toml',
    scope: 'user',
    command,
    args,
    env: {},
    envKeys: [],
    headers: {},
    headerKeys: [],
    enabled: true,
  };
}

describe('stdio probe launch safety', () => {
  it('recognizes direct and package-runner invocations of this CLI', () => {
    expect(isRecursiveSlauntLauncher(server('slaunt', []))).toBe(true);
    expect(isRecursiveSlauntLauncher(server('npx', ['--yes', 'slaunt']))).toBe(true);
    expect(isRecursiveSlauntLauncher(server('pnpx', ['slaunt@0.1.1']))).toBe(true);
    expect(isRecursiveSlauntLauncher(server('node', ['/tmp/slaunt-audit/dist/cli.js']))).toBe(true);
    expect(isRecursiveSlauntLauncher(server('npx', ['@modelcontextprotocol/server-filesystem']))).toBe(false);
  });

  it('refuses to spawn a recursive audit even when local starts are approved', async () => {
    const [probe] = await probeServers([server('npx', ['--yes', 'slaunt'])], {
      allowServerStarts: true,
      timeoutMs: 1_000,
    });
    expect(probe).toMatchObject({
      status: 'skipped',
      tools: [],
      message: 'Skipped a Slaunt CLI launcher to prevent a recursive audit',
    });
  });
});
