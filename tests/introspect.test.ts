import { describe, expect, it } from 'vitest';
import { expandEnvironment, isRecursiveSlauntLauncher, probeServers, resolvedEnvironment } from '../src/mcp/introspect.js';
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

describe('stdio environment boundary', () => {
  it('does not expand sensitive parent variables unless explicitly approved', () => {
    const name = 'SLAUNT_AUDIT_TEST_PARENT_SECRET';
    const previous = process.env[name];
    process.env[name] = 'parent-secret-value';
    try {
      expect(() => expandEnvironment(`\${${name}}`)).toThrow('Sensitive environment expansion');
      expect(expandEnvironment(`\${${name}}`, true)).toBe('parent-secret-value');
    } finally {
      if (previous === undefined) delete process.env[name];
      else process.env[name] = previous;
    }
  });

  it('passes configured variables without inheriting unrelated parent variables', () => {
    const name = 'SLAUNT_AUDIT_TEST_PARENT_SECRET';
    const previous = process.env[name];
    process.env[name] = 'parent-secret-value';
    try {
      expect(resolvedEnvironment({ MCP_MODE: 'audit' })).toEqual({ MCP_MODE: 'audit' });
    } finally {
      if (previous === undefined) delete process.env[name];
      else process.env[name] = previous;
    }
  });

  it('supports explicit full parent-environment inheritance', () => {
    const name = 'SLAUNT_AUDIT_TEST_PARENT_SECRET';
    const previous = process.env[name];
    process.env[name] = 'parent-secret-value';
    try {
      expect(resolvedEnvironment({ MCP_MODE: 'audit' }, true)).toMatchObject({
        MCP_MODE: 'audit',
        [name]: 'parent-secret-value',
      });
    } finally {
      if (previous === undefined) delete process.env[name];
      else process.env[name] = previous;
    }
  });

  it('never expands sensitive variables into remote HTTP probe headers', async () => {
    const name = 'SLAUNT_AUDIT_TEST_HTTP_SECRET';
    const previous = process.env[name];
    process.env[name] = 'remote-secret-value';
    const remote: ServerConfig = {
      ...server('unused', []),
      transport: 'http',
      command: undefined,
      url: 'https://mcp.example.test/mcp',
      headers: { Authorization: `Bearer \${${name}}` },
      headerKeys: ['Authorization'],
    };
    try {
      const [probe] = await probeServers([remote], {
        allowServerStarts: false,
        allowSensitiveEnvironment: true,
        timeoutMs: 1_000,
      });
      expect(probe?.status).toBe('failed');
      expect(probe?.message).toContain('Sensitive environment expansion');
    } finally {
      if (previous === undefined) delete process.env[name];
      else process.env[name] = previous;
    }
  });
});
