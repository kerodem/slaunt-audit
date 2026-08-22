import { describe, expect, it } from 'vitest';
import { runAudit } from '../src/audit/run.js';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { renderHtmlReport, writeHtmlReport } from '../src/report/html.js';
import type { DiscoveredConfiguration } from '../src/types.js';

describe('privacy boundary and report', () => {
  it('redacts configuration values from the result and JSON output', async () => {
    const discovery: DiscoveredConfiguration = {
      clients: [
        { id: 'claude-code', label: 'Claude Code', detected: true, sources: ['/tmp/.claude.json'] },
        { id: 'claude-desktop', label: 'Claude Desktop', detected: false, sources: [] },
        { id: 'codex', label: 'Codex', detected: false, sources: [] },
      ],
      servers: [{
        id: 'secret-server', client: 'claude-code', clientLabel: 'Claude Code', name: 'private',
        transport: 'unknown', sourcePath: '/tmp/.claude.json', scope: 'user', command: 'private-mcp',
        args: [
          '--token', 'super-secret-value',
          '--password=another-secret',
          'API_SECRET=inline-secret',
          '--mode', 'read-only',
        ],
        env: { API_TOKEN: 'super-secret-value' }, envKeys: ['API_TOKEN'],
        headers: { Authorization: 'Bearer super-secret-value' }, headerKeys: ['Authorization'], enabled: true,
      }],
      warnings: [],
    };
    const result = await runAudit({ allowServerStarts: false, offline: true, discovery });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain('super-secret-value');
    expect(result.discovery.servers[0]!.env.API_TOKEN).toBe('[redacted]');
    expect(result.discovery.servers[0]!.headers.Authorization).toBe('[redacted]');
    expect(result.discovery.servers[0]!.args).toEqual([
      '--token', '[redacted]',
      '--password=[redacted]',
      'API_SECRET=[redacted]',
      '--mode', 'read-only',
    ]);
    expect(result.privacy.uploadedAuditData).toBe(false);
  });

  it('emits a standalone CSP-hardened report without remote assets or scripts', async () => {
    const result = await runAudit({ allowServerStarts: false, offline: true, demo: true });
    const html = renderHtmlReport(result);
    expect(html).toContain("Content-Security-Policy");
    expect(html).toContain("default-src 'none'");
    expect(html).not.toContain('<script');
    expect(html).not.toContain('src="http');
    expect(html).toContain('admin.execute');
    expect(html.toLowerCase()).toContain('no audit payload was uploaded');
    expect(html).toContain('Agent access, explained.');
    expect(html).toContain('Why this matters:');
    expect(html).toContain('Recommended control:');
    expect(html).toContain('MCP server:');
    expect(html).toContain('Classification coverage');
  });

  it('refuses to overwrite an explicitly named report', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'slaunt-report-test-'));
    const path = join(directory, 'report.html');
    await writeFile(path, 'keep me');
    const result = await runAudit({ allowServerStarts: false, offline: true, demo: true });
    await expect(writeHtmlReport(result, path)).rejects.toThrow('refusing to overwrite');
    expect(await readFile(path, 'utf8')).toBe('keep me');
  });
});
