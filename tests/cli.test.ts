import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);

describe('built CLI', () => {
  it('reports the current package version', async () => {
    const { stdout } = await execFileAsync(process.execPath, ['dist/cli.js', '--version'], {
      cwd: process.cwd(), timeout: 10_000,
    });
    expect(stdout.trim()).toBe('0.1.1');
  });

  it('returns a redacted deterministic JSON audit', async () => {
    const { stdout } = await execFileAsync(process.execPath, [
      'dist/cli.js', 'audit', '--demo', '--json', '--no-report', '--no-install-slaunt', '--no-server-starts',
    ], { cwd: process.cwd(), timeout: 10_000 });
    const result = JSON.parse(stdout);
    expect(result.summary).toMatchObject({ clientsDetected: 2, servers: 5, tools: 43, classified: 38, unclassified: 5 });
    expect(result.privacy.uploadedAuditData).toBe(false);
  });
});
