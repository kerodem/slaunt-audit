import { describe, expect, it } from 'vitest';
import { runAudit } from '../src/audit/run.js';
import { renderAudit, renderHeader } from '../src/tui/render.js';

describe('terminal report', () => {
  it('uses a compact hierarchy with progressive disclosure', async () => {
    const result = await runAudit({ allowServerStarts: false, demo: true });
    result.reportPath = `${process.cwd()}/slaunt-audit-demo.html`;
    const output = `${renderHeader()}\n${renderAudit(result)}`;

    expect(output).toContain('SLAUNT · MCP agent access audit');
    expect(output).toContain('Audit complete');
    expect(output).toContain('High-priority findings');
    expect(output).toContain('Access overview');
    expect(output).toContain('Unclassified tools (5)');
    expect(output).toContain('Why this matters:');
    expect(output).toContain('Recommended control:');
    expect(output).toContain('Claude Code can deploy to production without an approval boundary');
    expect(output).toContain('Agent client: Claude Code');
    expect(output).toContain('MCP server: railway');
    expect(output).toContain('Capability: Trigger production deployments');
    expect(output).toContain('Agent clients are the AI applications being audited.');
    expect(output).toContain('./slaunt-audit-demo.html');
    expect(output).not.toContain('Why flagged:');
    expect(output).not.toContain('Recommendation:');
    expect(output).toContain('security posture');
    expect(output).toContain('Capabilities describe what each MCP server allows an agent to do.');
    expect(output).not.toContain('4 unclassified tools appear state-changing');
    expect(output.split('\n').length).toBeLessThan(90);
    expect(Math.max(...output.split('\n').map((line) => line.length))).toBeLessThanOrEqual(82);
  });

  it('never presents missing tool inventories as a strong posture', async () => {
    const result = await runAudit({ allowServerStarts: false, demo: true });
    result.tools = [];
    result.findings = [];
    result.probes = result.probes.map((probe) => ({
      ...probe, status: 'skipped', tools: [], message: 'Local server start was not approved',
    }));
    result.summary = {
      ...result.summary,
      tools: 0,
      classified: 0,
      sensitiveCapabilities: 0,
      highRiskFindings: 0,
      unclassified: 0,
      postureScore: 100,
    };

    const output = renderAudit(result);
    expect(output).toContain('Security posture unavailable · tool inventories are incomplete');
    expect(output).toContain('Missing inventories prevent a complete assessment.');
    expect(output).not.toContain('100/100 security posture · Strong');
  });
});
