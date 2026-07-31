import { describe, expect, it } from 'vitest';
import { runAudit } from '../src/audit/run.js';
import { renderAudit, renderHeader } from '../src/tui/render.js';

describe('terminal report', () => {
  it('uses a compact hierarchy with progressive disclosure', async () => {
    const result = await runAudit({ allowServerStarts: false, demo: true });
    result.reportPath = `${process.cwd()}/slaunt-audit-demo.html`;
    const output = `${renderHeader()}\n${renderAudit(result)}`;

    expect(output).toContain('SLAUNT · AI assistant safety check');
    expect(output).toContain('Safety check complete');
    expect(output).toContain('What needs your attention');
    expect(output).toContain('What each assistant can do');
    expect(output).toContain('Items Slaunt could not identify (5)');
    expect(output).toContain('Why this matters:');
    expect(output).toContain('What you can do:');
    expect(output).toContain('Claude Code can publish changes to a live service without approval');
    expect(output).toContain('./slaunt-audit-demo.html');
    expect(output).not.toContain('Why flagged:');
    expect(output).not.toContain('Recommendation:');
    expect(output).not.toContain('posture');
    expect(output).not.toContain('sensitive capabilities');
    expect(output).not.toContain('MCP');
    expect(output).not.toContain('unclassified');
    expect(output).not.toContain('4 unclassified tools appear state-changing');
    expect(output.split('\n').length).toBeLessThan(75);
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
    expect(output).toContain('Safety score unavailable · some services could not be fully checked');
    expect(output).toContain('Some services could not be checked, so this result is incomplete.');
    expect(output).not.toContain('100/100 safety score · Looks good');
  });
});
