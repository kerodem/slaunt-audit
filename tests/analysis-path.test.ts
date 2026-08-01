import { describe, expect, it } from 'vitest';
import { runAudit } from '../src/audit/run.js';
import { buildAnalysisPath, DEFAULT_INSPECTION_WINDOW_MS, playAnalysisPath } from '../src/tui/analysis-path.js';

describe('interactive analysis path', () => {
  it('turns real audit evidence into an adaptive search trail', async () => {
    const result = await runAudit({ allowServerStarts: false, demo: true });
    const beats = buildAnalysisPath(result);

    expect(beats.map((beat) => beat.active)).toEqual([
      'Discovering Claude and Codex MCP configurations',
      'Mapping MCP servers and transport types',
      'Retrieving tools/list inventories without calling tools',
      'Parsing 43 tool names, descriptions, and input schemas',
      'Classifying tools against the reviewed capability catalog',
      'Mapping sensitive capabilities to their MCP servers',
      'Tracing state-changing capabilities: write, execute, and deploy',
      'Checking direct production and administrative access',
      'Testing whether credential access can chain into shell execution',
      'Searching cross-server attack chains from combined permissions',
      'Comparing permissions across 2 agent clients',
      'Evaluating least privilege: only the access each agent needs',
      'Isolating unclassified tools for manual review',
      'Ranking findings by exploitability and blast radius',
    ]);
    expect(beats).toHaveLength(14);
    expect(beats.reduce((total, beat) => total + beat.delayMs, 0)).toBe(DEFAULT_INSPECTION_WINDOW_MS);
    expect(DEFAULT_INSPECTION_WINDOW_MS).toBeGreaterThanOrEqual(60_000);
    expect(DEFAULT_INSPECTION_WINDOW_MS).toBeLessThanOrEqual(120_000);
    expect(beats.at(-1)?.complete).toBe('3 high-risk · security posture 49/100 · 88% coverage');
    expect(beats.filter((beat) => beat.tone === 'warning')).toHaveLength(10);
  });

  it('paces the full guided inspection without delaying tests or automation', async () => {
    const result = await runAudit({ allowServerStarts: false, demo: true });
    const waits: number[] = [];

    await playAnalysisPath(result, {
      silent: true,
      sleep: async (milliseconds) => { waits.push(milliseconds); },
    });

    expect(waits).toHaveLength(28);
    expect(waits.reduce((total, milliseconds) => total + milliseconds, 0)).toBe(DEFAULT_INSPECTION_WINDOW_MS);
  });
});
