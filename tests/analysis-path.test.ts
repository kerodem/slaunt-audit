import { describe, expect, it } from 'vitest';
import { runAudit } from '../src/audit/run.js';
import { buildAnalysisPath, DEFAULT_INSPECTION_WINDOW_MS, playAnalysisPath } from '../src/tui/analysis-path.js';

describe('interactive analysis path', () => {
  it('turns real audit evidence into an adaptive search trail', async () => {
    const result = await runAudit({ allowServerStarts: false, demo: true });
    const beats = buildAnalysisPath(result);

    expect(beats.map((beat) => beat.active)).toEqual([
      'Mapping Claude and Codex configuration boundaries',
      'Normalizing MCP server identities and transports',
      'Verifying declared tool inventories without invoking tools',
      'Fingerprinting 43 tool names, descriptions, and schemas',
      'Semantically matching tool intent against trusted classifications',
      'Mapping sensitive capabilities to their owning servers',
      'Tracing state-changing write, execution, and deployment surfaces',
      'Checking for direct production and administrative authority',
      'Testing credential access against command-execution reachability',
      'Searching cross-server paths that amplify agent authority',
      'Comparing permissions across 2 agent clients',
      'Testing least-privilege separation between agent roles',
      'Isolating ambiguous tools for conservative review',
      'Ranking exploitability, blast radius, and classification confidence',
    ]);
    expect(beats).toHaveLength(14);
    expect(beats.reduce((total, beat) => total + beat.delayMs, 0)).toBe(DEFAULT_INSPECTION_WINDOW_MS);
    expect(DEFAULT_INSPECTION_WINDOW_MS).toBeGreaterThanOrEqual(60_000);
    expect(DEFAULT_INSPECTION_WINDOW_MS).toBeLessThanOrEqual(120_000);
    expect(beats.at(-1)?.complete).toBe('3 high-risk · posture 49/100 · coverage 88%');
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
