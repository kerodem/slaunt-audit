import { describe, expect, it } from 'vitest';
import { runAudit } from '../src/audit/run.js';
import { buildAnalysisPath, DEFAULT_INSPECTION_WINDOW_MS, playAnalysisPath } from '../src/tui/analysis-path.js';

describe('interactive analysis path', () => {
  it('turns real audit evidence into an adaptive search trail', async () => {
    const result = await runAudit({ allowServerStarts: false, demo: true });
    const beats = buildAnalysisPath(result);

    expect(beats.map((beat) => beat.active)).toEqual([
      'Finding Claude and Codex settings on this computer',
      'Listing the services each assistant can reach',
      'Checking what each connected service allows',
      'Reading the names and descriptions of 43 available actions',
      'Matching each action to the kind of access it provides',
      'Finding access to sensitive information and important changes',
      'Checking which actions can change data or run commands',
      'Looking for direct access to live systems or administrator controls',
      'Checking whether credentials and command access can be combined',
      'Looking for permissions that become riskier when combined',
      'Comparing what each of the 2 AI assistants can do',
      'Checking whether each assistant has only the access it needs',
      'Setting aside unfamiliar actions for a person to review',
      'Putting the most urgent issues first',
    ]);
    expect(beats).toHaveLength(14);
    expect(beats.reduce((total, beat) => total + beat.delayMs, 0)).toBe(DEFAULT_INSPECTION_WINDOW_MS);
    expect(DEFAULT_INSPECTION_WINDOW_MS).toBeGreaterThanOrEqual(60_000);
    expect(DEFAULT_INSPECTION_WINDOW_MS).toBeLessThanOrEqual(120_000);
    expect(beats.at(-1)?.complete).toBe('3 urgent issues · safety score 49/100 · 88% understood');
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
