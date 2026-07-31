import { describe, expect, it } from 'vitest';
import { runAudit } from '../src/audit/run.js';
import { buildAnalysisPath } from '../src/tui/analysis-path.js';

describe('interactive analysis path', () => {
  it('turns real audit evidence into an adaptive search trail', async () => {
    const result = await runAudit({ allowServerStarts: false, demo: true });
    const beats = buildAnalysisPath(result);

    expect(beats.map((beat) => beat.active)).toEqual([
      'Indexing 43 tools from 5 MCP servers',
      'Searching direct and chained privilege paths',
      'Comparing permissions across 2 agent clients',
      'Prioritizing findings by exploitability and blast radius',
    ]);
    expect(beats.map((beat) => beat.complete)).toEqual([
      'Indexed 43 tools from 5 MCP servers',
      '1 direct · 1 chained',
      'Permission overlap contributes to 2 findings',
      '3 high-risk · 5 unclassified',
    ]);
    expect(beats.map((beat) => beat.tone)).toEqual([
      'success', 'warning', 'warning', 'warning',
    ]);
  });
});
