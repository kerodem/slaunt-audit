import { describe, expect, it } from 'vitest';
import { runAudit } from '../src/audit/run.js';
import { buildAnalysisPath } from '../src/tui/analysis-path.js';

describe('interactive analysis path', () => {
  it('turns real audit evidence into an adaptive search trail', async () => {
    const result = await runAudit({ allowServerStarts: false, demo: true });
    const beats = buildAnalysisPath(result);

    expect(beats.map((beat) => beat.active)).toEqual([
      'Indexing 43 declared tools across detected clients',
      'Building the client → server → capability graph',
      'Searching for direct production-changing access',
      'Testing whether permissions can be chained across servers',
      'Comparing permission overlap between agent clients',
      'Checking classification confidence and unknown tools',
      'Ranking evidence by exploitability and blast radius',
    ]);
    expect(beats.map((beat) => beat.complete)).toEqual([
      'Indexed 43 tools from 5 MCP servers',
      'Mapped 31 sensitive capabilities across 2 clients',
      '1 critical direct-access path found',
      '1 cross-server capability chain found',
      'Permission overlap contributes to 2 findings',
      '5 tools need human classification',
      '3 high-risk findings prioritized for review',
    ]);
    expect(beats.map((beat) => beat.tone)).toEqual([
      'success', 'success', 'warning', 'warning', 'warning', 'warning', 'warning',
    ]);
  });
});
