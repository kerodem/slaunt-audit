import { describe, expect, it } from 'vitest';
import { analyzeRisks, summarizeAudit } from '../src/audit/risk-engine.js';
import { classifyTools } from '../src/classification/classifier.js';
import { BUILTIN_CATALOG } from '../src/classification/builtin-catalog.js';
import { demoDiscovery, demoProbes } from '../src/demo.js';

describe('tool classification and correlation', () => {
  it('reproduces the 43-tool audit fixture with five unknown tools', () => {
    const discovery = demoDiscovery();
    const tools = classifyTools(demoProbes().flatMap((probe) => probe.tools), BUILTIN_CATALOG);
    const unknown = tools.filter((tool) => tool.classification.source === 'unknown').map((tool) => tool.name);

    expect(tools).toHaveLength(43);
    expect(tools.length - unknown.length).toBe(38);
    expect(unknown).toEqual([
      'trigger_job',
      'sync',
      'company_data.query',
      'internal.run_workflow',
      'admin.execute',
    ]);

    const findings = analyzeRisks(discovery.servers, tools);
    expect(findings.some((finding) => finding.severity === 'critical' && finding.toolNames.includes('deploy_service'))).toBe(true);
    expect(findings.some((finding) => finding.severity === 'high' && finding.title.includes('shell commands and access secrets'))).toBe(true);
    expect(findings.some((finding) => finding.severity === 'high' && finding.title.includes('share broad GitHub permissions'))).toBe(true);
    expect(summarizeAudit(2, 5, tools, findings).highRiskFindings).toBe(3);
  });

  it('treats database rules as higher priority than bundled heuristics', () => {
    const [tool] = demoProbes()[0]!.tools;
    expect(tool).toBeDefined();
    const classified = classifyTools([tool!], [{
      id: 'db:reviewed-list',
      namespace: 'github',
      toolPattern: 'list_repositories',
      category: 'Reviewed repository inventory',
      capabilities: ['read-data'],
      riskScore: 18,
      riskLevel: 'low',
      sensitive: false,
      verified: true,
      rationale: 'Reviewed exact match.',
      priority: 1_100,
    }, ...BUILTIN_CATALOG]);
    expect(classified[0]!.classification.category).toBe('Reviewed repository inventory');
    expect(classified[0]!.classification.source).toBe('database');
  });
});
