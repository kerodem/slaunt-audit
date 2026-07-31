import type { ClassificationRule, ClassifiedTool, DeclaredTool } from '../types.js';

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

function globMatches(pattern: string, value: string): boolean {
  const normalizedPattern = pattern.toLowerCase().replace(/[^a-z0-9*]+/g, '_').replace(/^_+|_+$/g, '');
  const escaped = normalizedPattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replaceAll('*', '.*');
  return new RegExp(`^${escaped}$`, 'u').test(normalize(value));
}

function ruleScore(rule: ClassificationRule, tool: DeclaredTool): number | undefined {
  if (!globMatches(rule.toolPattern, tool.name)) return undefined;
  if (rule.namespace && !globMatches(rule.namespace, tool.serverName)) return undefined;
  const description = normalize(tool.description);
  const terms = rule.descriptionTerms || [];
  const matches = terms.filter((term) => description.includes(normalize(term))).length;
  if (terms.length > 0 && matches === 0) return undefined;
  const specificity = rule.toolPattern.replaceAll('*', '').length + (rule.namespace?.replaceAll('*', '').length || 0);
  return rule.priority * 10_000 + specificity * 10 + matches;
}

export function classifyTools(tools: DeclaredTool[], rules: ClassificationRule[]): ClassifiedTool[] {
  return tools.map((tool) => {
    let selected: ClassificationRule | undefined;
    let selectedScore = -1;
    for (const rule of rules) {
      const score = ruleScore(rule, tool);
      if (score !== undefined && score > selectedScore) {
        selected = rule;
        selectedScore = score;
      }
    }

    if (!selected) {
      return {
        ...tool,
        classification: {
          category: 'Unknown',
          capabilities: [],
          riskScore: 50,
          riskLevel: 'medium',
          sensitive: true,
          verified: false,
          rationale: 'No trusted classification rule matched this declared tool.',
          source: 'unknown',
        },
      };
    }

    return {
      ...tool,
      classification: {
        ruleId: selected.id,
        category: selected.category,
        capabilities: selected.capabilities,
        riskScore: selected.riskScore,
        riskLevel: selected.riskLevel,
        sensitive: selected.sensitive,
        verified: selected.verified,
        rationale: selected.rationale,
        source: selected.id.startsWith('db:') ? 'database' : selected.verified ? 'built-in' : 'heuristic',
      },
    };
  });
}
