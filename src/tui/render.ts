import { relative } from 'node:path';
import chalk from 'chalk';
import type { AuditResult, Capability, Finding, Severity } from '../types.js';

const severityColor: Record<Severity, (value: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.hex('#f59e0b').bold,
  medium: chalk.yellow,
  low: chalk.cyan,
  info: chalk.gray,
};

const capabilityPriority: Array<[Capability, string]> = [
  ['deploy-production', 'deploy'],
  ['execute-shell', 'execute'],
  ['read-secrets', 'credentials'],
  ['administer-system', 'admin'],
  ['merge-pull-request', 'merge'],
  ['edit-code', 'edit'],
  ['write-files', 'file write'],
  ['delete-data', 'delete'],
  ['write-data', 'write'],
  ['read-files', 'file read'],
  ['manage-auth', 'identity'],
  ['control-browser', 'browser'],
  ['send-message', 'message'],
  ['network-access', 'network'],
  ['create-pull-request', 'pull requests'],
  ['execute-code', 'code'],
  ['read-data', 'read'],
];

function width(): number {
  return Math.max(36, Math.min(82, process.stdout.columns || 78));
}

function plural(value: number, singular: string, pluralForm = `${singular}s`): string {
  return value === 1 ? singular : pluralForm;
}

function wrap(text: string, indent = '', continuationIndent = indent): string[] {
  const firstWidth = Math.max(12, width() - indent.length);
  const continuationWidth = Math.max(12, width() - continuationIndent.length);
  const words = text.trim().split(/\s+/);
  const lines: string[] = [];
  let line = '';
  let available = firstWidth;

  for (const word of words) {
    if (line && line.length + 1 + word.length > available) {
      lines.push(`${lines.length === 0 ? indent : continuationIndent}${line}`);
      line = word;
      available = continuationWidth;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(`${lines.length === 0 ? indent : continuationIndent}${line}`);
  return lines;
}

function section(title: string): string[] {
  return ['', chalk.bold(title)];
}

function scoreLabel(score: number): { color: (value: string) => string; label: string } {
  if (score >= 80) return { color: chalk.green, label: 'strong' };
  if (score >= 55) return { color: chalk.yellow, label: 'review' };
  return { color: chalk.red, label: 'needs attention' };
}

function postureLine(result: AuditResult, unavailable: number): string {
  const { summary } = result;
  if (summary.tools === 0 && unavailable > 0) {
    return `${chalk.yellow.bold('Posture unavailable')} ${chalk.gray('· tool inventories incomplete')}`;
  }
  const score = scoreLabel(summary.postureScore);
  const suffix = unavailable > 0 ? 'partial coverage' : score.label;
  return `${score.color(chalk.bold(`${summary.postureScore}/100`))} posture ${chalk.gray(`· ${suffix}`)}`;
}

function findingLines(item: Finding): string[] {
  const icon = item.severity === 'critical' ? '◆' : '▲';
  const color = severityColor[item.severity];
  const context = [item.serverNames.join(', '), item.toolNames.length === 1 ? item.toolNames[0] : undefined]
    .filter(Boolean)
    .join(' · ');
  return [
    '',
    ...wrap(`${icon} ${item.severity.toUpperCase()}  ${item.title}`),
    ...(context ? wrap(context, '  ').map((line) => chalk.gray(line)) : []),
    ...wrap(item.why, '  '),
    ...wrap(`Fix: ${item.recommendation}`, '  ').map((line) => color(line)),
  ];
}

function shortCapabilities(capabilities: Capability[]): string {
  const set = new Set(capabilities);
  const labels = capabilityPriority
    .filter(([capability]) => set.has(capability))
    .map(([, label]) => label);
  return [...new Set(labels)].slice(0, 3).join(' · ') || 'inventory unavailable';
}

function accessLines(result: AuditResult): string[] {
  const lines: string[] = [];
  for (const client of result.discovery.clients.filter((item) => item.detected)) {
    lines.push('', chalk.bold(client.label));
    const highestRisk = (serverId: string): number => Math.max(0, ...result.tools
      .filter((tool) => tool.serverId === serverId)
      .map((tool) => tool.classification.riskScore));
    const servers = result.discovery.servers
      .filter((item) => item.client === client.id)
      .sort((left, right) => highestRisk(right.id) - highestRisk(left.id));
    if (servers.length === 0) {
      lines.push(chalk.gray('  No enabled MCP servers'));
      continue;
    }
    for (const server of servers.slice(0, 6)) {
      const capabilities = [...new Set(result.tools
        .filter((tool) => tool.serverId === server.id)
        .flatMap((tool) => tool.classification.capabilities))];
      const name = server.name.slice(0, 14).padEnd(14);
      lines.push(`  ${chalk.hex('#a78bfa')(name)}${shortCapabilities(capabilities)}`);
    }
    if (servers.length > 6) lines.push(chalk.gray(`  + ${servers.length - 6} more in the full report`));
  }
  return lines;
}

function reportPath(path: string): string {
  const local = relative(process.cwd(), path);
  return local && !local.startsWith('..') ? `./${local}` : path;
}

export function renderAudit(result: AuditResult): string {
  const { summary } = result;
  const priority = result.findings.filter((finding) => finding.severity === 'critical' || finding.severity === 'high');
  const otherFindings = result.findings.length - priority.length;
  const unknown = result.tools.filter((tool) => tool.classification.source === 'unknown');
  const failedProbes = result.probes.filter((probe) => probe.status !== 'ok');
  const lines: string[] = [
    '',
    chalk.bold('Audit complete'),
    postureLine(result, failedProbes.length),
    '',
    `${chalk.bold(String(summary.clientsDetected))} ${plural(summary.clientsDetected, 'client')}  ${chalk.gray('·')}  ${chalk.bold(String(summary.servers))} ${plural(summary.servers, 'server')}  ${chalk.gray('·')}  ${chalk.bold(String(summary.tools))} ${plural(summary.tools, 'tool')}`,
    `${chalk.bold(String(summary.sensitiveCapabilities))} sensitive capabilities  ${chalk.gray('·')}  ${chalk.bold(String(summary.unclassified))} unclassified`,
    ...section('Priority findings'),
  ];

  if (priority.length) {
    for (const finding of priority.slice(0, 3)) lines.push(...findingLines(finding));
  } else if (failedProbes.length > 0) {
    lines.push('', chalk.yellow('No high-risk paths found in the retrieved inventories.'), chalk.gray('Missing inventories prevent a complete assessment.'));
  } else {
    lines.push('', chalk.green('✓ No critical or high-risk access paths found.'));
  }

  if (otherFindings > 0) {
    lines.push('', chalk.gray(`${otherFindings} additional ${plural(otherFindings, 'finding')} included in the full report.`));
  }

  lines.push(...section('Access by client'), ...accessLines(result));

  if (unknown.length) {
    const visibleUnknown = unknown.slice(0, 8);
    lines.push(
      ...section(`Unclassified tools (${unknown.length})`),
      '',
      ...wrap(visibleUnknown.map((tool) => tool.name).join('  ·  '), '  '),
      ...(unknown.length > visibleUnknown.length
        ? [chalk.gray(`  + ${unknown.length - visibleUnknown.length} more in the full report`)]
        : []),
      ...wrap('Treated as potentially sensitive until reviewed.', '  ').map((line) => chalk.gray(line)),
    );
  }

  if (failedProbes.length) {
    lines.push(...section(`Tool inventories unavailable (${failedProbes.length})`));
    for (const probe of failedProbes.slice(0, 4)) {
      const server = result.discovery.servers.find((item) => item.id === probe.serverId);
      lines.push(...wrap(`${server?.clientLabel || 'Client'} / ${server?.name || probe.serverId}: ${probe.message || probe.status}`, '  '));
    }
    if (failedProbes.length > 4) lines.push(chalk.gray(`  + ${failedProbes.length - 4} more in the full report`));
  }

  lines.push(
    ...section('Saved locally'),
    ...(result.reportPath ? ['', chalk.cyan(reportPath(result.reportPath))] : ['', chalk.gray('HTML report disabled for this run.')]),
    '',
    ...wrap('Scope: declared MCP tools only. No tools called, prompts analyzed, files read, or credentials inspected.').map((line) => chalk.gray(line)),
    ...section('Optional next step'),
    '',
    ...wrap('Add approvals and role-scoped access when you are ready:'),
    chalk.cyan.underline('https://slaunt.ai/setup'),
  );

  if (result.discovery.warnings.length) {
    lines.push(...section('Notes'));
    for (const warning of result.discovery.warnings.slice(0, 3)) lines.push(...wrap(warning, '  ').map((line) => chalk.gray(line)));
    if (result.discovery.warnings.length > 3) lines.push(chalk.gray(`  + ${result.discovery.warnings.length - 3} more in the full report`));
  }

  return lines.join('\n');
}

export function renderHeader(): string {
  return `${chalk.bold.hex('#a78bfa')('SLAUNT')} ${chalk.gray('· agent access audit')}\n${chalk.gray('Local analysis · no audit payload uploaded')}`;
}
