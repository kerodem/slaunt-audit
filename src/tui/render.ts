import { relative } from 'node:path';
import chalk from 'chalk';
import type { AuditResult, Capability, Finding, Severity } from '../types.js';
import { plainCapability, plainClient, plainFinding } from '../presentation/plain-language.js';

const severityColor: Record<Severity, (value: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.hex('#f59e0b').bold,
  medium: chalk.yellow,
  low: chalk.cyan,
  info: chalk.gray,
};

const capabilityPriority: Capability[] = [
  'deploy-production', 'execute-shell', 'read-secrets', 'administer-system',
  'merge-pull-request', 'edit-code', 'write-files', 'delete-data', 'write-data',
  'read-files', 'manage-auth', 'control-browser', 'send-message', 'network-access',
  'create-pull-request', 'execute-code', 'read-data',
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
  if (score >= 80) return { color: chalk.green, label: 'Looks good' };
  if (score >= 55) return { color: chalk.yellow, label: 'Review recommended' };
  return { color: chalk.red, label: 'Needs attention' };
}

function postureLine(result: AuditResult, unavailable: number): string {
  const { summary } = result;
  if (summary.tools === 0 && unavailable > 0) {
    return `${chalk.yellow.bold('Safety score unavailable')} ${chalk.gray('· some services could not be fully checked')}`;
  }
  const score = scoreLabel(summary.postureScore);
  const suffix = unavailable > 0 ? 'Some services could not be fully checked' : score.label;
  return `${score.color(chalk.bold(`${summary.postureScore}/100 safety score`))} ${chalk.gray(`· ${suffix}`)}`;
}

function naturalList(values: string[]): string {
  if (values.length <= 1) return values[0] || '';
  if (values.length === 2) return `${values[0]} and ${values[1]}`;
  return `${values.slice(0, -1).join(', ')}, and ${values.at(-1)}`;
}

function findingLines(item: Finding): string[] {
  const icon = item.severity === 'critical' ? '◆' : '▲';
  const color = severityColor[item.severity];
  const copy = plainFinding(item);
  const assistants = naturalList(item.clients.map(plainClient));
  const services = naturalList(item.serverNames);
  const where = [assistants, services].filter(Boolean).join(' → ');
  const actionLabel = item.toolNames.length === 1 ? 'Action name' : 'Action names';
  return [
    '',
    ...wrap(`${icon} ${copy.label.toUpperCase()}  ${copy.title}`),
    ...(where ? wrap(`Where: ${where}`, '  ').map((line) => chalk.gray(line)) : []),
    ...(item.toolNames.length ? wrap(`${actionLabel}: ${item.toolNames.join(', ')}`, '  ').map((line) => chalk.gray(line)) : []),
    ...wrap(`Why this matters: ${copy.why}`, '  '),
    ...wrap(`What you can do: ${copy.recommendation}`, '  ').map((line) => color(line)),
  ];
}

function shortCapabilities(capabilities: Capability[]): string {
  const set = new Set(capabilities);
  const labels = capabilityPriority
    .filter((capability) => set.has(capability))
    .map(plainCapability);
  return [...new Set(labels)].slice(0, 3).join(', ') || 'Permissions could not be read';
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
      lines.push(chalk.gray('  No connected services found'));
      continue;
    }
    for (const server of servers.slice(0, 6)) {
      const capabilities = [...new Set(result.tools
        .filter((tool) => tool.serverId === server.id)
        .flatMap((tool) => tool.classification.capabilities))];
      const name = server.name.slice(0, 14).padEnd(14);
      lines.push(`  ${chalk.hex('#a78bfa')(name)}${shortCapabilities(capabilities)}`);
    }
    if (servers.length > 6) lines.push(chalk.gray(`  + ${servers.length - 6} more in the detailed report`));
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
    chalk.bold('Safety check complete'),
    postureLine(result, failedProbes.length),
    '',
    `${chalk.bold(String(summary.clientsDetected))} AI ${plural(summary.clientsDetected, 'assistant')} checked  ${chalk.gray('·')}  ${chalk.bold(String(summary.servers))} connected ${plural(summary.servers, 'service')}`,
    `${chalk.bold(String(summary.tools))} available ${plural(summary.tools, 'action')} reviewed`,
    `${chalk.bold(String(summary.sensitiveCapabilities))} can access sensitive information or make changes  ${chalk.gray('·')}  ${chalk.bold(String(summary.unclassified))} need a closer look`,
    ...section('What needs your attention'),
  ];

  if (priority.length) {
    for (const finding of priority.slice(0, 3)) lines.push(...findingLines(finding));
  } else if (failedProbes.length > 0) {
    lines.push('', chalk.yellow('No urgent issues were found in the permissions Slaunt could read.'), chalk.gray('Some services could not be checked, so this result is incomplete.'));
  } else {
    lines.push('', chalk.green('✓ No urgent or high-priority access issues found.'));
  }

  if (otherFindings > 0) {
    lines.push('', chalk.gray(`${otherFindings} lower-priority ${plural(otherFindings, 'item')} saved in the detailed report.`));
  }

  lines.push(...section('What each assistant can do'), ...accessLines(result));

  if (unknown.length) {
    const visibleUnknown = unknown.slice(0, 8);
    lines.push(
      ...section(`Items Slaunt could not identify (${unknown.length})`),
      '',
      ...wrap(visibleUnknown.map((tool) => tool.name).join('  ·  '), '  '),
      ...(unknown.length > visibleUnknown.length
        ? [chalk.gray(`  + ${unknown.length - visibleUnknown.length} more in the detailed report`)]
        : []),
      ...wrap('These action names are not in Slaunt\'s reviewed guide yet. Until a person checks them, Slaunt treats them as possibly sensitive.', '  ').map((line) => chalk.gray(line)),
    );
  }

  if (failedProbes.length) {
    lines.push(...section(`Services that could not be fully checked (${failedProbes.length})`));
    for (const probe of failedProbes.slice(0, 4)) {
      const server = result.discovery.servers.find((item) => item.id === probe.serverId);
      lines.push(...wrap(`${server?.clientLabel || 'Client'} / ${server?.name || probe.serverId}: ${probe.message || probe.status}`, '  '));
    }
    if (failedProbes.length > 4) lines.push(chalk.gray(`  + ${failedProbes.length - 4} more in the detailed report`));
  }

  lines.push(
    ...section('Your detailed report'),
    ...(result.reportPath ? ['', chalk.cyan(reportPath(result.reportPath))] : ['', chalk.gray('No detailed report was saved for this run.')]),
    '',
    ...wrap('What this check covered: Slaunt reviewed the actions advertised by connected services. It did not use those actions or read your prompts, files, or credentials.').map((line) => chalk.gray(line)),
    ...section('Want ongoing protection?'),
    '',
    ...wrap('Add approval prompts and give each assistant only the access it needs:'),
    chalk.cyan.underline('https://slaunt.ai/setup'),
  );

  if (result.discovery.warnings.length) {
    lines.push(...section('Other notes'));
    for (const warning of result.discovery.warnings.slice(0, 3)) lines.push(...wrap(warning, '  ').map((line) => chalk.gray(line)));
    if (result.discovery.warnings.length > 3) lines.push(chalk.gray(`  + ${result.discovery.warnings.length - 3} more in the full report`));
  }

  return lines.join('\n');
}

export function renderHeader(): string {
  return `${chalk.bold.hex('#a78bfa')('SLAUNT')} ${chalk.gray('· AI assistant safety check')}\n${chalk.gray('Checks access on this computer · nothing from this check is uploaded')}`;
}
