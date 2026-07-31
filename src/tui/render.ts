import chalk from 'chalk';
import type { AuditResult, Capability, Finding, Severity } from '../types.js';

const capabilityLabels: Record<Capability, string> = {
  'read-data': 'Read data', 'write-data': 'Write data', 'read-files': 'Read files',
  'write-files': 'Write files', 'delete-data': 'Delete data', 'execute-code': 'Execute code',
  'execute-shell': 'Execute commands', 'read-secrets': 'Read credentials', 'manage-auth': 'Manage identity',
  'network-access': 'Network access', 'deploy-production': 'View and deploy', 'edit-code': 'Edit code',
  'create-pull-request': 'Create pull requests', 'merge-pull-request': 'Merge pull requests',
  'administer-system': 'Administer systems', 'control-browser': 'Control browser', 'send-message': 'Send messages',
};

const severityColor: Record<Severity, (value: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.hex('#ff8a4c').bold,
  medium: chalk.yellow.bold,
  low: chalk.cyan.bold,
  info: chalk.gray,
};

function width(): number {
  return Math.max(54, Math.min(76, process.stdout.columns || 76));
}

function divider(character = '─'): string {
  return chalk.gray(character.repeat(width()));
}

function row(label: string, value: number): string {
  const valueText = String(value);
  return `${label}${' '.repeat(Math.max(2, width() - label.length - valueText.length))}${chalk.bold(valueText)}`;
}

function findingBlock(item: Finding): string {
  const lines = [
    severityColor[item.severity](item.severity.toUpperCase()),
    chalk.bold(item.title),
  ];
  if (item.serverNames.length) lines.push('', `  ${chalk.gray(item.serverNames.length > 1 ? 'Servers:' : 'Server:')} ${item.serverNames.join(', ')}`);
  if (item.toolNames.length === 1) lines.push(`  ${chalk.gray('Tool:')} ${item.toolNames[0]}`);
  if (item.access.length) {
    lines.push(`  ${chalk.gray('Access:')}`);
    for (const access of item.access) lines.push(`  ${chalk.hex('#a78bfa')('•')} ${access}`);
  }
  lines.push('', `  ${chalk.gray('Why flagged:')} ${item.why}`, `  ${chalk.gray('Recommendation:')} ${item.recommendation}`);
  return lines.join('\n');
}

function accessOverview(result: AuditResult): string {
  const blocks: string[] = [];
  for (const client of result.discovery.clients.filter((item) => item.detected)) {
    blocks.push(chalk.bold(client.label));
    for (const server of result.discovery.servers.filter((item) => item.client === client.id)) {
      const capabilities = [...new Set(result.tools
        .filter((tool) => tool.serverId === server.id)
        .flatMap((tool) => tool.classification.capabilities))];
      const label = server.name.slice(0, 16).padEnd(16);
      blocks.push(`  ${chalk.hex('#c4b5fd')(label)}${capabilities.length ? capabilities.slice(0, 4).map((item) => capabilityLabels[item]).join(', ') : chalk.gray('Tool list unavailable')}`);
    }
    blocks.push('');
  }
  return blocks.join('\n').trimEnd();
}

function postureBar(score: number): string {
  const slots = 20;
  const filled = Math.round(score / 100 * slots);
  const color = score >= 80 ? chalk.green : score >= 55 ? chalk.yellow : chalk.red;
  return `${color('█'.repeat(filled))}${chalk.gray('░'.repeat(slots - filled))} ${chalk.bold(String(score))}/100`;
}

export function renderAudit(result: AuditResult): string {
  const summary = result.summary;
  const unknown = result.tools.filter((tool) => tool.classification.source === 'unknown');
  const failedProbes = result.probes.filter((probe) => probe.status !== 'ok');
  const lines: string[] = [
    '',
    chalk.bold('Slaunt Agent Access Audit'),
    chalk.gray('Inspecting MCP configurations locally. No audit payload uploaded.'),
    '',
    `${chalk.green('✓')} Found ${summary.clientsDetected} agent client${summary.clientsDetected === 1 ? '' : 's'}`,
    `${chalk.green('✓')} Found ${summary.servers} MCP server${summary.servers === 1 ? '' : 's'}`,
    `${chalk.green('✓')} Retrieved ${summary.tools} tool definition${summary.tools === 1 ? '' : 's'}`,
    `${chalk.green('✓')} Classified ${summary.classified} tool${summary.classified === 1 ? '' : 's'}`,
    summary.unclassified > 0
      ? `${chalk.yellow('!')} ${summary.unclassified} tool${summary.unclassified === 1 ? '' : 's'} require review`
      : `${chalk.green('✓')} Every retrieved tool is recognized`,
    '',
    divider(),
    '',
    chalk.bold('Audit summary'),
    '',
    row('Clients detected', summary.clientsDetected),
    row('MCP servers', summary.servers),
    row('Tools exposed', summary.tools),
    row('Sensitive capabilities', summary.sensitiveCapabilities),
    row('High-risk findings', summary.highRiskFindings),
    row('Unclassified tools', summary.unclassified),
    '',
    `${'Security posture'.padEnd(22)}${postureBar(summary.postureScore)}`,
    '',
    divider(),
    '',
    chalk.bold('Needs attention'),
    '',
    result.findings.length ? result.findings.map(findingBlock).join(`\n\n${chalk.gray('·'.repeat(20))}\n\n`) : chalk.green('No correlated high-risk paths were identified.'),
    '',
    divider(),
    '',
    chalk.bold('Access overview'),
    '',
    accessOverview(result) || chalk.gray('No MCP access was discovered.'),
    '',
    divider(),
    '',
    chalk.bold('Classification coverage'),
    '',
    `${summary.classified} verified or recognized`,
    `${String(summary.unclassified).padStart(String(summary.classified).length)} unknown`,
  ];

  if (unknown.length) {
    lines.push('', 'Unknown tools:', ...unknown.map((tool) => `  ${chalk.yellow('•')} ${tool.name}`), '', chalk.gray('Unknown tools are treated as potentially sensitive until reviewed.'));
  }

  if (failedProbes.length) {
    lines.push('', chalk.bold('Unavailable tool inventories'), '', ...failedProbes.map((probe) => {
      const server = result.discovery.servers.find((item) => item.id === probe.serverId);
      return `  ${chalk.yellow('!')} ${server?.clientLabel || 'Client'} / ${server?.name || probe.serverId}: ${probe.message || probe.status}`;
    }));
  }

  lines.push(
    '',
    divider(),
    '',
    chalk.bold('Audit scope'),
    '',
    'This audit inspected configured MCP servers and their declared tools.',
    'It did not call tools or inspect prompts, files, credentials, or non-MCP agents.',
    'It did not determine whether any exposed tool has actually been used.',
    '',
    chalk.bgHex('#5b21b6').white.bold('  MAP COMPLETE  '),
    '',
    chalk.bold('You found the paths. Put guardrails on them.'),
    `Slaunt can add approvals, role-scoped access, continuous monitoring, and`,
    `remote shutdown around the MCP stack you already use. ${chalk.bold('You choose when to connect.')}`,
    '',
    `${chalk.hex('#a78bfa')('Create your Slaunt workspace →')} ${chalk.underline('https://slaunt.ai/setup')}`,
  );

  if (result.discovery.warnings.length) {
    lines.push('', chalk.gray(`Notes: ${result.discovery.warnings.join(' · ')}`));
  }
  return lines.join('\n');
}

export function renderHeader(): string {
  return `\n${chalk.bold.hex('#a78bfa')('SLAUNT')} ${chalk.bold('agent access audit')}\n${chalk.gray('Local-first MCP exposure mapping')}`;
}
