import chalk from 'chalk';
import ora from 'ora';
import type { AuditResult, Capability } from '../types.js';

export type AnalysisBeatTone = 'success' | 'warning';

export interface AnalysisBeat {
  active: string;
  complete: string;
  delayMs: number;
  tone: AnalysisBeatTone;
}

export interface PlayAnalysisPathOptions {
  durationMs?: number;
  silent?: boolean;
  sleep?: (milliseconds: number) => Promise<void>;
}

export const DEFAULT_INSPECTION_WINDOW_MS = 78_000;

const wait = (milliseconds: number): Promise<void> => new Promise((resolve) => {
  setTimeout(resolve, milliseconds);
});

function plural(value: number, singular: string, pluralForm = `${singular}s`): string {
  return value === 1 ? singular : pluralForm;
}

function formatRemaining(milliseconds: number): string {
  const seconds = Math.max(0, Math.ceil(milliseconds / 1_000));
  if (seconds < 60) return `~${seconds}s left`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return `~${minutes}m ${remainder}s left`;
}

function hasAnyCapability(capabilities: Capability[], expected: Set<Capability>): boolean {
  return capabilities.some((capability) => expected.has(capability));
}

export function buildAnalysisPath(result: AuditResult): AnalysisBeat[] {
  const { summary } = result;
  const criticalPaths = result.findings.filter((finding) => finding.severity === 'critical').length;
  const crossServerChains = result.findings.filter((finding) => finding.serverNames.length > 1).length;
  const sharedPermissionFindings = result.findings.filter((finding) => finding.clients.length > 1).length;
  const successfulInventories = result.probes.filter((probe) => probe.status === 'ok').length;
  const unavailableInventories = result.probes.filter((probe) => probe.status !== 'ok').length;
  const transportKinds = new Set(result.discovery.servers.map((server) => server.transport)).size;
  const configSources = new Set(result.discovery.clients.flatMap((client) => client.sources)).size;
  const schemaBackedTools = result.tools.filter((tool) => tool.inputSchema && Object.keys(tool.inputSchema).length > 0).length;
  const sensitiveServers = new Set(result.tools
    .filter((tool) => tool.classification.sensitive)
    .map((tool) => `${tool.client}:${tool.serverName}`)).size;
  const stateChangingCapabilities = new Set<Capability>([
    'write-data', 'write-files', 'delete-data', 'execute-code', 'execute-shell',
    'deploy-production', 'edit-code', 'merge-pull-request', 'administer-system', 'send-message',
  ]);
  const stateChangingTools = result.tools.filter((tool) => (
    hasAnyCapability(tool.classification.capabilities, stateChangingCapabilities)
  )).length;
  const secretExecutionChains = result.findings.filter((finding) => (
    /secret|credential/i.test(`${finding.title} ${finding.access.join(' ')}`)
    && /shell|command|execute/i.test(`${finding.title} ${finding.access.join(' ')}`)
  )).length;
  const suspiciousUnknowns = result.tools.filter((tool) => (
    tool.classification.source === 'unknown'
    && /admin|execute|trigger|workflow|sync|deploy|delete/i.test(tool.name)
  )).length;
  const clientsWithSensitiveAccess = new Set(result.tools
    .filter((tool) => tool.classification.sensitive)
    .map((tool) => tool.client)).size;
  const confidence = summary.tools > 0 ? Math.round((summary.classified / summary.tools) * 100) : 0;
  const postureAvailable = summary.tools > 0;

  return [
    {
      active: 'Mapping Claude and Codex configuration boundaries',
      complete: `${summary.clientsDetected} ${plural(summary.clientsDetected, 'client')} · ${configSources} configuration ${plural(configSources, 'source')}`,
      delayMs: 4_800,
      tone: 'success',
    },
    {
      active: 'Normalizing MCP server identities and transports',
      complete: `${summary.servers} unique ${plural(summary.servers, 'server')} · ${transportKinds} transport ${plural(transportKinds, 'type')}`,
      delayMs: 5_400,
      tone: 'success',
    },
    {
      active: 'Verifying declared tool inventories without invoking tools',
      complete: `${successfulInventories} inventories available · ${unavailableInventories} unavailable`,
      delayMs: 5_200,
      tone: unavailableInventories > 0 ? 'warning' : 'success',
    },
    {
      active: `Fingerprinting ${summary.tools} tool names, descriptions, and schemas`,
      complete: `${summary.tools} tool signatures indexed · ${schemaBackedTools} include schemas`,
      delayMs: 5_200,
      tone: 'success',
    },
    {
      active: 'Semantically matching tool intent against trusted classifications',
      complete: `${summary.classified} recognized · ${summary.unclassified} held for review · ${confidence}% coverage`,
      delayMs: 6_000,
      tone: summary.unclassified > 0 ? 'warning' : 'success',
    },
    {
      active: 'Mapping sensitive capabilities to their owning servers',
      complete: `${summary.sensitiveCapabilities} sensitive ${plural(summary.sensitiveCapabilities, 'tool')} across ${sensitiveServers} server bindings`,
      delayMs: 5_200,
      tone: summary.sensitiveCapabilities > 0 ? 'warning' : 'success',
    },
    {
      active: 'Tracing state-changing write, execution, and deployment surfaces',
      complete: `${stateChangingTools} state-changing ${plural(stateChangingTools, 'tool')} exposed`,
      delayMs: 5_800,
      tone: stateChangingTools > 0 ? 'warning' : 'success',
    },
    {
      active: 'Checking for direct production and administrative authority',
      complete: criticalPaths > 0
        ? `${criticalPaths} critical direct ${plural(criticalPaths, 'path')} found`
        : 'No critical direct authority found',
      delayMs: 5_000,
      tone: criticalPaths > 0 ? 'warning' : 'success',
    },
    {
      active: 'Testing credential access against command-execution reachability',
      complete: secretExecutionChains > 0
        ? `${secretExecutionChains} credential-to-execution ${plural(secretExecutionChains, 'chain')} found`
        : 'No credential-to-execution chain found',
      delayMs: 6_200,
      tone: secretExecutionChains > 0 ? 'warning' : 'success',
    },
    {
      active: 'Searching cross-server paths that amplify agent authority',
      complete: crossServerChains > 0
        ? `${crossServerChains} cross-server ${plural(crossServerChains, 'path')} contributes to risk`
        : 'No cross-server amplification path found',
      delayMs: 6_400,
      tone: crossServerChains > 0 ? 'warning' : 'success',
    },
    {
      active: `Comparing permissions across ${summary.clientsDetected} agent clients`,
      complete: sharedPermissionFindings > 0
        ? `${sharedPermissionFindings} shared-permission ${plural(sharedPermissionFindings, 'finding')}`
        : 'No risky permission overlap found',
      delayMs: 5_200,
      tone: sharedPermissionFindings > 0 ? 'warning' : 'success',
    },
    {
      active: 'Testing least-privilege separation between agent roles',
      complete: `${clientsWithSensitiveAccess} ${plural(clientsWithSensitiveAccess, 'client')} hold sensitive access`,
      delayMs: 5_400,
      tone: clientsWithSensitiveAccess > 1 ? 'warning' : 'success',
    },
    {
      active: 'Isolating ambiguous tools for conservative review',
      complete: `${summary.unclassified} unknown · ${suspiciousUnknowns} appear state-changing`,
      delayMs: 4_400,
      tone: summary.unclassified > 0 ? 'warning' : 'success',
    },
    {
      active: 'Ranking exploitability, blast radius, and classification confidence',
      complete: postureAvailable
        ? `${summary.highRiskFindings} high-risk · posture ${summary.postureScore}/100 · coverage ${confidence}%`
        : 'Posture unavailable · no tool definitions retrieved',
      delayMs: 7_800,
      tone: !postureAvailable || summary.highRiskFindings + summary.unclassified > 0 ? 'warning' : 'success',
    },
  ];
}

export async function playAnalysisPath(
  result: AuditResult,
  options: PlayAnalysisPathOptions = {},
): Promise<void> {
  const sleep = options.sleep || wait;
  const beats = buildAnalysisPath(result);
  const first = beats[0];
  if (!first) return;

  const requestedDuration = Math.max(0, options.durationMs ?? DEFAULT_INSPECTION_WINDOW_MS);
  const nominalDuration = beats.reduce((total, beat) => total + beat.delayMs, 0);
  const scale = nominalDuration > 0 ? requestedDuration / nominalDuration : 0;
  let remainingMs = requestedDuration;
  const spinner = ora({
    color: 'magenta',
    ...(options.silent !== undefined ? { isSilent: options.silent } : {}),
    spinner: 'dots12',
    text: first.active,
  }).start();

  for (const [index, beat] of beats.entries()) {
    const phaseDuration = beat.delayMs * scale;
    const analysisDuration = Math.round(phaseDuration * 0.82);
    const evidenceDuration = Math.max(0, Math.round(phaseDuration) - analysisDuration);
    const position = chalk.gray(`${String(index + 1).padStart(2, '0')}/${beats.length}`);
    spinner.text = `${position} ${beat.active} ${chalk.gray(`· ${formatRemaining(remainingMs)}`)}`;
    await sleep(analysisDuration);
    remainingMs = Math.max(0, remainingMs - analysisDuration);

    const marker = beat.tone === 'warning' ? chalk.yellow('!') : chalk.green('✓');
    spinner.text = `${position} ${marker} ${beat.complete}`;
    await sleep(evidenceDuration);
    remainingMs = Math.max(0, remainingMs - evidenceDuration);
  }
  spinner.succeed(
    `${chalk.bold('Inspection complete')} ${chalk.gray('·')} ${result.summary.highRiskFindings} high-risk ${chalk.gray('·')} ${result.summary.unclassified} unclassified`,
  );
}
