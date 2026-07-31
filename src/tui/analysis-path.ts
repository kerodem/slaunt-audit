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
      active: 'Finding Claude and Codex settings on this computer',
      complete: `${summary.clientsDetected} AI ${plural(summary.clientsDetected, 'assistant')} found in ${configSources} settings ${plural(configSources, 'file')}`,
      delayMs: 4_800,
      tone: 'success',
    },
    {
      active: 'Listing the services each assistant can reach',
      complete: `${summary.servers} connected ${plural(summary.servers, 'service')} · ${transportKinds} connection ${plural(transportKinds, 'type')}`,
      delayMs: 5_400,
      tone: 'success',
    },
    {
      active: 'Checking what each connected service allows',
      complete: `${successfulInventories} permission ${plural(successfulInventories, 'list')} available · ${unavailableInventories} unavailable`,
      delayMs: 5_200,
      tone: unavailableInventories > 0 ? 'warning' : 'success',
    },
    {
      active: `Reading the names and descriptions of ${summary.tools} available actions`,
      complete: `${summary.tools} ${plural(summary.tools, 'action')} reviewed · ${schemaBackedTools} include usage details`,
      delayMs: 5_200,
      tone: 'success',
    },
    {
      active: 'Matching each action to the kind of access it provides',
      complete: `${summary.classified} understood · ${summary.unclassified} need a closer look · ${confidence}% covered`,
      delayMs: 6_000,
      tone: summary.unclassified > 0 ? 'warning' : 'success',
    },
    {
      active: 'Finding access to sensitive information and important changes',
      complete: `${summary.sensitiveCapabilities} sensitive ${plural(summary.sensitiveCapabilities, 'action')} across ${sensitiveServers} service connections`,
      delayMs: 5_200,
      tone: summary.sensitiveCapabilities > 0 ? 'warning' : 'success',
    },
    {
      active: 'Checking which actions can change data or run commands',
      complete: `${stateChangingTools} ${plural(stateChangingTools, 'action')} can make changes`,
      delayMs: 5_800,
      tone: stateChangingTools > 0 ? 'warning' : 'success',
    },
    {
      active: 'Looking for direct access to live systems or administrator controls',
      complete: criticalPaths > 0
        ? `${criticalPaths} urgent ${plural(criticalPaths, 'issue')} found`
        : 'No urgent direct access found',
      delayMs: 5_000,
      tone: criticalPaths > 0 ? 'warning' : 'success',
    },
    {
      active: 'Checking whether credentials and command access can be combined',
      complete: secretExecutionChains > 0
        ? `${secretExecutionChains} risky ${plural(secretExecutionChains, 'combination')} found`
        : 'Credentials and command access are kept separate',
      delayMs: 6_200,
      tone: secretExecutionChains > 0 ? 'warning' : 'success',
    },
    {
      active: 'Looking for permissions that become riskier when combined',
      complete: crossServerChains > 0
        ? `${crossServerChains} risky ${plural(crossServerChains, 'combination')} across connected services`
        : 'No risky combinations found across services',
      delayMs: 6_400,
      tone: crossServerChains > 0 ? 'warning' : 'success',
    },
    {
      active: `Comparing what each of the ${summary.clientsDetected} AI assistants can do`,
      complete: sharedPermissionFindings > 0
        ? `${sharedPermissionFindings} ${plural(sharedPermissionFindings, 'case')} of shared powerful access`
        : 'The assistants do not share risky access',
      delayMs: 5_200,
      tone: sharedPermissionFindings > 0 ? 'warning' : 'success',
    },
    {
      active: 'Checking whether each assistant has only the access it needs',
      complete: `${clientsWithSensitiveAccess} AI ${plural(clientsWithSensitiveAccess, 'assistant')} have sensitive access`,
      delayMs: 5_400,
      tone: clientsWithSensitiveAccess > 1 ? 'warning' : 'success',
    },
    {
      active: 'Setting aside unfamiliar actions for a person to review',
      complete: `${summary.unclassified} unfamiliar · ${suspiciousUnknowns} may make changes`,
      delayMs: 4_400,
      tone: summary.unclassified > 0 ? 'warning' : 'success',
    },
    {
      active: 'Putting the most urgent issues first',
      complete: postureAvailable
        ? `${summary.highRiskFindings} urgent ${plural(summary.highRiskFindings, 'issue')} · safety score ${summary.postureScore}/100 · ${confidence}% understood`
        : 'Safety score unavailable · no action lists could be read',
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
    `${chalk.bold('Safety check complete')} ${chalk.gray('·')} ${result.summary.highRiskFindings} urgent ${plural(result.summary.highRiskFindings, 'issue')} ${chalk.gray('·')} ${result.summary.unclassified} need review`,
  );
}
