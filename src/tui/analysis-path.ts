import chalk from 'chalk';
import ora from 'ora';
import type { AuditResult } from '../types.js';

export type AnalysisBeatTone = 'success' | 'warning';

export interface AnalysisBeat {
  active: string;
  complete: string;
  delayMs: number;
  tone: AnalysisBeatTone;
}

export interface PlayAnalysisPathOptions {
  sleep?: (milliseconds: number) => Promise<void>;
}

const wait = (milliseconds: number): Promise<void> => new Promise((resolve) => {
  setTimeout(resolve, milliseconds);
});

function plural(value: number, singular: string, pluralForm = `${singular}s`): string {
  return value === 1 ? singular : pluralForm;
}

export function buildAnalysisPath(result: AuditResult): AnalysisBeat[] {
  const { summary } = result;
  const criticalPaths = result.findings.filter((finding) => finding.severity === 'critical').length;
  const crossServerChains = result.findings.filter((finding) => (
    finding.serverNames.length > 1 && /chain/i.test(`${finding.title} ${finding.why}`)
  )).length;
  const sharedPermissionFindings = result.findings.filter((finding) => finding.clients.length > 1).length;

  return [
    {
      active: `Indexing ${summary.tools} declared tools across detected clients`,
      complete: `Indexed ${summary.tools} ${plural(summary.tools, 'tool')} from ${summary.servers} MCP ${plural(summary.servers, 'server')}`,
      delayMs: 360,
      tone: 'success',
    },
    {
      active: 'Building the client → server → capability graph',
      complete: `Mapped ${summary.sensitiveCapabilities} sensitive ${plural(summary.sensitiveCapabilities, 'capability', 'capabilities')} across ${summary.clientsDetected} ${plural(summary.clientsDetected, 'client')}`,
      delayMs: 440,
      tone: 'success',
    },
    {
      active: 'Searching for direct production-changing access',
      complete: criticalPaths > 0
        ? `${criticalPaths} critical direct-access ${plural(criticalPaths, 'path')} found`
        : 'No critical direct-access paths found',
      delayMs: 540,
      tone: criticalPaths > 0 ? 'warning' : 'success',
    },
    {
      active: 'Testing whether permissions can be chained across servers',
      complete: crossServerChains > 0
        ? `${crossServerChains} cross-server capability ${plural(crossServerChains, 'chain')} found`
        : 'No cross-server capability chains found',
      delayMs: 620,
      tone: crossServerChains > 0 ? 'warning' : 'success',
    },
    {
      active: 'Comparing permission overlap between agent clients',
      complete: sharedPermissionFindings > 0
        ? `Permission overlap contributes to ${sharedPermissionFindings} ${plural(sharedPermissionFindings, 'finding')}`
        : 'No risky permission overlap found',
      delayMs: 460,
      tone: sharedPermissionFindings > 0 ? 'warning' : 'success',
    },
    {
      active: 'Checking classification confidence and unknown tools',
      complete: summary.unclassified > 0
        ? `${summary.unclassified} ${plural(summary.unclassified, 'tool')} need human classification`
        : 'Every retrieved tool has a recognized classification',
      delayMs: 400,
      tone: summary.unclassified > 0 ? 'warning' : 'success',
    },
    {
      active: 'Ranking evidence by exploitability and blast radius',
      complete: summary.highRiskFindings > 0
        ? `${summary.highRiskFindings} high-risk ${plural(summary.highRiskFindings, 'finding')} prioritized for review`
        : 'No high-risk findings to prioritize',
      delayMs: 500,
      tone: summary.highRiskFindings > 0 ? 'warning' : 'success',
    },
  ];
}

export async function playAnalysisPath(
  result: AuditResult,
  options: PlayAnalysisPathOptions = {},
): Promise<void> {
  const sleep = options.sleep || wait;
  process.stdout.write(`\n${chalk.bold('Tracing exposure paths')}\n`);

  for (const beat of buildAnalysisPath(result)) {
    const spinner = ora({
      color: 'magenta',
      spinner: 'dots12',
      text: beat.active,
    }).start();
    await sleep(beat.delayMs);
    if (beat.tone === 'warning') spinner.warn(beat.complete);
    else spinner.succeed(beat.complete);
  }

  process.stdout.write(`${chalk.gray('Evidence graph complete. Preparing the risk map…')}\n`);
  await sleep(220);
}
