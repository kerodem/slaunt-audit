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
      active: `Indexing ${summary.tools} tools from ${summary.servers} MCP servers`,
      complete: `Indexed ${summary.tools} ${plural(summary.tools, 'tool')} from ${summary.servers} MCP ${plural(summary.servers, 'server')}`,
      delayMs: 380,
      tone: 'success',
    },
    {
      active: 'Searching direct and chained privilege paths',
      complete: `${criticalPaths} direct · ${crossServerChains} chained`,
      delayMs: 680,
      tone: criticalPaths + crossServerChains > 0 ? 'warning' : 'success',
    },
    {
      active: `Comparing permissions across ${summary.clientsDetected} agent clients`,
      complete: sharedPermissionFindings > 0
        ? `Permission overlap contributes to ${sharedPermissionFindings} ${plural(sharedPermissionFindings, 'finding')}`
        : 'No risky permission overlap found',
      delayMs: 520,
      tone: sharedPermissionFindings > 0 ? 'warning' : 'success',
    },
    {
      active: 'Prioritizing findings by exploitability and blast radius',
      complete: summary.highRiskFindings > 0
        ? `${summary.highRiskFindings} high-risk · ${summary.unclassified} unclassified`
        : `${summary.unclassified} unclassified · no high-risk findings`,
      delayMs: 490,
      tone: summary.highRiskFindings + summary.unclassified > 0 ? 'warning' : 'success',
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
  const spinner = ora({
    color: 'magenta',
    spinner: 'dots12',
    text: first.active,
  }).start();

  for (const beat of beats) {
    spinner.text = beat.active;
    await sleep(beat.delayMs);
  }
  spinner.succeed(
    `${chalk.bold('Analysis complete')} ${chalk.gray('·')} ${result.summary.highRiskFindings} high-risk ${chalk.gray('·')} ${result.summary.unclassified} unclassified`,
  );
}
