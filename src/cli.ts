#!/usr/bin/env node

import { confirm } from '@inquirer/prompts';
import chalk from 'chalk';
import open from 'open';
import ora from 'ora';
import type { ClientId, InstallChange } from './types.js';
import { runAudit } from './audit/run.js';
import { discoverConfigurations } from './config/discover.js';
import { installSlauntMcp } from './config/install.js';
import { isDynamicLauncher } from './mcp/introspect.js';
import { writeHtmlReport } from './report/html.js';
import { DEFAULT_INSPECTION_WINDOW_MS, playAnalysisPath } from './tui/analysis-path.js';
import { renderAudit, renderHeader } from './tui/render.js';
import { streamTerminalText } from './tui/stream.js';

interface CliOptions {
  customPaths: string[];
  demo: boolean;
  json: boolean;
  offline: boolean;
  openReport: boolean;
  noMotion: boolean;
  noReport: boolean;
  output?: string;
  timeoutMs?: number;
  installSlaunt?: boolean;
  allowServerStarts?: boolean;
  yes: boolean;
}

const HELP = `Slaunt MCP Agent Access Audit

Usage:
  npx slaunt audit [options]

Options:
  --install-slaunt          Add the Slaunt MCP server to detected client configurations
  --allow-server-starts     Start local stdio servers to request tools/list inventories
  --no-server-starts        Inspect configuration only; do not start local MCP servers
  --config <path>           Inspect an additional JSON or TOML MCP config (repeatable)
  --offline                 Use the built-in classification catalog; do not refresh it
  --output <path>           Full HTML report path
  --no-report               Do not save the full HTML report
  --open-report             Open the full HTML report after the audit
  --quick, --no-motion      Skip paced inspection and progressive report reveal
  --timeout <ms>            Per-server probe timeout (1000-60000; default 8000)
  --json                    Print a machine-readable result with secrets redacted
  --yes                     Approve read-only tools/list startup for automation
  --demo                    Render a deterministic 43-tool example audit
  -h, --help                Show help
  -v, --version             Show version

Privacy:
  Slaunt may download its reviewed classification catalog. Tool definitions,
  configuration values, and findings are analyzed locally and are not uploaded.
`;

function valueAfter(args: string[], index: number, option: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith('-')) throw new Error(`${option} requires a value`);
  return value;
}

function parseArguments(args: string[]): CliOptions {
  const options: CliOptions = {
    customPaths: [], demo: false, json: false, offline: false, openReport: false, noMotion: false, noReport: false, yes: false,
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === 'audit') continue;
    if (argument === '--demo') options.demo = true;
    else if (argument === '--json') options.json = true;
    else if (argument === '--offline') options.offline = true;
    else if (argument === '--open-report') options.openReport = true;
    else if (argument === '--no-open') options.openReport = false;
    else if (argument === '--no-motion' || argument === '--quick') options.noMotion = true;
    else if (argument === '--no-report') options.noReport = true;
    else if (argument === '--yes' || argument === '-y') options.yes = true;
    else if (argument === '--install-slaunt') options.installSlaunt = true;
    else if (argument === '--no-install-slaunt') options.installSlaunt = false;
    else if (argument === '--allow-server-starts') options.allowServerStarts = true;
    else if (argument === '--no-server-starts') options.allowServerStarts = false;
    else if (argument === '--config') options.customPaths.push(valueAfter(args, index++, argument));
    else if (argument === '--output') options.output = valueAfter(args, index++, argument);
    else if (argument === '--timeout') {
      const value = Number(valueAfter(args, index++, argument));
      if (!Number.isInteger(value) || value < 1_000 || value > 60_000) throw new Error('--timeout must be an integer from 1000 to 60000');
      options.timeoutMs = value;
    } else if (argument === '--help' || argument === '-h') {
      process.stdout.write(HELP);
      process.exit(0);
    } else if (argument === '--version' || argument === '-v') {
      process.stdout.write('0.1.6\n');
      process.exit(0);
    } else if (argument === 'connect') {
      throw new Error('connect is intentionally not implemented in this audit-only release');
    } else if (argument) {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  return options;
}

function installationSummary(changes: InstallChange[]): void {
  for (const change of changes) {
    const label = change.client === 'codex' ? 'Codex' : change.client === 'claude-code' ? 'Claude Code' : 'Claude Desktop';
    if (change.status === 'installed') {
      process.stdout.write(`${chalk.green('✓')} Added Slaunt MCP to ${label}${change.backupPath ? chalk.gray(' (backup created)') : ''}\n`);
    } else if (change.status === 'already-present') {
      process.stdout.write(`${chalk.green('✓')} Slaunt MCP already configured in ${label}\n`);
    } else if (change.status === 'failed') {
      process.stdout.write(`${chalk.yellow('!')} Could not update ${label}: ${change.message || 'unknown error'}\n`);
    }
  }
}

async function main(): Promise<void> {
  const rawArgs = process.argv.slice(2);
  if (rawArgs.length === 0 || rawArgs.every((arg) => arg.startsWith('-'))) rawArgs.unshift('audit');
  if (rawArgs[0] !== 'audit' && !['--help', '-h', '--version', '-v'].includes(rawArgs[0] || '')) {
    if (rawArgs[0] === 'connect') throw new Error('connect is intentionally not implemented in this audit-only release');
    throw new Error(`Unknown command: ${rawArgs[0]}`);
  }
  const options = parseArguments(rawArgs);
  const inspectionStartedAt = Date.now();
  const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY && !options.json);
  const motionEnabled = interactive
    && !options.noMotion
    && !options.yes
    && !process.env.CI
    && process.env.SLAUNT_NO_MOTION !== '1';

  if (!options.json) process.stdout.write(`${renderHeader()}\n\n`);

  let discovery = options.demo ? undefined : await discoverConfigurations({
    ...(options.customPaths.length ? { customPaths: options.customPaths } : {}),
  });

  const detectedClients = discovery?.clients.filter((client) => client.detected).map((client) => client.id) || [];
  const clientsMissingSlaunt = detectedClients.filter((client) => !discovery?.servers.some((server) => server.client === client && server.name.toLowerCase() === 'slaunt'));
  const shouldInstall = options.installSlaunt === true && !options.demo;
  if (shouldInstall && clientsMissingSlaunt.length > 0) {
    const changes = await installSlauntMcp({ clients: clientsMissingSlaunt as ClientId[] });
    if (!options.json) installationSummary(changes);
    discovery = await discoverConfigurations({ ...(options.customPaths.length ? { customPaths: options.customPaths } : {}) });
  }

  const stdioServers = discovery?.servers.filter((server) => server.transport === 'stdio') || [];
  let allowServerStarts = options.allowServerStarts ?? (options.yes && !options.demo);
  if (interactive && options.allowServerStarts === undefined && stdioServers.length > 0 && !options.demo) {
    const dynamicCount = stdioServers.filter(isDynamicLauncher).length;
    allowServerStarts = await confirm({
      message: `Start ${stdioServers.length} local MCP server${stdioServers.length === 1 ? '' : 's'} to request tools/list (their declared tool inventory)? No tools will be called.${dynamicCount ? ` ${dynamicCount} may launch package or container software.` : ''}`,
      default: true,
    });
  }

  const spinner = options.json ? undefined : ora({ text: 'Inspecting MCP configurations', color: 'magenta' }).start();
  const result = await runAudit({
    allowServerStarts: Boolean(allowServerStarts),
    ...(options.customPaths.length ? { customPaths: options.customPaths } : {}),
    ...(options.offline ? { offline: true } : {}),
    ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}),
    ...(options.demo ? { demo: true } : {}),
    ...(discovery ? { discovery } : {}),
    onStage: (_stage, detail) => { if (spinner) spinner.text = detail; },
  });
  spinner?.succeed('MCP evidence collected');
  if (motionEnabled) {
    const elapsedMs = Date.now() - inspectionStartedAt;
    await playAnalysisPath(result, {
      durationMs: Math.max(4_200, DEFAULT_INSPECTION_WINDOW_MS - elapsedMs),
    });
  }

  if (!options.noReport) {
    const reportPath = await writeHtmlReport(result, options.output);
    result.reportPath = reportPath;
  }

  if (options.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  const renderedAudit = `${renderAudit(result)}\n`;
  if (motionEnabled) await streamTerminalText(renderedAudit);
  else process.stdout.write(renderedAudit);
  if (options.openReport && result.reportPath) await open(result.reportPath, { wait: false });
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${chalk.red('slaunt audit failed:')} ${message}\n`);
  process.exitCode = 1;
});
