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
import { renderAudit, renderHeader } from './tui/render.js';

interface CliOptions {
  customPaths: string[];
  demo: boolean;
  json: boolean;
  offline: boolean;
  noOpen: boolean;
  noReport: boolean;
  output?: string;
  timeoutMs?: number;
  installSlaunt?: boolean;
  allowServerStarts?: boolean;
  yes: boolean;
}

const HELP = `Slaunt Agent Access Audit

Usage:
  npx slaunt audit [options]

Options:
  --install-slaunt          Add Slaunt MCP to detected Claude/Codex user configs
  --no-install-slaunt       Do not offer to add Slaunt MCP
  --allow-server-starts     Start configured stdio servers to request tools/list
  --no-server-starts        Inspect configuration only; do not start local servers
  --config <path>           Inspect an additional JSON or TOML MCP config (repeatable)
  --offline                 Use the bundled catalog; do not refresh from Supabase
  --output <path>           HTML report path
  --no-report               Do not write the local HTML report
  --no-open                 Do not offer to open the HTML report
  --timeout <ms>            Per-server probe timeout (1000-60000; default 8000)
  --json                    Print a machine-readable, redacted JSON result
  --yes                     Accept safe interactive defaults for automation
  --demo                    Render a deterministic 43-tool example audit
  -h, --help                Show help
  -v, --version             Show version

Privacy:
  Catalog rules may be downloaded from Supabase. Tool names, descriptions,
  schemas, config values, and findings are classified locally and are not uploaded.
`;

function valueAfter(args: string[], index: number, option: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith('-')) throw new Error(`${option} requires a value`);
  return value;
}

function parseArguments(args: string[]): CliOptions {
  const options: CliOptions = {
    customPaths: [], demo: false, json: false, offline: false, noOpen: false, noReport: false, yes: false,
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === 'audit') continue;
    if (argument === '--demo') options.demo = true;
    else if (argument === '--json') options.json = true;
    else if (argument === '--offline') options.offline = true;
    else if (argument === '--no-open') options.noOpen = true;
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
      process.stdout.write('0.1.0\n');
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
  const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY && !options.json);

  if (!options.json) process.stdout.write(`${renderHeader()}\n\n${chalk.gray('Tool and configuration data stays on this machine. No audit payload uploaded.')}\n\n`);

  let discovery = options.demo ? undefined : await discoverConfigurations({
    ...(options.customPaths.length ? { customPaths: options.customPaths } : {}),
  });

  const detectedClients = discovery?.clients.filter((client) => client.detected).map((client) => client.id) || [];
  const clientsMissingSlaunt = detectedClients.filter((client) => !discovery?.servers.some((server) => server.client === client && server.name.toLowerCase() === 'slaunt'));
  let shouldInstall = options.installSlaunt ?? (options.yes && !options.demo);
  if (interactive && options.installSlaunt === undefined && clientsMissingSlaunt.length > 0 && !options.demo) {
    shouldInstall = await confirm({
      message: `Add Slaunt MCP to ${clientsMissingSlaunt.length} detected client configuration${clientsMissingSlaunt.length === 1 ? '' : 's'}? Backups are created first.`,
      default: true,
    });
  }
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
      message: `Start ${stdioServers.length} configured local MCP server${stdioServers.length === 1 ? '' : 's'} to read tools/list? No tools will be called.${dynamicCount ? ` ${dynamicCount} use package/container launchers.` : ''}`,
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
  spinner?.succeed('Audit complete');

  if (!options.noReport) {
    const reportPath = await writeHtmlReport(result, options.output);
    result.reportPath = reportPath;
  }

  if (options.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  process.stdout.write(`${renderAudit(result)}\n`);
  if (result.reportPath) process.stdout.write(`\n${chalk.gray('Full local report:')}\n${result.reportPath}\n`);

  if (interactive && result.reportPath && !options.noOpen) {
    const shouldOpen = await confirm({ message: 'Open report now?', default: true });
    if (shouldOpen) await open(result.reportPath, { wait: false });
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${chalk.red('slaunt audit failed:')} ${message}\n`);
  process.exitCode = 1;
});
