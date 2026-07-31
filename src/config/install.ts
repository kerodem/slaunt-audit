import { randomBytes } from 'node:crypto';
import { chmod, copyFile, lstat, mkdir, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, join } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { ClientId, InstallChange } from '../types.js';
import type { PathContext } from './paths.js';
import { defaultPathContext } from './paths.js';

export const DEFAULT_SLAUNT_MCP_URL = 'https://central-mcp-ccr-production.up.railway.app/mcp';

interface InstallTarget {
  client: ClientId;
  path: string;
  format: 'json' | 'toml';
}

function targetsFor(clients: ClientId[], context: PathContext): InstallTarget[] {
  const targets: InstallTarget[] = [];
  if (clients.includes('claude-code')) {
    targets.push({ client: 'claude-code', path: join(context.home, '.claude.json'), format: 'json' });
  }
  if (clients.includes('claude-desktop')) {
    const path = context.platform === 'darwin'
      ? join(context.home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
      : context.platform === 'win32'
        ? join(context.appData || join(context.home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json')
        : join(context.home, '.config', 'Claude', 'claude_desktop_config.json');
    targets.push({ client: 'claude-desktop', path, format: 'json' });
  }
  if (clients.includes('codex')) {
    targets.push({ client: 'codex', path: join(context.home, '.codex', 'config.toml'), format: 'toml' });
  }
  return targets;
}

async function readExisting(path: string): Promise<{ content: string; mode: number } | undefined> {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) throw new Error('refusing to modify a symbolic link');
    if (!info.isFile()) throw new Error('configuration path is not a regular file');
    if (info.size > 5 * 1024 * 1024) throw new Error('configuration file is unexpectedly large');
    return { content: await readFile(path, 'utf8'), mode: info.mode & 0o777 };
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return undefined;
    throw error;
  }
}

async function atomicWrite(path: string, content: string, mode: number): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(path), `.${randomBytes(12).toString('hex')}.slaunt.tmp`);
  try {
    await writeFile(temporary, content, { encoding: 'utf8', mode, flag: 'wx' });
    await rename(temporary, path);
  } finally {
    await unlink(temporary).catch(() => undefined);
  }
}

async function backup(path: string, mode: number): Promise<string> {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = `${path}.slaunt-backup-${stamp}`;
  await copyFile(path, backupPath, constants.COPYFILE_EXCL);
  await chmod(backupPath, mode);
  return backupPath;
}

function updateJson(content: string | undefined, url: string): { content: string; present: boolean } {
  const parsed: unknown = content?.trim() ? JSON.parse(content) : {};
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('configuration root must be a JSON object');
  }
  const config = parsed as Record<string, unknown>;
  const existingServers = config.mcpServers;
  if (existingServers !== undefined && (typeof existingServers !== 'object' || existingServers === null || Array.isArray(existingServers))) {
    throw new Error('mcpServers must be a JSON object');
  }
  const servers = (existingServers || {}) as Record<string, unknown>;
  if (servers.slaunt) {
    const existing = servers.slaunt;
    if (typeof existing === 'object' && existing !== null && !Array.isArray(existing) && (existing as Record<string, unknown>).url === url) {
      return { content: content || '', present: true };
    }
    throw new Error('an MCP server named slaunt already exists with different settings');
  }
  config.mcpServers = { ...servers, slaunt: { type: 'http', url } };
  return { content: `${JSON.stringify(config, null, 2)}\n`, present: false };
}

function updateToml(content: string | undefined, url: string): { content: string; present: boolean } {
  const source = content || '';
  const parsed = source.trim() ? parseToml(source) : {};
  if (parsed.mcp_servers !== undefined && (typeof parsed.mcp_servers !== 'object' || parsed.mcp_servers === null || Array.isArray(parsed.mcp_servers))) {
    throw new Error('mcp_servers must be a TOML table');
  }
  const servers = (parsed.mcp_servers || {}) as Record<string, unknown>;
  if (servers.slaunt) {
    const existing = servers.slaunt;
    if (typeof existing === 'object' && existing !== null && !Array.isArray(existing) && (existing as Record<string, unknown>).url === url) {
      return { content: source, present: true };
    }
    throw new Error('an MCP server named slaunt already exists with different settings');
  }
  const separator = source.length === 0 || source.endsWith('\n\n') ? '' : source.endsWith('\n') ? '\n' : '\n\n';
  return {
    content: `${source}${separator}[mcp_servers.slaunt]\nenabled = true\nurl = ${JSON.stringify(url)}\n`,
    present: false,
  };
}

export interface InstallOptions {
  clients: ClientId[];
  context?: PathContext;
  url?: string;
}

export async function installSlauntMcp(options: InstallOptions): Promise<InstallChange[]> {
  const context = options.context || defaultPathContext();
  const url = options.url || process.env.SLAUNT_MCP_URL || DEFAULT_SLAUNT_MCP_URL;
  const parsedUrl = new URL(url);
  if (parsedUrl.protocol !== 'https:' && !(parsedUrl.protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(parsedUrl.hostname))) {
    throw new Error('Slaunt MCP URL must use HTTPS (HTTP is allowed only for localhost)');
  }

  const changes: InstallChange[] = [];
  for (const target of targetsFor([...new Set(options.clients)], context)) {
    try {
      const existing = await readExisting(target.path);
      const updated = target.format === 'json'
        ? updateJson(existing?.content, url)
        : updateToml(existing?.content, url);
      if (updated.present) {
        changes.push({ client: target.client, path: target.path, status: 'already-present' });
        continue;
      }
      const backupPath = existing ? await backup(target.path, existing.mode) : undefined;
      await atomicWrite(target.path, updated.content, existing?.mode || 0o600);
      const written = await stat(target.path);
      if (!written.isFile()) throw new Error('atomic configuration write did not produce a regular file');
      changes.push({
        client: target.client,
        path: target.path,
        status: 'installed',
        ...(backupPath ? { backupPath } : {}),
      });
    } catch (error) {
      changes.push({
        client: target.client,
        path: target.path,
        status: 'failed',
        message: error instanceof Error ? error.message : 'unknown installation error',
      });
    }
  }
  return changes;
}
