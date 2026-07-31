import { access, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, join, parse, resolve } from 'node:path';
import type { ClientId } from '../types.js';

export interface PathContext {
  home: string;
  cwd: string;
  platform: NodeJS.Platform;
  appData?: string;
}

export interface ConfigCandidate {
  client: ClientId;
  path: string;
  scope: 'user' | 'project' | 'desktop' | 'custom';
  format: 'json' | 'toml';
}

export function defaultPathContext(): PathContext {
  const home = process.env.SLAUNT_AUDIT_HOME || process.env.HOME || process.cwd();
  return {
    home: resolve(home),
    cwd: resolve(process.env.SLAUNT_AUDIT_CWD || process.cwd()),
    platform: (process.env.SLAUNT_AUDIT_PLATFORM as NodeJS.Platform | undefined) || process.platform,
    ...(process.env.APPDATA ? { appData: process.env.APPDATA } : {}),
  };
}

function ancestorDirectories(start: string, stopAt: string): string[] {
  const directories: string[] = [];
  let current = resolve(start);
  const stop = resolve(stopAt);
  const root = parse(current).root;

  while (true) {
    directories.push(current);
    if (current === stop || current === root) break;
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }

  return directories;
}

export function candidateConfigPaths(context = defaultPathContext()): ConfigCandidate[] {
  const candidates: ConfigCandidate[] = [
    { client: 'claude-code', path: join(context.home, '.claude.json'), scope: 'user', format: 'json' },
    { client: 'codex', path: join(context.home, '.codex', 'config.toml'), scope: 'user', format: 'toml' },
  ];

  if (context.platform === 'darwin') {
    candidates.push({
      client: 'claude-desktop',
      path: join(context.home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      scope: 'desktop',
      format: 'json',
    });
  } else if (context.platform === 'win32') {
    const appData = context.appData || join(context.home, 'AppData', 'Roaming');
    candidates.push({
      client: 'claude-desktop',
      path: join(appData, 'Claude', 'claude_desktop_config.json'),
      scope: 'desktop',
      format: 'json',
    });
  } else {
    candidates.push({
      client: 'claude-desktop',
      path: join(context.home, '.config', 'Claude', 'claude_desktop_config.json'),
      scope: 'desktop',
      format: 'json',
    });
  }

  for (const directory of ancestorDirectories(context.cwd, context.home)) {
    candidates.push(
      { client: 'claude-code', path: join(directory, '.mcp.json'), scope: 'project', format: 'json' },
      { client: 'codex', path: join(directory, '.codex', 'config.toml'), scope: 'project', format: 'toml' },
    );
  }

  const seen = new Set<string>();
  return candidates.filter((candidate) => {
    const key = `${candidate.client}:${candidate.path}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function existingCandidates(candidates: ConfigCandidate[]): Promise<ConfigCandidate[]> {
  const checks = await Promise.all(
    candidates.map(async (candidate) => {
      try {
        await access(candidate.path, constants.R_OK);
        const metadata = await stat(candidate.path);
        return metadata.isFile() && metadata.size <= 5 * 1024 * 1024 ? candidate : undefined;
      } catch {
        return undefined;
      }
    }),
  );
  return checks.filter((candidate): candidate is ConfigCandidate => candidate !== undefined);
}
