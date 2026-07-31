import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { basename, extname } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type {
  ClientDetection,
  ClientId,
  DiscoveredConfiguration,
  ServerConfig,
  TransportKind,
} from '../types.js';
import {
  candidateConfigPaths,
  defaultPathContext,
  existingCandidates,
  type ConfigCandidate,
  type PathContext,
} from './paths.js';

const CLIENT_LABELS: Record<ClientId, string> = {
  'claude-code': 'Claude Code',
  'claude-desktop': 'Claude Desktop',
  codex: 'Codex',
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringRecord(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  return Object.fromEntries(
    Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === 'string'),
  );
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function inferTransport(server: Record<string, unknown>): TransportKind {
  const explicit = typeof server.type === 'string' ? server.type.toLowerCase() : '';
  if (explicit === 'http' || explicit === 'streamable-http') return 'http';
  if (explicit === 'sse') return 'sse';
  if (explicit === 'stdio') return 'stdio';
  if (typeof server.command === 'string') return 'stdio';
  if (typeof server.url === 'string') return 'http';
  return 'unknown';
}

function serverId(client: ClientId, name: string, path: string): string {
  return createHash('sha256').update(`${client}\0${name}\0${path}`).digest('hex').slice(0, 20);
}

function normalizeServers(
  candidate: ConfigCandidate,
  rawServers: unknown,
): ServerConfig[] {
  if (!isRecord(rawServers)) return [];

  return Object.entries(rawServers).flatMap(([name, value]) => {
    if (!isRecord(value)) return [];
    const env = stringRecord(value.env);
    const headers = {
      ...stringRecord(value.headers),
      ...stringRecord(value.http_headers),
    };
    const envHeaderNames = stringRecord(value.env_http_headers);
    for (const [header, envName] of Object.entries(envHeaderNames)) {
      const resolved = process.env[envName];
      if (resolved) headers[header] = resolved;
    }

    const url = typeof value.url === 'string' ? value.url : undefined;
    const command = typeof value.command === 'string' ? value.command : undefined;
    const enabled = value.enabled !== false && value.disabled !== true;
    return [{
      id: serverId(candidate.client, name, candidate.path),
      client: candidate.client,
      clientLabel: CLIENT_LABELS[candidate.client],
      name,
      transport: inferTransport(value),
      sourcePath: candidate.path,
      scope: candidate.scope,
      ...(command ? { command } : {}),
      args: stringArray(value.args),
      env,
      envKeys: Object.keys(env).sort(),
      ...(url ? { url } : {}),
      headers,
      headerKeys: [...new Set([...Object.keys(headers), ...Object.keys(envHeaderNames)])].sort(),
      enabled,
    }];
  });
}

async function parseCandidate(candidate: ConfigCandidate): Promise<ServerConfig[]> {
  const content = await readFile(candidate.path, 'utf8');
  if (candidate.format === 'toml') {
    const parsed = parseToml(content);
    return normalizeServers(candidate, isRecord(parsed) ? parsed.mcp_servers : undefined);
  }
  const parsed: unknown = JSON.parse(content);
  return normalizeServers(candidate, isRecord(parsed) ? parsed.mcpServers : undefined);
}

function inferCustomCandidate(path: string): ConfigCandidate {
  const format = extname(path).toLowerCase() === '.toml' ? 'toml' : 'json';
  const lower = basename(path).toLowerCase();
  const client: ClientId = format === 'toml'
    ? 'codex'
    : lower.includes('desktop')
      ? 'claude-desktop'
      : 'claude-code';
  return { client, path, scope: 'custom', format };
}

export interface DiscoverOptions {
  context?: PathContext;
  customPaths?: string[];
}

export async function discoverConfigurations(options: DiscoverOptions = {}): Promise<DiscoveredConfiguration> {
  const context = options.context || defaultPathContext();
  const standard = candidateConfigPaths(context);
  const custom = (options.customPaths || []).map(inferCustomCandidate);
  const candidates = await existingCandidates([...standard, ...custom]);
  const warnings: string[] = [];
  const servers: ServerConfig[] = [];

  for (const candidate of candidates) {
    try {
      servers.push(...await parseCandidate(candidate));
    } catch (error) {
      const reason = error instanceof Error ? error.message : 'unknown parse error';
      warnings.push(`Could not parse ${candidate.path}: ${reason}`);
    }
  }

  const clients: ClientDetection[] = (Object.keys(CLIENT_LABELS) as ClientId[]).map((id) => {
    const sources = candidates.filter((candidate) => candidate.client === id).map((candidate) => candidate.path);
    return { id, label: CLIENT_LABELS[id], detected: sources.length > 0, sources };
  });

  return {
    clients,
    servers: servers.filter((server) => server.enabled),
    warnings,
  };
}
