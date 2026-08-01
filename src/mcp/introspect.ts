import { basename } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { DeclaredTool, ServerConfig, ServerProbe } from '../types.js';

function resolvedEnvironment(configured: Record<string, string>): Record<string, string> {
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter((entry): entry is [string, string] => typeof entry[1] === 'string'),
  );
  return { ...inherited, ...configured };
}

function expandEnvironment(value: string): string {
  return value.replace(/\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}/gi, (_match, name: string, fallback?: string) => {
    return process.env[name] ?? fallback ?? '';
  });
}

function redactedError(error: unknown, server: ServerConfig): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const value of [...Object.values(server.env), ...Object.values(server.headers)]) {
    if (value.length >= 4) message = message.replaceAll(value, '[redacted]');
  }
  message = message
    .replace(/(bearer\s+)[a-z0-9._~+/=-]+/gi, '$1[redacted]')
    .replace(/([?&](?:token|key|secret|password)=)[^&\s]+/gi, '$1[redacted]');
  return message.slice(0, 300);
}

function asInputSchema(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

async function listAllTools(client: Client, server: ServerConfig): Promise<DeclaredTool[]> {
  const tools: DeclaredTool[] = [];
  let cursor: string | undefined;
  do {
    const response = await client.listTools(cursor ? { cursor } : undefined);
    for (const tool of response.tools) {
      const inputSchema = asInputSchema(tool.inputSchema);
      tools.push({
        serverId: server.id,
        serverName: server.name,
        client: server.client,
        clientLabel: server.clientLabel,
        name: tool.name,
        description: tool.description || '',
        ...(inputSchema ? { inputSchema } : {}),
      });
    }
    cursor = response.nextCursor;
  } while (cursor);
  return tools;
}

async function connectAndList(
  server: ServerConfig,
  transport: StdioClientTransport | StreamableHTTPClientTransport | SSEClientTransport,
): Promise<DeclaredTool[]> {
  const client = new Client({ name: 'slaunt-audit', version: '0.1.6' }, { capabilities: {} });
  try {
    // The SDK's transport classes declare `sessionId?: string` while its shared
    // Transport interface is emitted without exact-optional compatibility.
    await client.connect(transport as Parameters<Client['connect']>[0]);
    return await listAllTools(client, server);
  } finally {
    await client.close().catch(() => undefined);
  }
}

async function withTimeout<T>(operation: Promise<T>, milliseconds: number, onTimeout: () => Promise<void>): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      void onTimeout().finally(() => reject(new Error(`MCP probe timed out after ${milliseconds} ms`)));
    }, milliseconds);
  });
  try {
    return await Promise.race([operation, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function probeServer(server: ServerConfig, allowServerStarts: boolean, timeoutMs: number): Promise<ServerProbe> {
  if (server.transport === 'stdio') {
    if (isRecursiveSlauntLauncher(server)) {
      return {
        serverId: server.id,
        status: 'skipped',
        tools: [],
        message: 'Skipped a Slaunt CLI launcher to prevent a recursive audit',
      };
    }
    if (!allowServerStarts) {
      return { serverId: server.id, status: 'skipped', tools: [], message: 'Local server start was not approved' };
    }
    if (!server.command) return { serverId: server.id, status: 'failed', tools: [], message: 'Missing stdio command' };
    try {
      const transport = new StdioClientTransport({
        command: expandEnvironment(server.command),
        args: server.args.map(expandEnvironment),
        env: resolvedEnvironment(server.env),
        stderr: 'pipe',
      });
      const tools = await withTimeout(connectAndList(server, transport), timeoutMs, () => transport.close());
      return { serverId: server.id, status: 'ok', tools };
    } catch (error) {
      return { serverId: server.id, status: 'failed', tools: [], message: redactedError(error, server) };
    }
  }

  if ((server.transport === 'http' || server.transport === 'sse') && server.url) {
    try {
      const endpoint = new URL(expandEnvironment(server.url));
      const headers = Object.fromEntries(
        Object.entries(server.headers).map(([name, value]) => [name, expandEnvironment(value)]),
      );
      const requestInit = { headers, redirect: 'error' as const };
      if (server.transport === 'sse') {
        const transport = new SSEClientTransport(endpoint, { requestInit });
        const tools = await withTimeout(connectAndList(server, transport), timeoutMs, () => transport.close());
        return { serverId: server.id, status: 'ok', tools };
      }
      try {
        const transport = new StreamableHTTPClientTransport(endpoint, { requestInit });
        const tools = await withTimeout(connectAndList(server, transport), timeoutMs, () => transport.close());
        return { serverId: server.id, status: 'ok', tools };
      } catch (streamableError) {
        const message = redactedError(streamableError, server);
        if (!/4\d\d|sse|method|content[- ]type/i.test(message)) throw streamableError;
        const transport = new SSEClientTransport(endpoint, { requestInit });
        const tools = await withTimeout(connectAndList(server, transport), timeoutMs, () => transport.close());
        return { serverId: server.id, status: 'ok', tools };
      }
    } catch (error) {
      return { serverId: server.id, status: 'failed', tools: [], message: redactedError(error, server) };
    }
  }

  return { serverId: server.id, status: 'skipped', tools: [], message: `Unsupported ${server.transport} transport` };
}

async function mapWithConcurrency<T, R>(items: T[], concurrency: number, mapper: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (true) {
      const index = next++;
      if (index >= items.length) return;
      const item = items[index];
      if (item !== undefined) results[index] = await mapper(item);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

export interface ProbeOptions {
  allowServerStarts: boolean;
  timeoutMs?: number;
  concurrency?: number;
}

export async function probeServers(servers: ServerConfig[], options: ProbeOptions): Promise<ServerProbe[]> {
  return mapWithConcurrency(
    servers,
    options.concurrency || 4,
    (server) => probeServer(server, options.allowServerStarts, options.timeoutMs || 8_000),
  );
}

export function isDynamicLauncher(server: ServerConfig): boolean {
  const command = server.command ? basename(server.command).toLowerCase() : '';
  return ['npx', 'uvx', 'docker', 'podman', 'bunx', 'pnpx'].includes(command);
}

export function isRecursiveSlauntLauncher(server: ServerConfig): boolean {
  const command = server.command ? basename(server.command).toLowerCase() : '';
  if (/^slaunt(?:\.cmd|\.exe)?$/.test(command)) return true;

  if (['npx', 'bunx', 'pnpx'].includes(command)) {
    return server.args.some((argument) => /^slaunt(?:@[^/\s]+)?$/i.test(argument));
  }

  return server.args.some((argument) => {
    const normalized = argument.replaceAll('\\', '/');
    return /(?:^|\/)slaunt(?:-audit)?(?:\/.*)?\/(?:dist\/)?cli\.(?:c?js|mjs)$/i.test(normalized);
  });
}
