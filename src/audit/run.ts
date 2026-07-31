import type { AuditResult, DiscoveredConfiguration, ServerConfig } from '../types.js';
import { classifyTools } from '../classification/classifier.js';
import { loadCatalog } from '../classification/catalog.js';
import { discoverConfigurations } from '../config/discover.js';
import { demoDiscovery, demoProbes } from '../demo.js';
import { probeServers } from '../mcp/introspect.js';
import { analyzeRisks, summarizeAudit } from './risk-engine.js';

export type AuditStage = 'discover' | 'catalog' | 'probe' | 'classify' | 'analyze';

export interface RunAuditOptions {
  customPaths?: string[];
  allowServerStarts: boolean;
  offline?: boolean;
  timeoutMs?: number;
  demo?: boolean;
  discovery?: DiscoveredConfiguration;
  onStage?: (stage: AuditStage, detail: string) => void;
}

function sanitizeServer(server: ServerConfig): ServerConfig {
  return {
    ...server,
    env: Object.fromEntries(server.envKeys.map((key) => [key, '[redacted]'])),
    headers: Object.fromEntries(server.headerKeys.map((key) => [key, '[redacted]'])),
  };
}

export async function runAudit(options: RunAuditOptions): Promise<AuditResult> {
  options.onStage?.('discover', 'Reading known Claude and Codex configuration locations');
  const discovery = options.demo
    ? demoDiscovery()
    : options.discovery || await discoverConfigurations({ ...(options.customPaths ? { customPaths: options.customPaths } : {}) });

  options.onStage?.('catalog', 'Loading signed-down classification rules; local tool data stays local');
  const catalog = await loadCatalog({ ...(options.offline || options.demo ? { offline: true } : {}) });
  if (catalog.warning) discovery.warnings.push(`Classification catalog: ${catalog.warning}`);

  options.onStage?.('probe', 'Retrieving declared MCP tool definitions without calling any tools');
  const probes = options.demo
    ? demoProbes()
    : await probeServers(discovery.servers, {
      allowServerStarts: options.allowServerStarts,
      ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}),
    });

  options.onStage?.('classify', 'Matching declared capabilities against the trusted catalog');
  const tools = classifyTools(probes.flatMap((probe) => probe.tools), catalog.rules);

  options.onStage?.('analyze', 'Correlating capabilities across clients and servers');
  const findings = analyzeRisks(discovery.servers, tools);
  const clientCount = discovery.clients.filter((client) => client.detected).length;
  const serverCount = new Set(discovery.servers.map((server) => server.name.toLowerCase())).size;
  const summary = summarizeAudit(clientCount, serverCount, tools, findings);

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    privacy: {
      uploadedAuditData: false,
      catalogSource: catalog.source,
      startedConfiguredServers: options.allowServerStarts && discovery.servers.some((server) => server.transport === 'stdio'),
    },
    discovery: {
      ...discovery,
      servers: discovery.servers.map(sanitizeServer),
    },
    probes,
    tools,
    findings,
    summary,
  };
}
