import { basename } from 'node:path';
import type {
  AuditSummary,
  Capability,
  ClassifiedTool,
  Finding,
  ServerConfig,
  Severity,
} from '../types.js';

const SEVERITY_ORDER: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const SECRET_NAME = /(token|secret|password|private[_-]?key|credential|api[_-]?key)/i;

function unique<T>(items: T[]): T[] {
  return [...new Set(items)];
}

function toolCapabilities(tools: ClassifiedTool[]): Set<Capability> {
  return new Set(tools.flatMap((tool) => tool.classification.capabilities));
}

function finding(partial: Omit<Finding, 'id'>): Finding {
  const id = `${partial.severity}:${partial.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')}`;
  return { id, ...partial };
}

function isLocalHost(hostname: string): boolean {
  return ['localhost', '127.0.0.1', '::1'].includes(hostname);
}

function packageIsPinned(argument: string): boolean {
  const packagePart = argument.startsWith('@') ? argument.slice(argument.indexOf('/') + 1) : argument;
  const at = packagePart.lastIndexOf('@');
  if (at < 0) return false;
  const version = packagePart.slice(at + 1);
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(version);
}

export function analyzeRisks(servers: ServerConfig[], tools: ClassifiedTool[]): Finding[] {
  const findings: Finding[] = [];

  for (const tool of tools.filter((item) => item.classification.capabilities.includes('deploy-production'))) {
    findings.push(finding({
      severity: 'critical',
      title: `${tool.clientLabel} can deploy without an external approval boundary`,
      serverNames: [tool.serverName],
      toolNames: [tool.name],
      access: ['Trigger production deployments'],
      why: 'A production-changing capability is directly exposed to the agent.',
      recommendation: 'Require a human approval policy and restrict deployment scope by environment.',
      clients: [tool.client],
    }));
  }

  for (const client of unique(tools.map((tool) => tool.client))) {
    const clientTools = tools.filter((tool) => tool.client === client);
    const capabilities = toolCapabilities(clientTools);
    if (capabilities.has('execute-shell') && capabilities.has('read-secrets')) {
      const label = clientTools[0]?.clientLabel || client;
      findings.push(finding({
        severity: 'high',
        title: `${label} can execute shell commands and access secrets`,
        serverNames: unique(clientTools
          .filter((tool) => tool.classification.capabilities.some((capability) => ['execute-shell', 'read-secrets'].includes(capability)))
          .map((tool) => tool.serverName)),
        toolNames: unique(clientTools
          .filter((tool) => tool.classification.capabilities.some((capability) => ['execute-shell', 'read-secrets'].includes(capability)))
          .map((tool) => tool.name)),
        access: ['Read credentials', 'Execute commands'],
        why: 'These capabilities can be chained to disclose or misuse credentials.',
        recommendation: 'Separate secret access from command execution and require approval for either boundary.',
        clients: [client],
      }));
    }
  }

  const githubByClient = new Map<string, ClassifiedTool[]>();
  for (const tool of tools.filter((item) => /github/i.test(item.serverName))) {
    const list = githubByClient.get(tool.client) || [];
    list.push(tool);
    githubByClient.set(tool.client, list);
  }
  const broadGithubClients = [...githubByClient.entries()].filter(([, clientTools]) => {
    const capabilities = toolCapabilities(clientTools);
    return capabilities.has('edit-code') && capabilities.has('merge-pull-request');
  });
  if (broadGithubClients.length >= 2) {
    findings.push(finding({
      severity: 'high',
      title: 'Detected clients share broad GitHub permissions',
      serverNames: unique(broadGithubClients.flatMap(([, clientTools]) => clientTools.map((tool) => tool.serverName))),
      toolNames: unique(broadGithubClients.flatMap(([, clientTools]) => clientTools.map((tool) => tool.name))),
      access: ['Edit code', 'Create pull requests', 'Merge pull requests', 'Delete branches or files'],
      why: 'Shared credentials erase role separation between agents.',
      recommendation: 'Assign repository permissions and credentials by agent role.',
      clients: broadGithubClients.map(([client]) => client as Finding['clients'][number]),
    }));
  }

  for (const server of servers) {
    if (server.url) {
      try {
        const url = new URL(server.url);
        if (url.protocol === 'http:' && !isLocalHost(url.hostname)) {
          findings.push(finding({
            severity: 'critical',
            title: `${server.clientLabel} sends MCP traffic over cleartext HTTP`,
            serverNames: [server.name],
            toolNames: [],
            access: ['MCP requests and responses can cross the network unencrypted'],
            why: 'A network observer could read or alter agent traffic.',
            recommendation: 'Use HTTPS with certificate verification before enabling this server.',
            clients: [server.client],
          }));
        }
      } catch {
        findings.push(finding({
          severity: 'high',
          title: `${server.clientLabel} has an invalid MCP server URL`,
          serverNames: [server.name],
          toolNames: [],
          access: [],
          why: 'The configured endpoint cannot be safely interpreted.',
          recommendation: 'Replace the endpoint with a reviewed HTTPS URL.',
          clients: [server.client],
        }));
      }
    }

    const inlineSecretKeys = server.envKeys.filter((key) => SECRET_NAME.test(key) && !/^\$\{.+\}$/u.test(server.env[key] || ''));
    const hasSecretArgument = server.args.some((arg, index) => SECRET_NAME.test(arg) && (
      /[=:]/u.test(arg) || Boolean(server.args[index + 1] && !server.args[index + 1]!.startsWith('-'))
    ));
    if (inlineSecretKeys.length > 0 || hasSecretArgument) {
      findings.push(finding({
        severity: 'high',
        title: `${server.clientLabel} stores credential material in an MCP configuration`,
        serverNames: [server.name],
        toolNames: [],
        access: [...inlineSecretKeys.map((key) => `Environment key: ${key}`), ...(hasSecretArgument ? ['Credential-like command argument'] : [])],
        why: 'Plaintext configuration values are exposed to local file readers and backups.',
        recommendation: 'Reference a protected environment variable or operating-system credential store.',
        clients: [server.client],
      }));
    }

    const command = server.command ? basename(server.command).toLowerCase() : '';
    if (['npx', 'pnpx', 'bunx'].includes(command)) {
      const packageArg = server.args.find((arg) => !arg.startsWith('-'));
      if (packageArg && !packageIsPinned(packageArg)) {
        findings.push(finding({
          severity: 'medium',
          title: `${server.name} can resolve an unpinned package at startup`,
          serverNames: [server.name],
          toolNames: [],
          access: ['Execute package registry code'],
          why: 'The code executed by this server can change without a configuration change.',
          recommendation: 'Pin the package to an exact reviewed version and preserve the package-manager lock or integrity data.',
          clients: [server.client],
        }));
      }
    }
  }

  const suspiciousUnknowns = tools.filter((item) => item.classification.source === 'unknown' && /admin|execute|trigger|workflow|sync/i.test(item.name));
  if (suspiciousUnknowns.length > 0) {
    findings.push(finding({
      severity: 'medium',
      title: `${suspiciousUnknowns.length} unclassified tools appear state-changing`,
      serverNames: unique(suspiciousUnknowns.map((tool) => tool.serverName)),
      toolNames: unique(suspiciousUnknowns.map((tool) => tool.name)),
      access: ['Potential administrative or execution capability'],
      why: 'No trusted rule explains tools whose names suggest privileged behavior.',
      recommendation: 'Review and classify these tools before leaving them exposed to an agent.',
      clients: unique(suspiciousUnknowns.map((tool) => tool.client)),
    }));
  }

  const deduplicated = [...new Map(findings.map((item) => [`${item.id}:${item.clients.join(',')}:${item.serverNames.join(',')}`, item])).values()];
  return deduplicated.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.title.localeCompare(b.title));
}

export function summarizeAudit(clientCount: number, serverCount: number, tools: ClassifiedTool[], findings: Finding[]): AuditSummary {
  const highRiskFindings = findings.filter((item) => item.severity === 'critical' || item.severity === 'high').length;
  const penalty = findings.reduce((total, item) => total + ({ critical: 22, high: 12, medium: 5, low: 2, info: 0 }[item.severity]), 0);
  return {
    clientsDetected: clientCount,
    servers: serverCount,
    tools: tools.length,
    classified: tools.filter((tool) => tool.classification.source !== 'unknown').length,
    sensitiveCapabilities: tools.filter((tool) => tool.classification.sensitive).length,
    highRiskFindings,
    unclassified: tools.filter((tool) => tool.classification.source === 'unknown').length,
    postureScore: Math.max(0, 100 - penalty),
  };
}
