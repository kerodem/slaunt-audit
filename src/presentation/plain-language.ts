import type { Capability, ClientId, Finding, Severity } from '../types.js';

export interface PlainFinding {
  label: string;
  title: string;
  why: string;
  recommendation: string;
}

const severityLabels: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

const capabilityLabels: Record<Capability, string> = {
  'read-data': 'Read data',
  'write-data': 'Write data',
  'read-files': 'Read files',
  'write-files': 'Write files',
  'delete-data': 'Delete data',
  'execute-code': 'Execute code',
  'execute-shell': 'Execute shell commands',
  'read-secrets': 'Read credentials',
  'manage-auth': 'Manage authentication',
  'network-access': 'Access the network',
  'deploy-production': 'Deploy to production',
  'edit-code': 'Edit code',
  'create-pull-request': 'Create pull requests',
  'merge-pull-request': 'Merge pull requests',
  'administer-system': 'Administer systems',
  'control-browser': 'Control browsers',
  'send-message': 'Send messages',
};

const clientLabels: Record<ClientId, string> = {
  'claude-code': 'Claude Code',
  'claude-desktop': 'Claude Desktop',
  codex: 'Codex',
};

export function plainCapability(capability: Capability): string {
  return capabilityLabels[capability];
}

export function plainClient(client: ClientId): string {
  return clientLabels[client];
}

export function plainSeverity(severity: Severity): string {
  return severityLabels[severity];
}

export function plainFinding(item: Finding): PlainFinding {
  const label = plainSeverity(item.severity);
  const title = item.title;

  if (/deploy without an external approval boundary/i.test(title)) {
    const assistant = plainClient(item.clients[0] || 'claude-code');
    return {
      label,
      title: `${assistant} can deploy to production without an approval boundary`,
      why: 'The exposed deployment tool can change the live environment before a person reviews the action.',
      recommendation: 'Require human approval for production deployments and restrict the environments this agent can change.',
    };
  }

  if (/execute shell commands and access secrets/i.test(title)) {
    const assistant = plainClient(item.clients[0] || 'codex');
    return {
      label,
      title: `${assistant} can chain credential access with shell execution`,
      why: 'A tool chain could read passwords or tokens and then use them from an operating-system command.',
      recommendation: 'Separate credential access from shell execution, or require approval at both capability boundaries.',
    };
  }

  if (/share broad GitHub permissions/i.test(title)) {
    return {
      label,
      title: 'Claude Code and Codex share broad GitHub permissions',
      why: 'Shared credentials remove role separation, so either agent can use the same code-changing permissions.',
      recommendation: 'Give each agent role-scoped GitHub credentials limited to the repositories and actions it needs.',
    };
  }

  if (/cleartext HTTP/i.test(title)) {
    const assistant = plainClient(item.clients[0] || 'codex');
    return {
      label,
      title: `${assistant} sends MCP traffic over unencrypted HTTP`,
      why: 'A network observer could read or alter requests and responses sent through this MCP connection.',
      recommendation: 'Use HTTPS with certificate verification before enabling the MCP server.',
    };
  }

  if (/invalid MCP server URL/i.test(title)) {
    const assistant = plainClient(item.clients[0] || 'codex');
    return {
      label,
      title: `${assistant} has an invalid MCP server URL`,
      why: 'Slaunt cannot safely determine the network destination from the configured address.',
      recommendation: 'Replace it with a reviewed HTTPS URL.',
    };
  }

  if (/stores credential material in an MCP configuration/i.test(title)) {
    const assistant = plainClient(item.clients[0] || 'codex');
    return {
      label,
      title: `${assistant} stores credentials directly in an MCP configuration`,
      why: 'Plaintext configuration values may be readable through local file access, backups, or diagnostic output.',
      recommendation: 'Reference a protected environment variable or operating-system credential store instead.',
    };
  }

  if (/unpinned package at startup/i.test(title)) {
    return {
      label,
      title: 'An MCP server can execute an unpinned package at startup',
      why: 'The package version is not fixed, so different code may run without a configuration change.',
      recommendation: 'Pin the package to an exact reviewed version and preserve its lockfile or integrity value.',
    };
  }

  if (/unclassified tools appear state-changing/i.test(title)) {
    return {
      label,
      title: 'Some unclassified tools appear state-changing',
      why: 'Their names suggest execution or administrative behavior, but no reviewed classification rule matched them.',
      recommendation: 'Manually classify these tools before leaving them exposed to an agent.',
    };
  }

  return {
    label,
    title,
    why: item.why,
    recommendation: item.recommendation,
  };
}
