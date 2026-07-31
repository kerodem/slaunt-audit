import type { Capability, ClientId, Finding, Severity } from '../types.js';

export interface PlainFinding {
  label: string;
  title: string;
  why: string;
  recommendation: string;
}

const severityLabels: Record<Severity, string> = {
  critical: 'Urgent',
  high: 'High priority',
  medium: 'Review',
  low: 'Low priority',
  info: 'For your information',
};

const capabilityLabels: Record<Capability, string> = {
  'read-data': 'Read data',
  'write-data': 'Change data',
  'read-files': 'Read files',
  'write-files': 'Change files',
  'delete-data': 'Delete data',
  'execute-code': 'Run code',
  'execute-shell': 'Run commands',
  'read-secrets': 'Read saved credentials',
  'manage-auth': 'Manage sign-in',
  'network-access': 'Connect to the internet',
  'deploy-production': 'Publish live changes',
  'edit-code': 'Edit code',
  'create-pull-request': 'Propose code changes',
  'merge-pull-request': 'Approve and merge code',
  'administer-system': 'Manage system settings',
  'control-browser': 'Control a browser',
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
      title: `${assistant} can publish changes to a live service without approval`,
      why: 'This could change what customers see before a person has reviewed it.',
      recommendation: 'Require a person to approve live releases and limit which environments this assistant can change.',
    };
  }

  if (/execute shell commands and access secrets/i.test(title)) {
    const assistant = plainClient(item.clients[0] || 'codex');
    return {
      label,
      title: `${assistant} can combine saved credentials with command access`,
      why: 'Together, these permissions could expose or misuse passwords, tokens, or other credentials.',
      recommendation: 'Keep credential access separate from command access, or require approval before either can be used.',
    };
  }

  if (/share broad GitHub permissions/i.test(title)) {
    return {
      label,
      title: 'Multiple AI assistants share powerful GitHub access',
      why: 'Shared access makes it harder to control what each assistant can change or to tell which one made a change.',
      recommendation: 'Give each assistant its own GitHub access, limited to the work it needs to do.',
    };
  }

  if (/cleartext HTTP/i.test(title)) {
    const assistant = plainClient(item.clients[0] || 'codex');
    return {
      label,
      title: `${assistant} connects to a service without encryption`,
      why: 'Someone on the network could read or change information sent through this connection.',
      recommendation: 'Use a secure HTTPS connection with certificate checking before enabling this service.',
    };
  }

  if (/invalid MCP server URL/i.test(title)) {
    const assistant = plainClient(item.clients[0] || 'codex');
    return {
      label,
      title: `${assistant} has a connection address that cannot be checked safely`,
      why: 'Slaunt cannot reliably determine where this connection sends information.',
      recommendation: 'Replace it with a reviewed HTTPS address.',
    };
  }

  if (/stores credential material in an MCP configuration/i.test(title)) {
    const assistant = plainClient(item.clients[0] || 'codex');
    return {
      label,
      title: `${assistant} stores a credential directly in its settings`,
      why: 'Other programs, backups, or people with access to this computer may be able to read it.',
      recommendation: 'Move the credential to a protected environment variable or the operating system credential store.',
    };
  }

  if (/unpinned package at startup/i.test(title)) {
    return {
      label,
      title: 'A connected service can change when it starts',
      why: 'It downloads a package without locking it to one reviewed version.',
      recommendation: 'Lock the package to an exact reviewed version.',
    };
  }

  if (/unclassified tools appear state-changing/i.test(title)) {
    return {
      label,
      title: 'Some unfamiliar actions may make changes',
      why: 'Their names suggest they can run jobs, change data, or use administrator access, but Slaunt does not recognize them yet.',
      recommendation: 'Have a person review these actions before leaving them available to an AI assistant.',
    };
  }

  return {
    label,
    title: title.replaceAll('MCP', 'connected').replaceAll('agent', 'AI assistant'),
    why: item.why,
    recommendation: item.recommendation,
  };
}
