export type ClientId = 'claude-code' | 'claude-desktop' | 'codex';
export type TransportKind = 'stdio' | 'http' | 'sse' | 'unknown';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ClassificationSource = 'database' | 'built-in' | 'heuristic' | 'unknown';

export type Capability =
  | 'read-data'
  | 'write-data'
  | 'read-files'
  | 'write-files'
  | 'delete-data'
  | 'execute-code'
  | 'execute-shell'
  | 'read-secrets'
  | 'manage-auth'
  | 'network-access'
  | 'deploy-production'
  | 'edit-code'
  | 'create-pull-request'
  | 'merge-pull-request'
  | 'administer-system'
  | 'control-browser'
  | 'send-message';

export interface ClientDetection {
  id: ClientId;
  label: string;
  detected: boolean;
  sources: string[];
}

export interface ServerConfig {
  id: string;
  client: ClientId;
  clientLabel: string;
  name: string;
  transport: TransportKind;
  sourcePath: string;
  scope: 'user' | 'project' | 'desktop' | 'custom';
  command?: string;
  args: string[];
  env: Record<string, string>;
  envKeys: string[];
  url?: string;
  headers: Record<string, string>;
  headerKeys: string[];
  enabled: boolean;
}

export interface DiscoveredConfiguration {
  clients: ClientDetection[];
  servers: ServerConfig[];
  warnings: string[];
}

export interface DeclaredTool {
  serverId: string;
  serverName: string;
  client: ClientId;
  clientLabel: string;
  name: string;
  description: string;
  inputSchema?: Record<string, unknown>;
}

export interface ServerProbe {
  serverId: string;
  status: 'ok' | 'skipped' | 'failed';
  tools: DeclaredTool[];
  message?: string;
}

export interface ClassificationRule {
  id: string;
  namespace?: string;
  toolPattern: string;
  descriptionTerms?: string[];
  category: string;
  capabilities: Capability[];
  riskScore: number;
  riskLevel: Severity;
  sensitive: boolean;
  verified: boolean;
  rationale: string;
  priority: number;
}

export interface ClassifiedTool extends DeclaredTool {
  classification: {
    ruleId?: string;
    category: string;
    capabilities: Capability[];
    riskScore: number;
    riskLevel: Severity;
    sensitive: boolean;
    verified: boolean;
    rationale: string;
    source: ClassificationSource;
  };
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  serverNames: string[];
  toolNames: string[];
  access: string[];
  why: string;
  recommendation: string;
  clients: ClientId[];
}

export interface AuditSummary {
  clientsDetected: number;
  servers: number;
  tools: number;
  classified: number;
  sensitiveCapabilities: number;
  highRiskFindings: number;
  unclassified: number;
  postureScore: number;
}

export interface AuditResult {
  schemaVersion: 1;
  generatedAt: string;
  privacy: {
    uploadedAuditData: false;
    catalogSource: 'database' | 'cache' | 'built-in';
    startedConfiguredServers: boolean;
  };
  discovery: DiscoveredConfiguration;
  probes: ServerProbe[];
  tools: ClassifiedTool[];
  findings: Finding[];
  summary: AuditSummary;
  reportPath?: string;
}

export interface InstallChange {
  client: ClientId;
  path: string;
  status: 'installed' | 'already-present' | 'skipped' | 'failed';
  backupPath?: string;
  message?: string;
}
