import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { z } from 'zod';
import type { Capability, ClassificationRule } from '../types.js';
import { BUILTIN_CATALOG } from './builtin-catalog.js';

const capabilities = [
  'read-data', 'write-data', 'read-files', 'write-files', 'delete-data', 'execute-code',
  'execute-shell', 'read-secrets', 'manage-auth', 'network-access', 'deploy-production',
  'edit-code', 'create-pull-request', 'merge-pull-request', 'administer-system',
  'control-browser', 'send-message',
] as const satisfies readonly Capability[];

const databaseRowSchema = z.object({
  id: z.union([z.string(), z.number()]).transform(String),
  namespace: z.string().max(200).nullable().optional(),
  tool_pattern: z.string().min(1).max(200),
  description_terms: z.array(z.string().min(1).max(100)).max(20).default([]),
  category: z.string().min(1).max(100),
  capabilities: z.array(z.enum(capabilities)).max(20),
  risk_score: z.number().int().min(0).max(100),
  risk_level: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  sensitive: z.boolean(),
  verified: z.boolean(),
  rationale: z.string().min(1).max(500),
  priority: z.number().int().min(0).max(1000),
});

const cacheSchema = z.object({
  fetchedAt: z.string(),
  rules: z.array(databaseRowSchema).max(10_000),
});

function cachePath(): string {
  const home = process.env.SLAUNT_AUDIT_HOME || process.env.HOME || process.cwd();
  return resolve(process.env.SLAUNT_AUDIT_CACHE || join(home, '.cache', 'slaunt', 'catalog-v1.json'));
}

function mapRule(row: z.infer<typeof databaseRowSchema>): ClassificationRule {
  return {
    id: `db:${row.id}`,
    ...(row.namespace ? { namespace: row.namespace } : {}),
    toolPattern: row.tool_pattern,
    ...(row.description_terms.length > 0 ? { descriptionTerms: row.description_terms } : {}),
    category: row.category,
    capabilities: row.capabilities,
    riskScore: row.risk_score,
    riskLevel: row.risk_level,
    sensitive: row.sensitive,
    verified: row.verified,
    rationale: row.rationale,
    priority: row.priority + 1_000,
  };
}

async function readCache(): Promise<ClassificationRule[] | undefined> {
  try {
    const raw = await readFile(cachePath(), 'utf8');
    const parsed = cacheSchema.parse(JSON.parse(raw));
    const age = Date.now() - Date.parse(parsed.fetchedAt);
    if (!Number.isFinite(age) || age > 7 * 24 * 60 * 60 * 1000) return undefined;
    return parsed.rules.map(mapRule);
  } catch {
    return undefined;
  }
}

async function writeCache(rows: z.infer<typeof databaseRowSchema>[]): Promise<void> {
  const path = cachePath();
  const temporary = join(dirname(path), `.${randomBytes(12).toString('hex')}.tmp`);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(temporary, `${JSON.stringify({ fetchedAt: new Date().toISOString(), rules: rows })}\n`, {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx',
  });
  await rename(temporary, path);
}

function validatedSupabaseUrl(raw: string): URL {
  const url = new URL(raw);
  const local = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
  if (url.username || url.password || url.hash || (url.protocol !== 'https:' && !(local && url.protocol === 'http:'))) {
    throw new Error('Supabase URL must be credential-free HTTPS (or localhost HTTP)');
  }
  return url;
}

async function fetchDatabaseRules(): Promise<z.infer<typeof databaseRowSchema>[]> {
  const rawUrl = process.env.SLAUNT_SUPABASE_URL;
  const key = process.env.SLAUNT_SUPABASE_PUBLISHABLE_KEY || process.env.SLAUNT_SUPABASE_ANON_KEY;
  if (!rawUrl || !key) throw new Error('Supabase catalog is not configured');
  const base = validatedSupabaseUrl(rawUrl);
  const endpoint = new URL('/rest/v1/tool_classification_catalog', base);
  endpoint.searchParams.set('select', 'id,namespace,tool_pattern,description_terms,category,capabilities,risk_score,risk_level,sensitive,verified,rationale,priority');
  endpoint.searchParams.set('active', 'eq.true');
  endpoint.searchParams.set('order', 'priority.desc');
  endpoint.searchParams.set('limit', '10000');

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const headers: Record<string, string> = { apikey: key, accept: 'application/json' };
    if (key.split('.').length === 3) headers.authorization = `Bearer ${key}`;
    const response = await fetch(endpoint, { headers, signal: controller.signal, redirect: 'error' });
    if (!response.ok) throw new Error(`catalog request returned HTTP ${response.status}`);
    const body = await response.text();
    if (body.length > 2 * 1024 * 1024) throw new Error('catalog response exceeded 2 MiB');
    return z.array(databaseRowSchema).max(10_000).parse(JSON.parse(body));
  } finally {
    clearTimeout(timeout);
  }
}

export interface CatalogResult {
  rules: ClassificationRule[];
  source: 'database' | 'cache' | 'built-in';
  warning?: string;
}

export async function loadCatalog(options: { offline?: boolean } = {}): Promise<CatalogResult> {
  if (!options.offline && process.env.SLAUNT_SUPABASE_URL) {
    try {
      const rows = await fetchDatabaseRules();
      await writeCache(rows).catch(() => undefined);
      return { rules: [...rows.map(mapRule), ...BUILTIN_CATALOG], source: 'database' };
    } catch (error) {
      const cached = await readCache();
      if (cached) {
        return {
          rules: [...cached, ...BUILTIN_CATALOG],
          source: 'cache',
          warning: error instanceof Error ? error.message : 'database catalog unavailable',
        };
      }
      return {
        rules: BUILTIN_CATALOG,
        source: 'built-in',
        warning: error instanceof Error ? error.message : 'database catalog unavailable',
      };
    }
  }
  const cached = options.offline ? undefined : await readCache();
  return cached
    ? { rules: [...cached, ...BUILTIN_CATALOG], source: 'cache' }
    : { rules: BUILTIN_CATALOG, source: 'built-in' };
}
