import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadCatalog } from '../src/classification/catalog.js';
import { PUBLIC_CATALOG_KEY, PUBLIC_CATALOG_URL } from '../src/classification/public-catalog-config.js';

const row = {
  id: 'reviewed-rule',
  namespace: 'github',
  tool_pattern: 'list_repositories',
  description_terms: [],
  category: 'Repository inventory',
  capabilities: ['read-data'],
  risk_score: 18,
  risk_level: 'low',
  sensitive: false,
  verified: true,
  rationale: 'Reviewed exact match.',
  priority: 100,
};

describe('Supabase catalog client', () => {
  let auditHome: string;
  const originalFetch = globalThis.fetch;
  const originalEnvironment = { ...process.env };

  beforeEach(async () => {
    auditHome = await mkdtemp(join(tmpdir(), 'slaunt-catalog-test-'));
    process.env = { ...originalEnvironment, SLAUNT_AUDIT_HOME: auditHome };
    delete process.env.SLAUNT_SUPABASE_URL;
    delete process.env.SLAUNT_SUPABASE_PUBLISHABLE_KEY;
    delete process.env.SLAUNT_SUPABASE_ANON_KEY;
  });

  afterEach(async () => {
    globalThis.fetch = originalFetch;
    process.env = { ...originalEnvironment };
    await rm(auditHome, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('uses the zero-configuration public catalog without sending audit data', async () => {
    let requestedInput: RequestInfo | URL | undefined;
    let requestedInit: RequestInit | undefined;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requestedInput = input;
      requestedInit = init;
      return new Response(JSON.stringify([row]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    globalThis.fetch = fetchMock as typeof fetch;

    const result = await loadCatalog();

    expect(result.source).toBe('database');
    expect(result.rules[0]?.id).toBe('db:reviewed-rule');
    expect(fetchMock).toHaveBeenCalledOnce();
    const endpoint = new URL(String(requestedInput));
    expect(endpoint.origin).toBe(PUBLIC_CATALOG_URL);
    expect(endpoint.pathname).toBe('/rest/v1/tool_classification_catalog');
    expect([...endpoint.searchParams.keys()].sort()).toEqual(['active', 'limit', 'order', 'select']);
    expect(requestedInit?.method).toBeUndefined();
    expect(requestedInit?.body).toBeUndefined();
    expect(requestedInit?.redirect).toBe('error');
    expect(requestedInit?.headers).toEqual({ apikey: PUBLIC_CATALOG_KEY, accept: 'application/json' });
  });

  it('refuses a secret key before making a network request', async () => {
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock;
    process.env.SLAUNT_SUPABASE_PUBLISHABLE_KEY = 'sb_secret_not-permitted-in-this-client';

    const result = await loadCatalog();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(result.source).toBe('built-in');
    expect(result.warning).toMatch(/refusing to use a Supabase secret key/i);
  });

  it('does not contact Supabase in offline mode', async () => {
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock;

    const result = await loadCatalog({ offline: true });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(result.source).toBe('built-in');
  });
});
