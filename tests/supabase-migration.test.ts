import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

describe('Supabase catalog security', () => {
  it('ships a read-only, RLS-forced public catalog migration', async () => {
    const sql = await readFile('supabase/migrations/20260731202505_create_tool_classification_catalog.sql', 'utf8');
    expect(sql).toMatch(/enable row level security/i);
    expect(sql).toMatch(/force row level security/i);
    expect(sql).toMatch(/for select\s+to anon, authenticated/i);
    expect(sql).toMatch(/grant select \(/i);
    expect(sql).not.toMatch(/grant\s+(insert|update|delete|all).*\b(anon|authenticated)\b/i);
    expect(sql).not.toMatch(/security\s+definer/i);
    expect(sql).toMatch(/not active or review_status = 'approved'/i);
  });

  it('restricts local database listeners and disables unused services', async () => {
    const config = await readFile('supabase/config.toml', 'utf8');
    expect(config).toContain('allowed_cidrs = ["127.0.0.1/32"]');
    expect(config).toContain('allowed_cidrs_v6 = ["::1/128"]');
    expect(config).toMatch(/\[db\.ssl_enforcement\]\nenabled = true/);
    expect(config).toMatch(/\[auth\]\nenabled = false/);
    expect(config).toMatch(/\[realtime\]\nenabled = false/);
  });
});
