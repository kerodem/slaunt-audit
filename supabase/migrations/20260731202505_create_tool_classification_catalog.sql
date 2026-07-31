-- Public, read-only classification catalog consumed by `npx slaunt audit`.
-- The CLI downloads approved rules and performs all matching locally. Audit
-- payloads are never sent to this table or any RPC.

create table public.tool_classification_catalog (
  id text primary key,
  namespace text,
  tool_pattern text not null,
  description_terms text[] not null default '{}',
  category text not null,
  capabilities text[] not null,
  risk_score smallint not null,
  risk_level text not null,
  sensitive boolean not null default true,
  verified boolean not null default false,
  rationale text not null,
  priority integer not null default 0,
  active boolean not null default false,
  review_status text not null default 'draft',
  source_ref text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint tool_classification_namespace_length check (namespace is null or char_length(namespace) between 1 and 200),
  constraint tool_classification_pattern_length check (char_length(tool_pattern) between 1 and 200),
  constraint tool_classification_category_length check (char_length(category) between 1 and 100),
  constraint tool_classification_rationale_length check (char_length(rationale) between 1 and 500),
  constraint tool_classification_description_terms_count check (cardinality(description_terms) <= 20),
  constraint tool_classification_capabilities_count check (cardinality(capabilities) between 1 and 20),
  constraint tool_classification_risk_score check (risk_score between 0 and 100),
  constraint tool_classification_risk_level check (risk_level in ('critical', 'high', 'medium', 'low', 'info')),
  constraint tool_classification_review_status check (review_status in ('draft', 'in_review', 'approved', 'rejected')),
  constraint tool_classification_activation_requires_approval check (not active or review_status = 'approved'),
  constraint tool_classification_known_capabilities check (
    capabilities <@ array[
      'read-data', 'write-data', 'read-files', 'write-files', 'delete-data',
      'execute-code', 'execute-shell', 'read-secrets', 'manage-auth',
      'network-access', 'deploy-production', 'edit-code', 'create-pull-request',
      'merge-pull-request', 'administer-system', 'control-browser', 'send-message'
    ]::text[]
  )
);

create unique index tool_classification_match_identity
  on public.tool_classification_catalog (coalesce(namespace, '*'), tool_pattern, category);
create index tool_classification_public_catalog_order
  on public.tool_classification_catalog (active, review_status, priority desc)
  where active and review_status = 'approved';

alter table public.tool_classification_catalog enable row level security;
alter table public.tool_classification_catalog force row level security;

revoke all on table public.tool_classification_catalog from public;
revoke all on table public.tool_classification_catalog from anon;
revoke all on table public.tool_classification_catalog from authenticated;
grant usage on schema public to anon, authenticated;
grant select (
  id, namespace, tool_pattern, description_terms, category, capabilities,
  risk_score, risk_level, sensitive, verified, rationale, priority, active
) on public.tool_classification_catalog to anon, authenticated;

create policy "approved catalog rules are publicly readable"
  on public.tool_classification_catalog
  for select
  to anon, authenticated
  using (active and review_status = 'approved');

comment on table public.tool_classification_catalog is
  'Approved MCP tool classification rules. Public roles are read-only and can see approved active rows only.';
comment on column public.tool_classification_catalog.tool_pattern is
  'A bounded glob pattern interpreted locally by the Slaunt audit CLI. It is never executed as database regex.';

insert into public.tool_classification_catalog (
  id, namespace, tool_pattern, description_terms, category, capabilities,
  risk_score, risk_level, sensitive, verified, rationale, priority,
  active, review_status, source_ref
)
values
  ('deploy-production', null, '*deploy*', array['deploy','production'], 'Deployment', array['deploy-production','write-data','network-access'], 96, 'critical', true, true, 'Can change a deployed production environment.', 100, true, 'approved', 'builtin:v1'),
  ('shell-exec-command', null, '*exec*command*', '{}', 'Shell', array['execute-shell','execute-code','read-files','write-files'], 90, 'high', true, true, 'Can execute arbitrary operating-system commands.', 95, true, 'approved', 'builtin:v1'),
  ('shell-run-command', '*shell*', '*run*command*', '{}', 'Shell', array['execute-shell','execute-code','read-files','write-files'], 90, 'high', true, true, 'Can execute commands through a shell-capable server.', 94, true, 'approved', 'builtin:v1'),
  ('secrets-read', '*secret*', '*', '{}', 'Secrets', array['read-secrets'], 88, 'high', true, true, 'Can read or enumerate credential material.', 92, true, 'approved', 'builtin:v1'),
  ('github-merge', '*github*', '*merge*pull*request*', '{}', 'Source control', array['merge-pull-request','edit-code','write-data'], 86, 'high', true, true, 'Can merge changes into a repository branch.', 90, true, 'approved', 'builtin:v1'),
  ('github-delete', '*github*', '*delete*', '{}', 'Source control', array['delete-data','edit-code','write-data'], 86, 'high', true, true, 'Can delete repository content or references.', 89, true, 'approved', 'builtin:v1'),
  ('github-update-file', '*github*', '*update*file*', '{}', 'Source control', array['edit-code','write-data'], 75, 'high', true, true, 'Can edit source-controlled files.', 85, true, 'approved', 'builtin:v1'),
  ('github-create-file', '*github*', '*create*file*', '{}', 'Source control', array['edit-code','write-data'], 75, 'high', true, true, 'Can create source-controlled files.', 85, true, 'approved', 'builtin:v1'),
  ('github-create-pr', '*github*', '*create*pull*request*', '{}', 'Source control', array['create-pull-request','write-data'], 65, 'medium', true, true, 'Can create pull requests visible to collaborators.', 82, true, 'approved', 'builtin:v1'),
  ('filesystem-delete', '*file*', '*delete*', '{}', 'Filesystem', array['delete-data','write-files'], 84, 'high', true, true, 'Can remove local files.', 88, true, 'approved', 'builtin:v1'),
  ('filesystem-write', '*file*', '*write*', '{}', 'Filesystem', array['write-files'], 70, 'high', true, true, 'Can write local files.', 80, true, 'approved', 'builtin:v1'),
  ('filesystem-edit', '*file*', '*edit*', '{}', 'Filesystem', array['write-files'], 70, 'high', true, true, 'Can modify local files.', 80, true, 'approved', 'builtin:v1'),
  ('filesystem-read', '*file*', '*read*', '{}', 'Filesystem', array['read-files'], 45, 'medium', true, true, 'Can read local files that may contain sensitive data.', 70, true, 'approved', 'builtin:v1'),
  ('database-execute-sql', null, '*execute*sql*', '{}', 'Database', array['read-data','write-data','delete-data'], 85, 'high', true, true, 'Can execute SQL that may read or modify database state.', 86, true, 'approved', 'builtin:v1'),
  ('browser-control', '*browser*', '*', '{}', 'Browser automation', array['control-browser','network-access'], 62, 'medium', true, true, 'Can interact with websites using the user browser context.', 68, true, 'approved', 'builtin:v1'),
  ('computer-control', '*computer*', '*', '{}', 'Computer control', array['execute-code','control-browser'], 82, 'high', true, true, 'Can control local applications or the desktop.', 72, true, 'approved', 'builtin:v1'),
  ('message-send', null, '*send*message*', '{}', 'Communications', array['send-message','write-data','network-access'], 66, 'medium', true, true, 'Can communicate externally as the configured user.', 67, true, 'approved', 'builtin:v1'),
  ('generic-list', null, '*list*', '{}', 'Read-only data', array['read-data'], 22, 'low', false, false, 'Appears to list data without changing state.', 20, true, 'approved', 'builtin:v1'),
  ('generic-get', null, '*get*', '{}', 'Read-only data', array['read-data'], 22, 'low', false, false, 'Appears to retrieve data without changing state.', 20, true, 'approved', 'builtin:v1'),
  ('generic-search', null, '*search*', '{}', 'Read-only data', array['read-data'], 25, 'low', false, false, 'Appears to search data without changing state.', 20, true, 'approved', 'builtin:v1');
