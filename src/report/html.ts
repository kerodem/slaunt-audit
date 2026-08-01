import { randomBytes } from 'node:crypto';
import { access, link, mkdir, unlink, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { AuditResult } from '../types.js';
import { plainCapability, plainClient, plainFinding } from '../presentation/plain-language.js';

function escapeHtml(value: unknown): string {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function accessOverview(result: AuditResult): string {
  return result.discovery.clients.filter((client) => client.detected).map((client) => {
    const servers = result.discovery.servers.filter((server) => server.client === client.id);
    const rows = servers.map((server) => {
      const capabilities = [...new Set(result.tools
        .filter((tool) => tool.serverId === server.id)
        .flatMap((tool) => tool.classification.capabilities))];
      return `<tr><td>${escapeHtml(server.name)}</td><td>${escapeHtml(capabilities.map(plainCapability).join(', ') || 'Permissions could not be read')}</td></tr>`;
    }).join('');
    return `<section class="client"><h3>${escapeHtml(client.label)}</h3><table><tbody>${rows}</tbody></table></section>`;
  }).join('');
}

export function renderHtmlReport(result: AuditResult): string {
  const summary = result.summary;
  const findings = result.findings.map((item) => {
    const copy = plainFinding(item);
    const assistants = item.clients.map(plainClient).join(', ');
    return `
    <article class="finding ${escapeHtml(item.severity)}">
      <div class="severity">${escapeHtml(copy.label)}</div>
      <h3>${escapeHtml(copy.title)}</h3>
      ${assistants ? `<p><strong>Agent client:</strong> ${escapeHtml(assistants)}</p>` : ''}
      ${item.serverNames.length ? `<p><strong>MCP server:</strong> ${escapeHtml(item.serverNames.join(', '))}</p>` : ''}
      ${item.toolNames.length ? `<p><strong>Tool:</strong> ${escapeHtml(item.toolNames.join(', '))}</p>` : ''}
      ${item.access.length ? `<p><strong>Capabilities:</strong> ${escapeHtml(item.access.join(', '))}</p>` : ''}
      <p><strong>Why this matters:</strong> ${escapeHtml(copy.why)}</p>
      <p><strong>Recommended control:</strong> ${escapeHtml(copy.recommendation)}</p>
    </article>`;
  }).join('');
  const unknown = result.tools.filter((tool) => tool.classification.source === 'unknown');
  const unavailable = result.probes.filter((probe) => probe.status !== 'ok').length;
  const scoreAvailable = summary.tools > 0 || unavailable === 0;
  const scoreClass = !scoreAvailable ? 'warn' : summary.postureScore >= 80 ? 'good' : summary.postureScore >= 55 ? 'warn' : 'bad';
  const scoreValue = scoreAvailable ? summary.postureScore : 0;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>Slaunt MCP Agent Access Audit</title><style>
:root{color-scheme:light dark;--bg:#0b0d12;--card:#141821;--ink:#f4f6fb;--muted:#9ba6b8;--line:#293142;--accent:#8b5cf6;--critical:#ff4d6d;--high:#ff8a4c;--medium:#f7c948;--low:#48cae4}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#24164a 0,transparent 32%),var(--bg);color:var(--ink);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{width:min(1060px,calc(100% - 32px));margin:0 auto;padding:64px 0 96px}header{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:end;padding-bottom:36px;border-bottom:1px solid var(--line)}.eyebrow{color:#b69cff;text-transform:uppercase;letter-spacing:.14em;font-size:12px;font-weight:800}h1{font-size:clamp(34px,6vw,64px);line-height:1;margin:.18em 0}.sub{color:var(--muted);max-width:640px}.score{width:136px;height:136px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--accent) calc(var(--score)*1%),#252b38 0);position:relative}.score:before{content:"";position:absolute;inset:9px;border-radius:50%;background:var(--card)}.score span{position:relative;font-size:38px;font-weight:850}.score small{display:block;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}.metrics{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:28px 0}.metric{padding:18px;background:color-mix(in srgb,var(--card) 92%,transparent);border:1px solid var(--line);border-radius:14px}.metric b{display:block;font-size:28px}.metric span{color:var(--muted);font-size:12px}h2{margin:52px 0 18px;font-size:24px}.finding{border:1px solid var(--line);border-left-width:4px;border-radius:14px;background:var(--card);padding:22px;margin:14px 0}.finding.critical{border-left-color:var(--critical)}.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}.finding h3{margin:4px 0 12px}.finding p{margin:7px 0;color:#cbd3df}.severity{text-transform:uppercase;letter-spacing:.12em;font-size:11px;font-weight:900}.critical .severity{color:var(--critical)}.high .severity{color:var(--high)}.medium .severity{color:var(--medium)}.low .severity{color:var(--low)}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}.client{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px}.client h3{margin:0 0 12px}table{width:100%;border-collapse:collapse}td{padding:9px 0;border-top:1px solid var(--line);vertical-align:top}td:first-child{font-weight:750;width:32%}td:last-child{color:var(--muted)}code{background:#202635;padding:.15em .38em;border-radius:5px}.notice{padding:18px;border:1px solid #4c3a86;background:#171229;border-radius:14px;color:#d9cffc}.unknown{columns:2;margin:0;padding-left:22px}.unknown li{break-inside:avoid;padding:3px}.cta{margin-top:52px;padding:30px;border-radius:18px;background:linear-gradient(130deg,#5b21b6,#312e81);box-shadow:0 22px 70px #5b21b633}.cta h2{margin:0 0 8px}.cta a{display:inline-block;margin-top:12px;background:white;color:#28145d;text-decoration:none;font-weight:850;padding:11px 16px;border-radius:9px}.fine{font-size:12px;color:var(--muted);margin-top:42px}@media(max-width:800px){header{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.unknown{columns:1}}
</style></head><body><main>
<header><div><div class="eyebrow">Slaunt MCP audit</div><h1>Agent access, explained.</h1><p class="sub">A local audit of MCP servers—the services that expose tools to Claude and Codex. No tool was called and no audit payload was uploaded.</p></div><div class="score ${scoreClass}" style="--score:${scoreValue}"><span>${scoreAvailable ? summary.postureScore : '?'}<small>${scoreAvailable ? 'security posture' : 'insufficient coverage'}</small></span></div></header>
<section class="metrics">
<div class="metric"><b>${summary.clientsDetected}</b><span>Agent clients</span></div><div class="metric"><b>${summary.servers}</b><span>MCP servers</span></div><div class="metric"><b>${summary.tools}</b><span>Tools exposed</span></div><div class="metric"><b>${summary.sensitiveCapabilities}</b><span>Sensitive tools</span></div><div class="metric"><b>${summary.highRiskFindings}</b><span>High-risk findings</span></div><div class="metric"><b>${summary.unclassified}</b><span>Unclassified tools</span></div>
</section>
<div class="notice">Classification source: <strong>${escapeHtml(result.privacy.catalogSource)}</strong>. Tool names, descriptions, schemas, configuration values, and findings stayed on this machine.</div>
<h2>High-priority findings</h2>${findings || '<p>No correlated high-risk access paths were identified from the available tool declarations.</p>'}
<h2>Access overview</h2><p>Capabilities describe what each MCP server allows an agent to do.</p><div class="grid">${accessOverview(result)}</div>
<h2>Classification coverage</h2><p><strong>${summary.classified}</strong> tools matched a reviewed catalog rule. <strong>${summary.unclassified}</strong> did not match and require manual review.</p>
${unknown.length ? `<ul class="unknown">${unknown.map((tool) => `<li><code>${escapeHtml(tool.name)}</code> <span>(${escapeHtml(tool.serverName)})</span></li>`).join('')}</ul>` : '<p>Every retrieved tool matched a reviewed classification rule.</p>'}
<section class="cta"><h2>Apply controls to the access paths you found.</h2><p>Slaunt can add role-scoped capabilities, approval policies, continuous monitoring, and remote shutdown around the MCP servers you already use. You choose when to connect.</p><a href="https://slaunt.ai/setup">Set up Slaunt →</a></section>
<p class="fine">Scope: configured MCP servers and their declared tools. This audit did not call tools or inspect prompts, file contents, credentials, non-MCP agents, or tool-use history. Generated ${escapeHtml(result.generatedAt)}.</p>
</main></body></html>`;
}

export async function writeHtmlReport(result: AuditResult, outputPath?: string): Promise<string> {
  const date = result.generatedAt.slice(0, 10);
  const requested = resolve(outputPath || `slaunt-audit-${date}.html`);
  let path = requested;
  if (outputPath) {
    await access(path).then(
      () => { throw new Error(`refusing to overwrite existing report: ${path}`); },
      () => undefined,
    );
  } else {
    for (let suffix = 2; suffix < 1_000; suffix += 1) {
      try {
        await access(path);
        path = resolve(`slaunt-audit-${date}-${suffix}.html`);
      } catch {
        break;
      }
    }
  }
  const temporary = `${path}.${randomBytes(10).toString('hex')}.tmp`;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  try {
    await writeFile(temporary, renderHtmlReport(result), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await link(temporary, path);
  } finally {
    await unlink(temporary).catch(() => undefined);
  }
  return path;
}
