const SENSITIVE_NAME = /(?:token|secret|password|passwd|pass|key|auth|authorization|credential)/iu;
const SENSITIVE_HEADER = /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\s*:/iu;

function hasSensitiveName(value: string): boolean {
  return SENSITIVE_NAME.test(value);
}

function redactInlineAssignments(value: string): string {
  const assignment = /(^|[?&\s=])(-{0,2}[A-Za-z][A-Za-z0-9_.-]*)\s*=\s*([^&\s]*)/gu;
  return value.replace(assignment, (match, prefix: string, key: string, assignedValue: string) => {
    if (hasSensitiveName(key)) return `${prefix}${key}=[redacted]`;
    if (!assignedValue.includes('=')) return match;
    const nested = redactInlineAssignments(assignedValue);
    return nested === assignedValue ? match : `${prefix}${key}=${nested}`;
  });
}

function redactEmbeddedCredentials(value: string): string {
  return redactInlineAssignments(value)
    .replace(/\b(Bearer|Basic|Token)\s+[^\s,;]+/giu, '$1 [redacted]')
    .replace(/(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\s*:\s*[^\s,;]+/giu, '$1: [redacted]');
}

function isSensitiveFlag(value: string): boolean {
  const match = /^-{1,2}([^=]+)(?:=.*)?$/u.exec(value);
  return Boolean(match && hasSensitiveName(match[1] || ''));
}

export function sanitizeCommandArgs(args: string[]): string[] {
  const sanitized: string[] = [];
  let redactNext = false;
  let inspectNextHeader = false;

  for (const arg of args) {
    if (redactNext) {
      sanitized.push('[redacted]');
      redactNext = false;
      continue;
    }

    if (inspectNextHeader) {
      sanitized.push(SENSITIVE_HEADER.test(arg) ? `${arg.split(':', 1)[0]}: [redacted]` : redactEmbeddedCredentials(arg));
      inspectNextHeader = false;
      continue;
    }

    const redacted = redactEmbeddedCredentials(arg);
    sanitized.push(redacted);
    if (isSensitiveFlag(arg) && !arg.includes('=')) redactNext = true;
    if (/^(?:--header|-H)$/iu.test(arg)) inspectNextHeader = true;
  }

  return sanitized;
}
