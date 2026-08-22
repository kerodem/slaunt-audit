import { describe, expect, it } from 'vitest';
import { sanitizeCommandArgs } from '../src/privacy/redaction.js';

describe('stdio command argument redaction', () => {
  it('redacts values for sensitive flags while preserving safe arguments', () => {
    expect(sanitizeCommandArgs([
      '--token', 'token-value',
      '--secret', 'secret-value',
      '--password', 'password-value',
      '--key', 'key-value',
      '--auth', 'auth-value',
      '--mode', 'read-only',
    ])).toEqual([
      '--token', '[redacted]',
      '--secret', '[redacted]',
      '--password', '[redacted]',
      '--key', '[redacted]',
      '--auth', '[redacted]',
      '--mode', 'read-only',
    ]);
  });

  it('redacts sensitive inline assignments, including nested environment assignments', () => {
    expect(sanitizeCommandArgs([
      '--api-key=key-value',
      'AUTH_TOKEN=token-value',
      '--env=DB_PASSWORD=password-value',
      '--url=https://example.test/mcp?access_token=query-value&mode=read-only',
      '--header', 'Authorization: Bearer header-secret',
      '-H', 'X-Api-Key: api-key-secret',
    ])).toEqual([
      '--api-key=[redacted]',
      'AUTH_TOKEN=[redacted]',
      '--env=DB_PASSWORD=[redacted]',
      '--url=https://example.test/mcp?access_token=[redacted]&mode=read-only',
      '--header', 'Authorization: [redacted]',
      '-H', 'X-Api-Key: [redacted]',
    ]);
  });
});
