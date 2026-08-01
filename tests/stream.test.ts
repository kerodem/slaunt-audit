import { describe, expect, it } from 'vitest';
import { streamTerminalText } from '../src/tui/stream.js';

describe('progressive terminal reveal', () => {
  it('streams ANSI-formatted output in token-like bursts without changing it', async () => {
    const output = [
      '\u001B[1mAudit complete\u001B[22m',
      '',
      '◆ CRITICAL  Claude Code can deploy to production without approval',
      '  MCP server: railway',
      '  Why this matters: The tool can change the live environment.',
      '',
    ].join('\n');
    const chunks: string[] = [];
    const delays: number[] = [];

    await streamTerminalText(output, {
      sleep: async (milliseconds) => { delays.push(milliseconds); },
      write: (chunk) => { chunks.push(chunk); },
    });

    expect(chunks.join('')).toBe(output);
    expect(chunks.length).toBeGreaterThan(10);
    expect(delays.length).toBeGreaterThan(8);
    expect(delays.reduce((total, delay) => total + delay, 0)).toBeGreaterThan(300);
    expect(Math.max(...delays)).toBeLessThanOrEqual(170);
  });
});
