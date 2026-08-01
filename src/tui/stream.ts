export interface StreamTerminalTextOptions {
  sleep?: (milliseconds: number) => Promise<void>;
  write?: (chunk: string) => void;
}

const ANSI_SEQUENCE = /^\u001B\[[0-?]*[ -/]*[@-~]$/u;
const TOKEN_PATTERN = /\u001B\[[0-?]*[ -/]*[@-~]|\s+|[^\s]+/gu;
const ANSI_GLOBAL = /\u001B\[[0-?]*[ -/]*[@-~]/gu;
const BURST_SIZES = [3, 4, 2, 5];
const BURST_DELAYS_MS = [12, 18, 9, 15];

const wait = (milliseconds: number): Promise<void> => new Promise((resolve) => {
  setTimeout(resolve, milliseconds);
});

function isVisibleToken(token: string): boolean {
  return !ANSI_SEQUENCE.test(token) && !/^\s+$/u.test(token);
}

function isSectionHeading(line: string): boolean {
  const visible = line.replace(ANSI_GLOBAL, '');
  return visible.length > 0
    && visible.length <= 48
    && !/^\s/u.test(visible)
    && !/[.!?:]$/u.test(visible)
    && !/^[-+◆▲✓!\d]/u.test(visible);
}

export async function streamTerminalText(
  value: string,
  options: StreamTerminalTextOptions = {},
): Promise<void> {
  const sleep = options.sleep || wait;
  const write = options.write || ((chunk: string) => { process.stdout.write(chunk); });
  const lines = value.split('\n');
  let burstIndex = 0;

  for (const [lineIndex, line] of lines.entries()) {
    const tokens = line.match(TOKEN_PATTERN) || [];
    let buffer = '';
    let visibleTokens = 0;

    for (const token of tokens) {
      buffer += token;
      if (!isVisibleToken(token)) continue;
      visibleTokens += 1;
      const burstSize = BURST_SIZES[burstIndex % BURST_SIZES.length] || 3;
      if (visibleTokens < burstSize) continue;

      write(buffer);
      buffer = '';
      visibleTokens = 0;
      await sleep(BURST_DELAYS_MS[burstIndex % BURST_DELAYS_MS.length] || 12);
      burstIndex += 1;
    }

    if (buffer) write(buffer);
    if (lineIndex < lines.length - 1) write('\n');

    const visibleLine = line.replace(ANSI_GLOBAL, '');
    if (visibleLine.length === 0) await sleep(65);
    else if (isSectionHeading(line)) await sleep(170);
    else if (/[.!?]$/u.test(visibleLine)) await sleep(35);
  }
}
