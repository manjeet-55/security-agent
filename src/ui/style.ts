export interface Style {
  enabled: boolean;
  red(s: string): string;
  yellow(s: string): string;
  green(s: string): string;
  cyan(s: string): string;
  dim(s: string): string;
  bold(s: string): string;
}

export const SYMBOL = { pass: '✓', fail: '✗', unverifiable: '?', error: '!', pointer: '›', on: '◉', off: '○' } as const;

/** ANSI colours for a terminal; plain text when the stream is not a terminal or NO_COLOR is set (https://no-color.org). */
export function createStyle(stream: { isTTY?: boolean }, env: NodeJS.ProcessEnv = process.env): Style {
  const enabled = stream.isTTY === true && !env.NO_COLOR;
  const wrap = (open: number, close: number) => (s: string) => (enabled ? `\u001b[${open}m${s}\u001b[${close}m` : s);
  return { enabled, red: wrap(31, 39), yellow: wrap(33, 39), green: wrap(32, 39), cyan: wrap(36, 39), dim: wrap(2, 22), bold: wrap(1, 22) };
}
