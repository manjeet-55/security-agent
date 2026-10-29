import { emitKeypressEvents } from 'node:readline';
import { SYMBOL, type Style } from './style.js';

export interface Choice<T> {
  value: T;
  label: string;
  hint?: string;
}

/** The questions the guided scan asks. The terminal implementation is below; tests script the answers. */
export interface Prompter {
  text(q: { message: string; default?: string; validate?: (value: string) => string | undefined }): Promise<string>;
  confirm(q: { message: string; default?: boolean }): Promise<boolean>;
  select<T>(q: { message: string; choices: readonly Choice<T>[]; default?: T }): Promise<T>;
  multiselect<T>(q: { message: string; choices: readonly Choice<T>[]; initial?: readonly T[]; min?: number }): Promise<T[]>;
  note(text: string): void;
}

/** The person pressed Ctrl+C, or the input ended. */
export class PromptCancelled extends Error {
  constructor() {
    super('cancelled');
    this.name = 'PromptCancelled';
  }
}

type Input = NodeJS.ReadableStream & { isTTY?: boolean; setRawMode?(on: boolean): unknown };

interface Key {
  str: string | undefined;
  name: string | undefined;
  ctrl: boolean;
}

/** Key presses in arrival order, so keys typed before a question is shown are not lost. */
class KeyQueue {
  private readonly keys: Key[] = [];
  private waiting: { resolve: (k: Key) => void; reject: (e: Error) => void } | undefined;
  private ended = false;
  private readonly onKey = (str: string | undefined, key: { name?: string; ctrl?: boolean } | undefined) => {
    this.push({ str, name: key?.name, ctrl: key?.ctrl === true });
  };
  private readonly onEnd = () => {
    this.ended = true;
    this.waiting?.reject(new PromptCancelled());
    this.waiting = undefined;
  };

  constructor(private readonly input: Input) {
    emitKeypressEvents(input);
    input.on('keypress', this.onKey);
    input.on('end', this.onEnd);
  }

  private push(k: Key): void {
    if (this.waiting) {
      const w = this.waiting;
      this.waiting = undefined;
      w.resolve(k);
    } else {
      this.keys.push(k);
    }
  }

  /** The next key; Ctrl+C and the end of input reject with PromptCancelled. */
  async next(): Promise<Key> {
    const k =
      this.keys.shift() ??
      (await new Promise<Key>((resolve, reject) => {
        if (this.ended) reject(new PromptCancelled());
        else this.waiting = { resolve, reject };
      }));
    if (k.ctrl && k.name === 'c') throw new PromptCancelled();
    return k;
  }

  close(): void {
    this.input.off('keypress', this.onKey);
    this.input.off('end', this.onEnd);
    this.input.pause();
  }
}

const isEnter = (k: Key) => k.name === 'return' || k.name === 'enter';

/**
 * Prompts on a terminal with no dependencies: line editing for text, arrow keys and space for choices (raw mode), a numbered list
 * when raw mode is not available. Raw mode and the cursor are restored on every exit path, Ctrl+C included.
 */
export function createTtyPrompter(input: Input, output: NodeJS.WritableStream, style: Style): Prompter & { close(): void } {
  const keys = new KeyQueue(input);
  const raw = typeof input.setRawMode === 'function';
  const write = (s: string) => {
    output.write(s);
  };
  const ask = (message: string, suffix = '') => `${style.cyan('?')} ${style.bold(message)}${suffix ? ` ${style.dim(suffix)}` : ''} ${style.dim(SYMBOL.pointer)} `;

  async function withRaw<T>(fn: () => Promise<T>): Promise<T> {
    if (raw) input.setRawMode?.(true);
    try {
      return await fn();
    } finally {
      if (raw) input.setRawMode?.(false);
    }
  }

  /** One edited line, echoed as typed. */
  async function readLine(): Promise<string> {
    let buffer = '';
    for (;;) {
      const k = await keys.next();
      if (isEnter(k)) {
        write('\n');
        return buffer;
      }
      if (k.name === 'backspace') {
        if (buffer.length > 0) {
          buffer = buffer.slice(0, -1);
          write('\b \b');
        }
      } else if (k.str && !k.ctrl && k.str >= ' ' && k.str !== '\u007f') {
        buffer += k.str;
        write(k.str);
      }
    }
  }

  async function text(q: { message: string; default?: string; validate?: (value: string) => string | undefined }): Promise<string> {
    return withRaw(async () => {
      for (;;) {
        write(ask(q.message, q.default ? `(${q.default})` : ''));
        const typed = (await readLine()).trim();
        const value = typed === '' ? (q.default ?? '') : typed;
        const error = q.validate?.(value);
        if (error === undefined) return value;
        write(`  ${style.red(error)}\n`);
      }
    });
  }

  /** Draws a block of lines, replacing the block drawn before it. */
  function redrawer(): (lines: string[]) => void {
    let drawn = 0;
    return (lines) => {
      if (drawn > 0) write(`\u001b[${drawn}A\r\u001b[0J`);
      write(`${lines.join('\n')}\n`);
      drawn = lines.length;
    };
  }

  async function choose<T>(message: string, choices: readonly Choice<T>[], start: number, multi: { selected: Set<number>; min: number } | undefined): Promise<number[]> {
    const draw = redrawer();
    let cursor = start;
    let error = '';
    const render = () => {
      const lines = [ask(message, multi ? '(space to select, enter to confirm)' : '(arrows to move, enter to choose)')];
      choices.forEach((c, i) => {
        const mark = multi ? `${multi.selected.has(i) ? style.green(SYMBOL.on) : SYMBOL.off} ` : '';
        const label = i === cursor ? style.cyan(`${SYMBOL.pointer} ${mark}${c.label}`) : `  ${mark}${c.label}`;
        lines.push(`  ${label}${c.hint ? `  ${style.dim(c.hint)}` : ''}`);
      });
      if (error) lines.push(`  ${style.red(error)}`);
      draw(lines);
    };
    write('\u001b[?25l');
    try {
      render();
      for (;;) {
        const k = await keys.next();
        error = '';
        if (k.name === 'up') cursor = (cursor - 1 + choices.length) % choices.length;
        else if (k.name === 'down') cursor = (cursor + 1) % choices.length;
        else if (multi && k.name === 'space') {
          if (multi.selected.has(cursor)) multi.selected.delete(cursor);
          else multi.selected.add(cursor);
        } else if (isEnter(k)) {
          if (!multi) return [cursor];
          if (multi.selected.size >= multi.min) return [...multi.selected].sort((a, b) => a - b);
          error = `Choose at least ${multi.min} (space to select)`;
        }
        render();
      }
    } finally {
      write('\u001b[?25h');
    }
  }

  /** Without raw mode: a numbered list and a typed answer. */
  async function chooseByNumber<T>(message: string, choices: readonly Choice<T>[], multi: boolean, min: number): Promise<number[]> {
    choices.forEach((c, i) => write(`  ${i + 1}) ${c.label}\n`));
    const parse = (v: string) => v.split(',').map((s) => Number(s.trim()) - 1);
    const answer = await text({
      message: multi ? `${message} (numbers, comma separated)` : `${message} (number)`,
      validate: (v) => {
        const picked = v.trim() === '' ? [] : parse(v);
        if (picked.some((n) => !Number.isInteger(n) || n < 0 || n >= choices.length)) return `Enter ${multi ? 'numbers' : 'a number'} from 1 to ${choices.length}`;
        if (!multi && picked.length !== 1) return `Enter a number from 1 to ${choices.length}`;
        if (picked.length < min) return `Choose at least ${min}`;
        return undefined;
      },
    });
    return answer.trim() === '' ? [] : [...new Set(parse(answer))].sort((a, b) => a - b);
  }

  /** Replaces the question block with one line saying what was chosen. */
  function settle(message: string, labels: string[]): void {
    write(`${ask(message)}${style.cyan(labels.join(', ') || 'none')}\n`);
  }

  return {
    text,

    async confirm(q) {
      const answer = await text({
        message: q.message,
        default: q.default === undefined ? undefined : q.default ? 'Y/n' : 'y/N',
        validate: (v) => (/^(y|yes|n|no|y\/n|Y\/n|y\/N)$/i.test(v) || v === '' ? undefined : 'Please answer y or n'),
      });
      if (/^(y|yes)$/i.test(answer)) return true;
      if (/^(n|no)$/i.test(answer)) return false;
      return q.default ?? false;
    },

    async select(q) {
      if (q.choices.length === 0) throw new Error(`select "${q.message}" has no choices`);
      const start = Math.max(0, q.choices.findIndex((c) => c.value === q.default));
      const [i] = raw ? await withRaw(() => choose(q.message, q.choices, start, undefined)) : await chooseByNumber(q.message, q.choices, false, 1);
      const choice = q.choices[i ?? 0] as Choice<(typeof q.choices)[number]['value']>;
      if (raw) settle(q.message, [choice.label]);
      return choice.value;
    },

    async multiselect(q) {
      const selected = new Set(q.choices.flatMap((c, i) => (q.initial?.includes(c.value) ? [i] : [])));
      const min = q.min ?? 0;
      const picked = raw ? await withRaw(() => choose(q.message, q.choices, 0, { selected, min })) : await chooseByNumber(q.message, q.choices, true, min);
      const chosen = picked.map((i) => q.choices[i]).filter((c): c is Choice<(typeof q.choices)[number]['value']> => c !== undefined);
      if (raw) settle(q.message, chosen.map((c) => c.label));
      return chosen.map((c) => c.value);
    },

    note(textLine) {
      write(`${textLine}\n`);
    },

    close() {
      keys.close();
    },
  };
}
