import { PassThrough, Writable } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';
import { createTtyPrompter, PromptCancelled } from '../../src/ui/prompt.js';
import { createStyle } from '../../src/ui/style.js';

const DOWN = '\u001b[B';
const UP = '\u001b[A';
const ENTER = '\r';
const CTRL_C = '\u0003';
const BACKSPACE = '\u007f';

function terminal(opts: { raw?: boolean } = {}) {
  const input = new PassThrough() as PassThrough & { isTTY?: boolean; setRawMode?: (on: boolean) => void };
  input.isTTY = true;
  const setRawMode = vi.fn();
  if (opts.raw !== false) input.setRawMode = setRawMode;
  let written = '';
  const output = new Writable({
    write(chunk, _enc, cb) {
      written += chunk.toString();
      cb();
    },
  });
  const prompter = createTtyPrompter(input, output, createStyle({ isTTY: false }));
  /** Types each chunk once the prompt is waiting for it. */
  const type = (...chunks: string[]) => {
    for (const c of chunks) input.write(c);
  };
  return { input, setRawMode, prompter, type, written: () => written };
}

const CHOICES = [
  { value: 'a', label: 'Alpha' },
  { value: 'b', label: 'Beta' },
  { value: 'c', label: 'Gamma' },
];

describe('text', () => {
  it('takes the default on an empty line', async () => {
    const t = terminal();
    t.type(ENTER);
    expect(await t.prompter.text({ message: 'Name?', default: 'shop' })).toBe('shop');
  });

  it('re-asks while validation fails, and shows why', async () => {
    const t = terminal();
    t.type('bad', ENTER, 'good', ENTER);
    const answer = await t.prompter.text({ message: 'URL?', validate: (v) => (v === 'good' ? undefined : 'must be good') });
    expect(answer).toBe('good');
    expect(t.written()).toContain('must be good');
  });

  it('supports backspace', async () => {
    const t = terminal();
    t.type('abx', BACKSPACE, 'c', ENTER);
    expect(await t.prompter.text({ message: 'x?' })).toBe('abc');
  });
});

describe('confirm', () => {
  it('reads yes and no, takes the default on enter, and re-asks on anything else', async () => {
    const t = terminal();
    t.type(ENTER);
    expect(await t.prompter.confirm({ message: 'ok?', default: true })).toBe(true);
    t.type('n', ENTER);
    expect(await t.prompter.confirm({ message: 'ok?', default: true })).toBe(false);
    t.type('maybe', ENTER, 'YES', ENTER);
    expect(await t.prompter.confirm({ message: 'ok?' })).toBe(true);
  });

  it('with no default, an empty answer is a no', async () => {
    const t = terminal();
    t.type(ENTER);
    expect(await t.prompter.confirm({ message: 'I own these systems?' })).toBe(false);
  });
});

describe('select', () => {
  it('moves with the arrow keys and accepts with enter', async () => {
    const t = terminal();
    t.type(DOWN, DOWN, UP, ENTER);
    expect(await t.prompter.select({ message: 'Pick', choices: CHOICES })).toBe('b');
    expect(t.setRawMode).toHaveBeenCalledWith(true);
    expect(t.setRawMode).toHaveBeenLastCalledWith(false);
  });

  it('starts on the default', async () => {
    const t = terminal();
    t.type(ENTER);
    expect(await t.prompter.select({ message: 'Pick', choices: CHOICES, default: 'c' })).toBe('c');
  });

  it('without raw mode, asks for a number instead', async () => {
    const t = terminal({ raw: false });
    t.type('9', ENTER, '2', ENTER);
    expect(await t.prompter.select({ message: 'Pick', choices: CHOICES })).toBe('b');
    expect(t.written()).toContain('2) Beta');
  });
});

describe('multiselect', () => {
  it('toggles with space and keeps the order of the choices', async () => {
    const t = terminal();
    t.type(DOWN, DOWN, ' ', UP, UP, ' ', ENTER);
    expect(await t.prompter.multiselect({ message: 'Pick', choices: CHOICES })).toEqual(['a', 'c']);
  });

  it('starts from the initial selection and refuses fewer than min', async () => {
    const t = terminal();
    t.type(' ', ENTER, ' ', ENTER);
    expect(await t.prompter.multiselect({ message: 'Pick', choices: CHOICES, initial: ['a'], min: 1 })).toEqual(['a']);
    expect(t.written()).toContain('Choose at least 1');
  });
});

describe('cancelling', () => {
  it('Ctrl+C rejects with PromptCancelled and gives the terminal back', async () => {
    const t = terminal();
    t.type(CTRL_C);
    await expect(t.prompter.select({ message: 'Pick', choices: CHOICES })).rejects.toBeInstanceOf(PromptCancelled);
    expect(t.setRawMode).toHaveBeenLastCalledWith(false);
  });

  it('the end of input rejects too', async () => {
    const t = terminal();
    t.input.end();
    await expect(t.prompter.text({ message: 'x?' })).rejects.toBeInstanceOf(PromptCancelled);
  });
});

it('note prints a line', () => {
  const t = terminal();
  t.prompter.note('hello');
  expect(t.written()).toContain('hello\n');
});
