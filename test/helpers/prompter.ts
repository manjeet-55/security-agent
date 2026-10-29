import type { Choice, Prompter } from '../../src/ui/prompt.js';

/**
 * Answers questions from a script, in order. `undefined` takes the question's default. A text answer that fails validation is
 * recorded in `rejected` and the next answer is tried, the way the terminal re-asks. Anything unexpected throws.
 */
export class ScriptedPrompter implements Prompter {
  readonly asked: string[] = [];
  readonly notes: string[] = [];
  readonly rejected: Array<{ message: string; answer: string; error: string }> = [];
  private readonly answers: unknown[];

  constructor(answers: readonly unknown[]) {
    this.answers = [...answers];
  }

  private take(message: string): unknown {
    this.asked.push(message);
    if (this.answers.length === 0) throw new Error(`unexpected question: ${message}`);
    return this.answers.shift();
  }

  async text(q: { message: string; default?: string; validate?: (value: string) => string | undefined }): Promise<string> {
    for (;;) {
      const raw = this.take(q.message);
      const value = raw === undefined ? (q.default ?? '') : String(raw);
      const error = q.validate?.(value);
      if (error === undefined) return value;
      this.rejected.push({ message: q.message, answer: value, error });
    }
  }

  async confirm(q: { message: string; default?: boolean }): Promise<boolean> {
    const raw = this.take(q.message);
    return raw === undefined ? (q.default ?? false) : Boolean(raw);
  }

  async select<T>(q: { message: string; choices: readonly Choice<T>[]; default?: T }): Promise<T> {
    const raw = this.take(q.message);
    const value = raw === undefined ? (q.default ?? q.choices[0]?.value) : raw;
    if (!q.choices.some((c) => c.value === value)) throw new Error(`"${String(value)}" is not a choice for "${q.message}"`);
    return value as T;
  }

  async multiselect<T>(q: { message: string; choices: readonly Choice<T>[]; initial?: readonly T[]; min?: number }): Promise<T[]> {
    const raw = this.take(q.message);
    const values = (raw === undefined ? [...(q.initial ?? [])] : raw) as T[];
    for (const v of values) if (!q.choices.some((c) => c.value === v)) throw new Error(`"${String(v)}" is not a choice for "${q.message}"`);
    return q.choices.map((c) => c.value).filter((v) => values.includes(v));
  }

  note(text: string): void {
    this.notes.push(text);
  }

  done(): void {
    if (this.answers.length > 0) throw new Error(`${this.answers.length} answer(s) left: ${JSON.stringify(this.answers)}`);
  }
}
