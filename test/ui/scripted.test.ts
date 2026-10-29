import { describe, expect, it } from 'vitest';
import { ScriptedPrompter } from '../helpers/prompter.js';

describe('ScriptedPrompter', () => {
  it('answers in order, takes undefined as the default, and records the questions', async () => {
    const p = new ScriptedPrompter(['shop', undefined, 'b', ['a']]);
    expect(await p.text({ message: 'Name?' })).toBe('shop');
    expect(await p.confirm({ message: 'Sure?', default: true })).toBe(true);
    expect(await p.select({ message: 'Pick', choices: [{ value: 'a', label: 'A' }, { value: 'b', label: 'B' }] })).toBe('b');
    expect(await p.multiselect({ message: 'Many', choices: [{ value: 'a', label: 'A' }] })).toEqual(['a']);
    expect(p.asked).toEqual(['Name?', 'Sure?', 'Pick', 'Many']);
    p.done();
  });

  it('feeds a rejected text answer through validate and moves to the next one, like a re-ask', async () => {
    const p = new ScriptedPrompter(['bad', 'good']);
    expect(await p.text({ message: 'x?', validate: (v) => (v === 'good' ? undefined : 'no') })).toBe('good');
    expect(p.rejected).toEqual([{ message: 'x?', answer: 'bad', error: 'no' }]);
  });

  it('fails loudly on an unexpected question, an answer that is not a choice, or leftovers', async () => {
    await expect(new ScriptedPrompter([]).text({ message: 'Who?' })).rejects.toThrow('unexpected question: Who?');
    await expect(new ScriptedPrompter(['z']).select({ message: 'Pick', choices: [{ value: 'a', label: 'A' }] })).rejects.toThrow('not a choice');
    expect(() => new ScriptedPrompter(['left']).done()).toThrow('1 answer(s) left');
  });
});
