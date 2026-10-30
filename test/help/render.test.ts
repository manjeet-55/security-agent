import { describe, expect, it } from 'vitest';
import { COMMAND_GROUPS, COMMANDS, findCommand } from '../../src/help/commands.js';
import { didYouMean, renderHelp, renderOverview, unknownCommand } from '../../src/help/render.js';
import { GUIDES } from '../../src/help/topics.js';

describe('help', () => {
  it('the overview starts with how to begin, lists every group, command and guide, and keeps the usage line', () => {
    const text = renderOverview();
    expect(text).toContain('Usage: secagent <command> [options]');
    expect(text.indexOf('Start here')).toBeLessThan(text.indexOf('Commands'));
    for (const g of COMMAND_GROUPS) expect(text).toContain(g);
    for (const c of COMMANDS) expect(text).toContain(c.name);
    for (const g of GUIDES) expect(text).toContain(g.name);
  });

  it('a command page has the summary, usage, every option and the examples', () => {
    const { ok, text } = renderHelp(['scan']);
    expect(ok).toBe(true);
    expect(text).toMatch(/^secagent scan · /);
    expect(text).toContain('secagent scan [--dir <path>] [--only <groups>] [--fail-on <severity>]');
    expect(text).toContain('--fail-on <severity>');
    expect(text).toContain('--no-ai');
    expect(text).toContain('secagent scan --only code --fail-on high');
    expect(text).toContain('See also');
  });

  it('finds sub-commands by one or two words', () => {
    expect(findCommand(['snapshot'])?.name).toBe('snapshot add');
    expect(findCommand(['snapshot', 'add'])?.name).toBe('snapshot add');
    expect(findCommand(['mcp'])?.name).toBe('mcp');
    expect(findCommand(['mcp', 'setup'])?.name).toBe('mcp setup');
    expect(findCommand(['kb'])?.name).toBe('kb review');
    expect(findCommand(['kb', 'index'])?.name).toBe('kb index');
    expect(findCommand(['accept', 'code-secrets-working-tree@code'])?.name).toBe('accept');
    expect(findCommand(['nope'])).toBeUndefined();
  });

  it('prints a guide by name, and says what is wrong for a name that is neither', () => {
    expect(renderHelp(['servers'])).toMatchObject({ ok: true, text: expect.stringContaining('sudo sh collect.sh > web-1.json') });
    const bad = renderHelp(['chekclist']);
    expect(bad.ok).toBe(false);
    expect(bad.text).toContain('Did you mean "checklist"?');
  });

  it('suggests the closest command or guide for a likely typo, and nothing for a far one', () => {
    expect(didYouMean('chekclist')).toBe('checklist');
    expect(didYouMean('scna')).toBe('scan');
    expect(didYouMean('serevrs')).toBe('servers');
    expect(didYouMean('nope')).toBeUndefined();
    expect(unknownCommand('scna')).toBe('Unknown command "scna". Did you mean "scan"?\nRun secagent help to see every command and guide.');
    expect(unknownCommand('nope')).toBe('Unknown command "nope".\nRun secagent help to see every command and guide.');
  });

  it('every page is complete, names are unique, and every "see also" leads somewhere', () => {
    const names = COMMANDS.map((c) => c.name);
    expect(new Set(names).size).toBe(names.length);
    for (const c of COMMANDS) {
      expect(c.usage.startsWith(`secagent ${c.name}`)).toBe(true);
      expect(c.examples.length).toBeGreaterThan(0);
      for (const s of c.seeAlso) {
        const [first = '', second] = s.split(' ');
        if (first === 'help') expect(GUIDES.map((g) => g.name)).toContain(second);
        else expect(names).toContain(s);
      }
    }
    // A guide named like a command would make `secagent help <name>` ambiguous.
    for (const g of GUIDES) expect(names.map((n) => n.split(' ')[0])).not.toContain(g.name);
  });
});
