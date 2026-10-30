import { CatalogError } from '../checks/catalog.js';
import { ObservationError } from '../checks/errors.js';
import { repoState } from '../code/git.js';
import { showGuides } from '../home/actions.js';
import { runHome } from '../home/run.js';
import { KbError } from '../kb/lesson.js';
import { loadProject, ProjectConfigError, projectFile } from '../project/schema.js';
import { ScopeError } from '../project/scope.js';
import { detectStack } from '../project/stack.js';
import { PromptCancelled } from '../ui/prompt.js';
import { askPlan } from './questions.js';
import { askDepsFor, exists, savePlan, scanAndReport, type WizardDeps } from './steps.js';

export type { WizardDeps } from './steps.js';

const INTRO = [
  "I look at your project the way an attacker's first pass would, then tell you what to fix first.",
  '  • Code: secrets, .env and key files, git history, npm packages',
  '  • Websites and APIs you give me: headers, TLS, cookies, exposed files',
  '  • Servers you give me: SSH, nginx, packages (you run a read-only script on them)',
  '',
  'I never log in, guess passwords or change anything. I only send read-only requests, only to',
  'addresses you list, and only after you say I may. Secret values are never printed.',
].join('\n');

/**
 * `secagent` on a terminal. First run: what secagent does, the setup questions, the first scan, then the home screen. Later runs go
 * straight to the home screen. Returns the exit code: 0 done, 130 cancelled, 1 for a problem with the settings or the scan.
 */
export async function runWizard(dir: string, deps: WizardDeps): Promise<number> {
  const { prompter, out, style } = deps;
  const now = deps.now ?? (() => new Date());
  try {
    if (await exists(projectFile(dir))) {
      try {
        await loadProject(dir);
      } catch (e) {
        if (!(e instanceof ProjectConfigError)) throw e;
        out.write(`${style.red(e.message)}\nFix it, or delete it to start over.\n`);
        return 1;
      }
      return await runHome(dir, deps, {});
    }

    out.write(`\n${style.bold('secagent')} · security check for this project\n`);
    const detection = await detectStack(dir);
    const git = await repoState(dir);
    const stack = Object.values(detection.stack).filter((v): v is string => typeof v === 'string');
    out.write(`  Folder: ${dir}\n  Stack: ${stack.length > 0 ? stack.join(', ') : 'not detected'}\n  Git: ${git.state === 'repo' ? 'repository' : 'not a repository'}\n\n${INTRO}\n\n`);
    for (;;) {
      const go = await prompter.select({
        message: 'Shall we start?',
        choices: [
          { value: 'setup' as const, label: 'Set up and scan this project' },
          { value: 'guides' as const, label: 'How secagent works first' },
          { value: 'quit' as const, label: 'Quit' },
        ],
        default: 'setup' as const,
      });
      if (go === 'setup') break;
      if (go === 'quit') {
        out.write('Nothing was saved and nothing was scanned.\n');
        return 0;
      }
      await showGuides(deps);
    }

    const plan = await askPlan(prompter, await askDepsFor(dir, now, { detection }));
    if (!plan) {
      out.write('Nothing was saved and nothing was scanned.\n');
      return 0;
    }
    await savePlan(dir, plan, now);
    await scanAndReport(dir, plan, deps);
    return await runHome(dir, deps, { plan });
  } catch (e) {
    if (e instanceof PromptCancelled) {
      out.write('\nCancelled.\n');
      return 130;
    }
    if (e instanceof ProjectConfigError || e instanceof ScopeError || e instanceof CatalogError || e instanceof ObservationError || e instanceof KbError) {
      out.write(`${style.red(e.message)}\n`);
      return 1;
    }
    throw e;
  }
}
