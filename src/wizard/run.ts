import { CatalogError } from '../checks/catalog.js';
import { ObservationError } from '../checks/errors.js';
import { repoState } from '../code/git.js';
import { KbError } from '../kb/lesson.js';
import { pendingLessons } from '../kb/write.js';
import { loadProject, ProjectConfigError, projectFile, type ProjectConfig } from '../project/schema.js';
import { ScopeError } from '../project/scope.js';
import { detectStack } from '../project/stack.js';
import { loadReportInput } from '../report/model.js';
import { writeReport } from '../report/write.js';
import { PromptCancelled } from '../ui/prompt.js';
import { askPlan } from './questions.js';
import { acceptFromMenu, askDepsFor, exists, openWithSystem, reviewLessons, savePlan, scanWithProgress, showResult, type WizardDeps } from './steps.js';

export type { WizardDeps } from './steps.js';

/**
 * The guided scan: asks what to check, saves the answers, scans with live progress, writes the Markdown and PDF report and shows
 * the result. Returns the exit code: 0 done, 130 cancelled, 1 for a problem with the settings or the scan.
 */
export async function runWizard(dir: string, deps: WizardDeps): Promise<number> {
  const { prompter, out, style } = deps;
  const now = deps.now ?? (() => new Date());
  const openFile = deps.openFile ?? openWithSystem;
  try {
    out.write(`\n${style.bold('secagent')} · security check for this project\n`);
    const detection = await detectStack(dir);
    const git = await repoState(dir);
    const stack = Object.values(detection.stack).filter((v): v is string => typeof v === 'string');
    out.write(`  Folder: ${dir}\n  Stack: ${stack.length > 0 ? stack.join(', ') : 'not detected'}\n  Git: ${git.state === 'repo' ? 'repository' : 'not a repository'}\n\n`);

    let existing: ProjectConfig | undefined;
    if (await exists(projectFile(dir))) {
      try {
        existing = await loadProject(dir);
      } catch (e) {
        if (!(e instanceof ProjectConfigError)) throw e;
        out.write(`${style.red(e.message)}\nFix it, or delete it to start over.\n`);
        return 1;
      }
    }

    const plan = await askPlan(prompter, await askDepsFor(dir, now, { detection, ...(existing ? { existing } : {}) }));
    if (!plan) {
      out.write('Nothing was saved and nothing was scanned.\n');
      return 0;
    }
    await savePlan(dir, plan, now);

    for (;;) {
      const record = await scanWithProgress(dir, plan, deps);
      const input = await loadReportInput(dir);
      if (!input) throw new Error('the scan did not leave a record to report on');
      const { latest } = await writeReport(dir, input, { formats: ['md', 'pdf', 'html'] });
      showResult(record, input, deps);
      const [md, pdf, html] = latest;
      out.write(`\n${style.bold('Report')}\n  Markdown: ${md}\n  PDF:      ${pdf}\n  HTML:     ${html}\n\n`);

      let rescan = false;
      while (!rescan) {
        prompter.discardPending?.();
        const open = record.findings.filter((f) => f.status === 'open');
        const pending = await pendingLessons(dir).catch(() => []);
        const next = await prompter.select({
          message: 'What next?',
          choices: [
            { value: 'open' as const, label: 'Open the PDF report' },
            { value: 'html' as const, label: 'Open the HTML report' },
            ...(open.length > 0 ? [{ value: 'accept' as const, label: 'Accept the risk of a finding for now', hint: `${open.length} open` }] : []),
            ...(pending.length > 0 ? [{ value: 'lessons' as const, label: 'Review lessons an AI assistant proposed', hint: `${pending.length} waiting` }] : []),
            { value: 'again' as const, label: 'Scan again' },
            { value: 'exit' as const, label: 'Exit' },
          ],
          default: 'exit' as const,
        });
        if (next === 'exit') return 0;
        if (next === 'again') rescan = true;
        else if (next === 'open' || next === 'html') {
          const file = next === 'open' ? pdf : html;
          if (file && !(await openFile(file))) out.write(`Could not open it from here: ${file}\n`);
        } else if (next === 'accept') {
          rescan = await acceptFromMenu(dir, input, open, deps, now);
        } else {
          await reviewLessons(dir, deps, now);
        }
      }
    }
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
